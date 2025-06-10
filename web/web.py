from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Set, Optional
from decimal import Decimal
from database.database import get_db, get_current_height
from wallet.wallet import verify_transaction
from gossip.gossip import sha256d
from blockchain.blockchain import serialize_transaction
from state.state import pending_transactions
import json
import base64
import time

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

websocket_clients: Set[WebSocket] = set()

class WorkerRequest(BaseModel):
    request_type: str
    message: Optional[str] = None
    signature: Optional[str] = None
    pubkey: Optional[str] = None

class WorkerResponse(BaseModel):
    status: str
    message: str
    tx_id: Optional[str] = None

class WebSocketManager:
    def __init__(self):
        self.connections: Dict[WebSocket, Set[str]] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections[websocket] = set()

    async def disconnect(self, websocket: WebSocket):
        self.connections.pop(websocket, None)

    def subscribe(self, websocket: WebSocket, update_type: str):
        if websocket in self.connections:
            self.connections[websocket].add(update_type)

    async def broadcast(self, message: dict, update_type: str):
        for ws, types in self.connections.items():
            if update_type in types:
                await ws.send_json(message)

websocket_manager = WebSocketManager()

def get_balance(wallet_address: str) -> Decimal:
    db = get_db()
    total = Decimal("0")
    for key, value in db.items():
        if isinstance(key, bytes) and key.startswith(b"utxo:"):
            utxo = json.loads(value.decode())
            if utxo["receiver"] == wallet_address and not utxo["spent"]:
                total += Decimal(utxo["amount"])
    return total

def get_transactions(wallet_address: str, limit: int = 50):
    db = get_db()
    transactions = []
    for key, value in db.items():
        if isinstance(key, bytes) and not key.startswith(b"utxo:"):
            continue
        utxo = json.loads(value.decode())
        if wallet_address not in (utxo["sender"], utxo["receiver"]):
            continue
        txid = utxo["txid"]
        tx_data = db.get(f"tx:{txid}".encode())
        timestamp = json.loads(tx_data.decode()).get("timestamp", 0) if tx_data else 0
        direction = "sent" if utxo["sender"] == wallet_address else "received"
        amount = Decimal(utxo["amount"])
        transactions.append({
            "txid": txid,
            "direction": direction,
            "amount": f"{'-' if direction == 'sent' else ''}{amount}",
            "timestamp": timestamp
        })
    transactions.sort(key=lambda x: x["timestamp"], reverse=True)
    return transactions[:limit]

@app.get("/balance/{wallet_address}")
async def balance(wallet_address: str):
    return {"wallet_address": wallet_address, "balance": str(get_balance(wallet_address))}

@app.get("/transactions/{wallet_address}")
async def transactions(wallet_address: str, limit: int = 50):
    return {"wallet_address": wallet_address, "transactions": get_transactions(wallet_address, limit)}

@app.get("/health")
async def health(request: Request):
    db = get_db()
    gossip_client = request.app.state.gossip_client
    return {
        "status": "healthy",
        "height": get_current_height(db)[0],
        "peers": len(gossip_client.client_peers) if gossip_client else 0,
        "pending_txs": len(pending_transactions)
    }

@app.post("/worker")
async def worker(request: Request):
    db = get_db()
    gossip_client = request.app.state.gossip_client
    payload = await request.json()

    if payload.get("request_type") != "broadcast_tx":
        return {"status": "error", "message": "Unsupported request type"}

    try:
        msg_bytes = base64.b64decode(payload["message"])
        sig_bytes = base64.b64decode(payload["signature"])
        pubkey_bytes = base64.b64decode(payload["pubkey"])
        msg = msg_bytes.decode("utf-8")
        sender, receiver, amount, *rest = msg.split(":")

        # Removed unused variable 'nonce'

        if not verify_transaction(msg, sig_bytes.hex(), pubkey_bytes.hex()):
            return {"status": "error", "message": "Invalid signature"}

        inputs, total = [], Decimal("0")
        for k, v in db.items():
            if isinstance(k, bytes) and k.startswith(b"utxo:"):
                utxo = json.loads(v.decode())
                if utxo["receiver"] == sender and not utxo["spent"]:
                    val = Decimal(utxo["amount"])
                    inputs.append({"txid": utxo["txid"], "amount": str(val), **utxo})
                    total += val

        fee = (Decimal(amount) * Decimal("0.001")).quantize(Decimal("0.00000001"))
        needed = Decimal(amount) + fee
        if total < needed:
            return {"status": "error", "message": f"Insufficient funds: Need {needed}, have {total}"}

        outputs = [{"sender": sender, "receiver": receiver, "amount": str(amount), "spent": False, "utxo_index": 0}]
        change = total - needed
        if change > 0:
            outputs.append({"sender": sender, "receiver": sender, "amount": str(change), "spent": False, "utxo_index": 1})

        tx = {
            "type": "transaction",
            "inputs": inputs,
            "outputs": outputs,
            "body": {"msg_str": msg, "pubkey": pubkey_bytes.hex(), "signature": sig_bytes.hex()},
            "timestamp": int(time.time() * 1000)
        }

        raw_tx = serialize_transaction(tx)
        txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
        tx["txid"] = txid
        for o in tx["outputs"]:
            o["txid"] = txid
        pending_transactions[txid] = tx
        await gossip_client.randomized_broadcast(tx)
        return {"status": "success", "message": "Transaction broadcast", "tx_id": txid}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.websocket("/ws")
async def ws(websocket: WebSocket):
    try:
        await websocket_manager.connect(websocket)
        while True:
            data = await websocket.receive_json()
            update_type = data.get("update_type")
            if update_type:
                websocket_manager.subscribe(websocket, update_type)
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)
    except Exception as e:
        await websocket.close(code=1008, reason=f"Error: {str(e)}")
