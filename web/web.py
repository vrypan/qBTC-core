from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from wallet.wallet import  verify_transaction
from pydantic import BaseModel
from typing import Dict, List, Set, Optional
from decimal import Decimal
from datetime import datetime
import logger
import json
import base64

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
websocket_clients: Set[WebSocket] = set()

class WorkerRequest(BaseModel):
    request_type: str
    message: Optional[str] = None
    signature: Optional[str] = None
    pubkey: Optional[str] = None
    wallet_address: Optional[str] = None
    network: Optional[str] = None
    direction: Optional[str] = None
    btc_account: Optional[str] = None

class WorkerResponse(BaseModel):
    status: str
    message: str
    tx_id: Optional[str] = None
    address: Optional[str] = None
    secret: Optional[str] = None

class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[WebSocket, Set[str]] = {}
        self.wallet_map: Dict[str, Set[WebSocket]] = {}
        self.bridge_sessions: Dict[str, Dict] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[websocket] = set()

    async def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            subscriptions = self.active_connections.pop(websocket)
            for wallet in list(self.wallet_map.keys()):
                if websocket in self.wallet_map[wallet]:
                    self.wallet_map[wallet].discard(websocket)
                    if not self.wallet_map[wallet]:
                        del self.wallet_map[wallet]

    def subscribe(self, websocket: WebSocket, update_type: str, wallet_address: str = None):
        if websocket in self.active_connections:
            self.active_connections[websocket].add(update_type)
            if wallet_address and update_type in ["combined_update", "bridge"]:
                self.wallet_map.setdefault(wallet_address, set()).add(websocket)

    async def broadcast(self, message: dict, update_type: str, wallet_address: str = None):
        target_connections = (
            set(self.active_connections.keys()) if update_type in ["all_transactions", "l1_proofs_testnet"]
            else self.wallet_map.get(wallet_address, set())
        )
        for connection in target_connections:
            if update_type in self.active_connections.get(connection, set()):
                await connection.send_json(message)

    def create_bridge_session(self, wallet_address: str, direction: str, bridge_address: str = None, secret: str = None):
        session_id = f"{wallet_address}_{direction}_{int(time.time())}"
        self.bridge_sessions[session_id] = {
            "wallet_address": wallet_address, "direction": direction, "bridge_address": bridge_address,
            "secret": secret, "status": "waiting", "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        return session_id

    def get_bridge_sessions(self, wallet_address: str):
        return [session for session_id, session in self.bridge_sessions.items() if session["wallet_address"] == wallet_address]

    def update_bridge_status(self, wallet_address: str, bridge_address: str, status: str):
        for session_id, session in self.bridge_sessions.items():
            if session["wallet_address"] == wallet_address and session.get("bridge_address") == bridge_address:
                session["status"] = status
                session["updated_at"] = datetime.now().isoformat()
                return session
        return None

websocket_manager = WebSocketManager()

def get_balance(wallet_address: str) -> Decimal:
    db = get_db()
    total = Decimal("0")
    for key, value in db.items():
        if key.startswith(b"utxo:"):
            utxo_data = json.loads(value.decode())
            if utxo_data["receiver"] == wallet_address and not utxo_data["spent"]:
                total += Decimal(utxo_data["amount"])
    return total

def get_transactions(wallet_address: str, limit: int = 50) -> List[dict]:
    """
    Same semantics as before but handles decimal amounts safely.
    Returned 'amount' is a string so the caller can feed it to Decimal().
    """
    db = get_db()
    tx_list = []

    for key, value in db.items():
        if not key.startswith(b"tx:"):
            continue

        tx = json.loads(value.decode())
        ts = tx.get("timestamp", 0)

        # -------- Sent side -------------------------------------------------
        sent_total = Decimal("0")
        sent_to = set()

        for inp in tx.get("inputs", []):
            if inp.get("sender") == wallet_address:
                try:
                    sent_total += Decimal(str(inp.get("amount", "0")))
                except InvalidOperation:
                    continue
                sent_to.add(inp.get("receiver"))

        if sent_total != 0:
            tx_list.append({
                "txid":        tx["txid"],
                "direction":   "sent",
                "amount":      str(-sent_total),           # keep sign, stringify
                "counterpart": list(sent_to),
                "timestamp":   ts
            })

        # -------- Received side ---------------------------------------------
        recv_total = Decimal("0")
        recv_from = set()

        for out in tx.get("outputs", []):
            if out.get("receiver") == wallet_address:
                try:
                    recv_total += Decimal(str(out.get("amount", "0")))
                except InvalidOperation:
                    continue
                recv_from.add(out.get("sender"))

        if recv_total != 0:
            tx_list.append({
                "txid":        tx["txid"],
                "direction":   "received",
                "amount":      str(recv_total),
                "counterpart": list(recv_from),
                "timestamp":   ts
            })

    tx_list.sort(key=lambda x: x["timestamp"], reverse=True)
    return tx_list[:limit]

    #target = 2 ** (256 - difficulty)
    #bits = target_to_bits(target)  # Convert target to bits format

async def simulate_all_transactions():
    while True:
        transactions = get_transactions("")
        formatted = []
        for tx in transactions:
            formatted.append({
                "id": tx["txid"], "hash": tx["txid"], "sender": tx["sender"],
                "receiver": tx["receiver"], "amount": f"{Decimal(tx['amount']):.8f} BQS",
                "timestamp": datetime.fromtimestamp(tx["timestamp"] / 1000).isoformat(),  # Convert to ISO
                "status": "confirmed"
            })
        update_data = {"type": "transaction_update", "transactions": formatted, "timestamp": datetime.now().isoformat()}
        await websocket_manager.broadcast(update_data, "all_transactions")
        await asyncio.sleep(10)

async def broadcast_to_websocket_clients(message: str):
    # Copy clients to avoid modifying set during iteration
    disconnected_clients = []
    for client in websocket_clients:
        try:
            await client.send_text(message)
        except WebSocketDisconnect:
            disconnected_clients.append(client)
        except Exception as e:
            logger.error(f"Error broadcasting to client: {e}")
            disconnected_clients.append(client)
    
    # Remove disconnected clients
    for client in disconnected_clients:
        websocket_clients.remove(client)


async def simulate_combined_updates(wallet_address: str):
    """
    Periodically push balance + recent transactions to every WebSocket client.
    Compatible with the new get_transactions() that returns 'amount' as str.
    """
    while True:
        balance = get_balance(wallet_address)
        transactions = get_transactions(wallet_address)
        formatted = []
        for tx in transactions:
            tx_type = "send" if tx["direction"] == "sent" else "receive"
            # Parse string → Decimal, then abs() for magnitude display
            amt_dec = Decimal(tx["amount"])
            amount_fmt = f"{abs(amt_dec):.8f} BQS"
            address = ", ".join(tx["counterpart"]) if tx["counterpart"] else "n/a"
            formatted.append({
                "id":        tx["txid"],
                "type":      tx_type,
                "amount":    amount_fmt,
                "address":   address,
                "timestamp": datetime.fromtimestamp(tx["timestamp"] / 1000).isoformat(),
                "hash":      tx["txid"],
                "status":    "confirmed"
            })
        await websocket_manager.broadcast(
            {
                "type":         "combined_update",
                "balance":      str(balance),
                "transactions": formatted
            },
            "combined_update",
            wallet_address
        )
        await asyncio.sleep(10)

async def simulate_l1_proofs_testnet():
    while True:
        db = get_db()
        proofs = {}
        for key, value in db.items():
            if key.startswith(b"block:"):
                block = json.loads(value.decode())
                tx_ids = block["tx_ids"]
                proofs[block["height"]] = {
                    "blockHeight": block["height"], "merkleRoot": block["block_hash"],
                    "bitcoinTxHash": None, "timestamp": datetime.fromtimestamp(block["timestamp"] / 1000).isoformat(),
                    "transactions": [{"id": tx_id, "hash": tx_id, "status": "confirmed"} for tx_id in tx_ids],
                    "status": "confirmed"
                }
        update_data = {"type": "l1proof_update", "proofs": list(proofs.values()), "timestamp": datetime.now().isoformat()}
        await websocket_manager.broadcast(update_data, "l1_proofs_testnet")
        await asyncio.sleep(10)

async def simulate_bridge_updates(wallet_address: str, bridge_address: str, secret: str):
    statuses = ["waiting", "confirmed", "exchanging", "sending", "complete"]
    current_status_idx = 0
    websocket_manager.create_bridge_session(wallet_address, "btc-to-bqs", bridge_address, secret)
    while current_status_idx < len(statuses):
        status = statuses[current_status_idx]
        websocket_manager.update_bridge_status(wallet_address, bridge_address, status)
        bridge_data = {
            "type": "bridge_update", "bridge_address": bridge_address, "current_status": status,
            "created_at": datetime.now().isoformat(),
            "tx_hash": None if current_status_idx < 2 else f"0x{hashlib.sha256(bridge_address.encode()).hexdigest()}",
            "timestamp": datetime.now().isoformat()
        }
        await websocket_manager.broadcast(bridge_data, "bridge", wallet_address)
        current_status_idx += 1
        await asyncio.sleep(10)

def generate_bridge_address(wallet_address: str, network: str, direction: str) -> tuple:
    seed = f"{wallet_address}_{network}_{direction}_{int(time.time())}"
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    secret = base64.b64encode(hash_bytes).decode('utf-8')[:16]
    prefix = "tb1" if network == "testnet" else "bc1"
    address = f"{prefix}{''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyz', k=38))}"
    bridge_addresses[wallet_address] = {"address": address, "secret": secret, "direction": direction, "created_at": datetime.now().isoformat()}
    return address, secret

@app.get("/balance/{wallet_address}")
async def get_balance_endpoint(wallet_address: str):
    balance = get_balance(wallet_address)
    return {"wallet_address": wallet_address, "balance": str(balance)}

@app.get("/transactions/{wallet_address}")
async def get_transactions_endpoint(wallet_address: str, limit: int = 50):
    transactions = get_transactions(wallet_address, limit)
    return {"wallet_address": wallet_address, "transactions": transactions}

@app.get("/health")
async def health_check():
    db = get_db()
    return {
        "status": "healthy",
        "height": get_current_height(db),
        "peers": len(gossip_client.peers) if gossip_client else 0,
        "pending_txs": len(pending_transactions)
    }

@app.post("/worker")
async def worker_endpoint(request: Request):
    global gossip_client
    db = get_db()
    payload = await request.json()

    if payload.get("request_type") == "broadcast_tx":
        message_bytes = base64.b64decode(payload["message"])
        signature_bytes = base64.b64decode(payload["signature"])
        pubkey_bytes = base64.b64decode(payload["pubkey"])
        signature_hex = signature_bytes.hex()
        pubkey_hex = pubkey_bytes.hex()
        message_str = message_bytes.decode("utf-8")
        parts = message_str.split(":")
        sender_, receiver_, send_amount = parts[0], parts[1], parts[2]
        nonce = parts[3] if len(parts) > 3 else str(int(time.time() * 1000))
        if not verify_transaction(message_str, signature_hex, pubkey_hex):
            return {"status": "error", "message": "Invalid signature"}
        inputs = []
        total_available = Decimal("0")
        for key, value in db.items():
            if key.startswith(b"utxo:"):
                utxo_data = json.loads(value.decode())
                if utxo_data["receiver"] == sender_ and not utxo_data["spent"]:
                    txid = utxo_data.get("txid")
                    utxo_index = utxo_data.get("utxo_index")
                    sender = utxo_data.get("sender")
                    receiver = utxo_data.get("receiver")
                    amount_decimal = Decimal(str(utxo_data.get("amount")))
                    inputs.append({
                        "txid": txid,
                        "utxo_index": utxo_index,
                        "sender": sender,
                        "receiver": receiver,
                        "amount":  str(amount_decimal),
                        "spent": False
                    })
                    total_available += amount_decimal
        miner_fee = (Decimal(send_amount) * Decimal("0.001")).quantize(Decimal("0.00000001"))
        treasury_fee = (Decimal(send_amount) * Decimal("0.001")).quantize(Decimal("0.00000001"))
        total_required = Decimal(send_amount) + Decimal(miner_fee) + Decimal(treasury_fee)
        if total_available < total_required:
            return {
                "status": "error",
                "message": f"Insufficient funds: Need {total_required}, have {total_available}"
            }
        print(f"sender: {sender_}")
        print(f"receiver: {receiver_}")
        outputs = [
            {"utxo_index": 0, "sender": sender_, "receiver": receiver_, "amount": str(send_amount), "spent": False},
            {"utxo_index": 2, "sender": sender_, "receiver": TREASURY_ADDRESS, "amount": str(treasury_fee), "spent": False}
        ]
        change = Decimal(total_available) - Decimal(total_required)
        if change > 0:
            outputs.insert(1, {
                "utxo_index": 1, "sender": sender_, "receiver": sender_, "amount": str(change), "spent": False
            })
        transaction = {
            "type": "transaction",
            "inputs": inputs,
            "outputs": outputs,
            "body": {
                "msg_str": message_str,
                "pubkey": pubkey_hex,
                "signature": signature_hex
            },
            "timestamp": int(time.time() * 1000)
        }
        raw_tx = serialize_transaction(transaction)
        txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex() 
        transaction["txid"] = txid
        for output in transaction["outputs"]:
            output["txid"] = txid
        pending_transactions[txid] = transaction
        print(f"[TX] Added {txid} to mempool. Total: {len(pending_transactions)}")
        await gossip_client.randomized_broadcast(transaction)
        return {"status": "success", "message": "Transaction broadcast successfully", "tx_id": txid}


    if payload.get("request_type") == "get_bridge_address":
        if not request.wallet_address:
            return {"status": "error", "message": "Wallet address required"}
        address, secret = generate_bridge_address(
            request.wallet_address,
            request.network or "testnet",
            request.direction or "btc-to-bqs"
        )
        return {"status": "success", "message": "Bridge address generated", "address": address, "secret": secret}

    return {"status": "error", "message": "Unsupported request type"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    logger.info(f"WebSocket connection attempt from {websocket.client} with headers: {dict(websocket.headers)}")
    try:
        logger.info(f"WebSocket accepted: {websocket.client}")
        await websocket_manager.connect(websocket)
        while True:
            try:
                data = await websocket.receive_json()
                logger.debug(f"Received: {data}")
                update_type = data.get("update_type")
                wallet_address = data.get("wallet_address")
                if update_type:
                    websocket_manager.subscribe(websocket, update_type, wallet_address if update_type != "all_transactions" else None)
                    if update_type == "combined_update" and wallet_address:
                        task = asyncio.create_task(simulate_combined_updates(wallet_address))
                        logger.debug(f"Started combined_updates task for {wallet_address}")
                    elif update_type == "bridge" and wallet_address and data.get("bridge_address") and data.get("secret"):
                        asyncio.create_task(simulate_bridge_updates(wallet_address, data["bridge_address"], data["secret"]))
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON received: {e}")
                await websocket.send_json({"error": "Invalid JSON", "message": str(e)})
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected: {websocket.client}")
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}", exc_info=True)
        await websocket.close(code=1008, reason=f"Server error: {str(e)}")