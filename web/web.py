from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from wallet.wallet import  verify_transaction
from pydantic import BaseModel
from typing import Dict, List, Set, Optional
from decimal import Decimal, InvalidOperation
from datetime import datetime
from gossip.gossip import sha256d
from blockchain.blockchain import serialize_transaction
from blockchain.protobuf_class import Input,Output,TxBody,Transaction,Block
from state.state import pending_transactions
import logging
import json
import base64
import time
import asyncio


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

def get_transactions(wallet_address: str, limit: int = 50):
    db = get_db()
    tx_list = []
    transactions = {}

    for key, value in db.items():
        if not key.startswith(b"utxo:"):
            continue

        utxo = json.loads(value.decode('utf-8'))
        sender = utxo["sender"]
        receiver = utxo["receiver"]
        amount = Decimal(utxo["amount"])
        txid = utxo["txid"]

        # Skip change transactions explicitly
        if sender == wallet_address and receiver == wallet_address:
            continue

        # Initialize if needed
        if txid not in transactions:
            # Fetch the correct timestamp from corresponding tx entry
            tx_key = f"tx:{txid}".encode()
            tx_data_raw = db.get(tx_key)

            if tx_data_raw:
                tx_data = json.loads(tx_data_raw.decode('utf-8'))
                timestamp = tx_data.get("timestamp", 0)
            else:
                timestamp = 0

            transactions[txid] = {
                "sent": Decimal("0"),
                "received": Decimal("0"),
                "sent_to": [],
                "received_from": [],
                "timestamp": timestamp
            }

        if sender == wallet_address and receiver != wallet_address:
            transactions[txid]["sent"] += amount
            transactions[txid]["sent_to"].append(receiver)

        elif receiver == wallet_address and sender != wallet_address:
            transactions[txid]["received"] += amount
            transactions[txid]["received_from"].append(sender)

    for txid, data in transactions.items():
        if data["sent"] > 0:
            sent_to_addr = next((addr for addr in data["sent_to"] if addr != wallet_address), "Unknown")
            tx_list.append({
                "txid": txid,
                "direction": "sent",
                "amount": f"-{data['sent']}",
                "counterpart": sent_to_addr,
                "timestamp": data["timestamp"]
            })

        if data["received"] > 0:
            received_from_addr = next((addr for addr in data["received_from"] if addr != wallet_address), "Unknown")
            tx_list.append({
                "txid": txid,
                "direction": "received",
                "amount": f"{data['received']}",
                "counterpart": received_from_addr,
                "timestamp": data["timestamp"]
            })

    tx_list.sort(key=lambda x: x["timestamp"], reverse=True)

    return tx_list[:limit]

async def simulate_all_transactions():
    while True:
        db = get_db()
        formatted = []

        for key, value in db.items():
            key_text = key.decode("utf-8")
            if not key_text.startswith("utxo:"):
                continue

            try:
                utxo = json.loads(value.decode("utf-8"))
                txid = utxo["txid"]
                sender = utxo["sender"]
                receiver = utxo["receiver"]
                amount = Decimal(utxo["amount"])

                # Skip change outputs (self-to-self)
                if sender == receiver:
                    continue

                # Skip mining rewards (no sender)
                if sender == "":
                    continue

                # Get timestamp if available
                tx_data_raw = db.get(f"tx:{txid}".encode())
                if tx_data_raw:
                    tx_data = json.loads(tx_data_raw.decode())
                    ts = tx_data.get("timestamp", 0)
                else:
                    ts = 0

                timestamp_iso = datetime.fromtimestamp(ts / 1000).isoformat() if ts else datetime.utcnow().isoformat()

                formatted.append({
                    "id": txid,
                    "hash": txid,
                    "sender": sender,
                    "receiver": receiver,
                    "amount": f"{amount:.8f} qBTC",
                    "timestamp": timestamp_iso,
                    "status": "confirmed",
                    "_sort_ts": ts  # hidden field for sorting
                })

            except (json.JSONDecodeError, InvalidOperation, KeyError) as e:
                print(f"Skipping bad UTXO: {e}")
                continue

        # Sort most recent first (descending by timestamp)
        formatted.sort(key=lambda x: x["_sort_ts"], reverse=True)

        # Remove internal sorting field
        for tx in formatted:
            tx.pop("_sort_ts", None)

        update_data = {
            "type": "transaction_update",
            "transactions": formatted,
            "timestamp": datetime.utcnow().isoformat()
        }

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
            logging.error(f"Error broadcasting to client: {e}")
            disconnected_clients.append(client)
    
    # Remove disconnected clients
    for client in disconnected_clients:
        websocket_clients.remove(client)


async def simulate_combined_updates(wallet_address: str):
    while True:
        balance = get_balance(wallet_address)
        transactions = get_transactions(wallet_address)
        formatted = []

        for tx in transactions:
            tx_type = "send" if tx["direction"] == "sent" else "receive"
            
            amt_dec = Decimal(tx["amount"])
            amount_fmt = f"{abs(amt_dec):.8f} qBTC"

            address = tx["counterpart"] if tx["counterpart"] else "n/a"

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

async def simulate_bridge_updates(wallet_address, secret):
    """
    Simulate a backend process and send updates to the client for each step.
    """
    query = '''
        SELECT *
        FROM `bridge-btc-bqs`
        WHERE secret = %s;
    '''
    statuses = ['waiting', 'confirmed', 'exchanging', 'sending', 'complete']
    expiration_time = datetime.now() + timedelta(hours=2)
    last_sent_status = None

    while True:
        try:
            # Fetch the current status from the database
            status = await db.query(query, (secret,))
            
            if not status:
                current_status = "waiting"
                created_at = datetime.now().isoformat()
                bridge_address = None
                tx_hash = None
            else:
                current_status = status[0].get("current_status", "waiting")
                created_at = status[0].get("created_at", datetime.now().isoformat())
                bridge_address = status[0].get("bridge_address")
                tx_hash = status[0].get("tx_hash")

            # Check for expiration
            if current_status == "waiting" and datetime.now() >= expiration_time:
                expiration_data = {
                    "current_status": "expired",
                    "message": "No deposit received within 2 hours"
                }
                await websocket_manager.broadcast(
                    expiration_data,
                    update_type="bridge",
                    wallet_address=wallet_address,
                )
                return  # Exit the loop after expiration

            # Send status updates if status changes
            if current_status and current_status != last_sent_status:
                bridge_data = {
                    "type": "bridge_update",
                    "bridge_address": bridge_address,
                    "current_status": current_status,
                    "created_at": created_at,
                    "tx_hash": tx_hash,
                    "timestamp": datetime.now().isoformat(),
                }

                await websocket_manager.broadcast(
                    bridge_data,
                    update_type="bridge",
                    wallet_address=wallet_address,
                )
                last_sent_status = current_status

            # Wait for 10 seconds before checking again
            await asyncio.sleep(10)

        except Exception as e:
            print(f"Error in simulate_bridge_updates for wallet {wallet_address}: {e}")
            break

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
async def health_check(request: Request):
    db = get_db()
    gossip_client = request.app.state.gossip_client  
    print("DHT peers:", gossip_client.dht_peers)
    print("Client peers:", gossip_client.client_peers)
    return {
        "status": "healthy",
        "height": get_current_height(db)[0],
        "peers": len(gossip_client.dht_peers | gossip_client.client_peers),
        "pending_txs": len(pending_transactions)
    }

@app.post("/worker")
async def worker_endpoint(request: Request):
    db = get_db()
    gossip_client = request.app.state.gossip_client  

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
                    amount_decimal = Decimal(str(utxo_data["amount"]))
                    inputs.append(Input(
                        txid=utxo_data["txid"],
                        utxo_index=int(utxo_data["utxo_index"]),
                        sender=utxo_data["sender"],
                        receiver=utxo_data["receiver"],
                        amount=str(amount_decimal),
                        spent=False
                    ))
                    total_available += amount_decimal

        miner_fee = (Decimal(send_amount) * Decimal("0.001")).quantize(Decimal("0.00000001"))
        total_required = Decimal(send_amount) + miner_fee

        if total_available < total_required:
            return {
                "status": "error",
                "message": f"Insufficient funds: Need {total_required}, have {total_available}"
            }

        outputs = [
            Output(
                utxo_index=0,
                sender=sender_,
                receiver=receiver_,
                amount=str(send_amount),
                spent=False
            )
        ]

        change = total_available - total_required
        if change > 0:
            outputs.append(Output(
                utxo_index=1,
                sender=sender_,
                receiver=sender_,
                amount=str(change),
                spent=False
            ))

        body = TxBody(
            msg_str=message_str,
            pubkey=pubkey_hex,
            signature=signature_hex
        )

        transaction = Transaction(
            inputs=inputs,
            outputs=outputs,
            body=body,
            timestamp=int(time.time() * 1000)
        )

        raw_tx = transaction.SerializeToString()
        txid = sha256d(raw_tx)[::-1].hex()
        transaction.txid = txid
        for i, output in enumerate(transaction.outputs):
            output.txid = txid
            output.utxo_index = i

        pending_transactions[txid] = transaction
        db.put(b"tx:" + txid.encode(), transaction.SerializeToString())

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
    logging.info(f"WebSocket connection attempt from {websocket.client} with headers: {dict(websocket.headers)}")
    try:
        logging.info(f"WebSocket accepted: {websocket.client}")
        await websocket_manager.connect(websocket)
        while True:
            try:
                data = await websocket.receive_json()
                logging.debug(f"Received: {data}")
                update_type = data.get("update_type")
                wallet_address = data.get("wallet_address")
                if update_type:
                    websocket_manager.subscribe(websocket, update_type, wallet_address if update_type != "all_transactions" else None)
                    if update_type == "combined_update" and wallet_address:
                        task = asyncio.create_task(simulate_combined_updates(wallet_address))
                        logging.debug(f"Started combined_updates task for {wallet_address}")

                    if update_type == "all_transactions":
                        task = asyncio.create_task(simulate_all_transactions())

                    elif update_type == "bridge" and wallet_address and data.get("bridge_address") and data.get("secret"):
                        asyncio.create_task(simulate_bridge_updates(wallet_address, data["secret"]))
            except json.JSONDecodeError as e:
                logging.warning(f"Invalid JSON received: {e}")
                await websocket.send_json({"error": "Invalid JSON", "message": str(e)})
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)
        logging.info(f"WebSocket disconnected: {websocket.client}")
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}", exc_info=True)
        await websocket.close(code=1008, reason=f"Server error: {str(e)}")