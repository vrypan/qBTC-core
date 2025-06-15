import logging
import json
import base64
import time
import asyncio
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Dict, Set, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from wallet.wallet import verify_transaction
from pydantic import BaseModel
from blockchain.blockchain import sha256d, serialize_transaction
from state.state import pending_transactions

# Import security components
from models.validation import (
    TransactionRequest, WebSocketSubscription
)
from errors.exceptions import (
    ValidationError, InsufficientFundsError, InvalidSignatureError
)
from middleware.error_handler import setup_error_handlers
from security.integrated_security import integrated_security_middleware
from monitoring.health import health_monitor
from security.integrated_security import get_security_status, unblock_client, get_client_info

logger = logging.getLogger(__name__)



app = FastAPI(title="qBTC Core API", version="1.0.0")

# Setup security middleware
app.middleware("http")(integrated_security_middleware)

# Setup error handlers
setup_error_handlers(app)

# CORS - in production, restrict origins
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True, 
    allow_methods=["GET", "POST"],  # Only allow necessary methods
    allow_headers=["*"]
)
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
            self.active_connections.pop(websocket)
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



@app.get("/balance/{wallet_address}")
async def get_balance_endpoint(wallet_address: str):
    # Validate address format
    if not wallet_address.startswith('bqs') or len(wallet_address) < 20:
        raise ValidationError("Invalid wallet address format")
    
    try:
        balance = get_balance(wallet_address)
        return {"wallet_address": wallet_address, "balance": str(balance)}
    except Exception as e:
        logger.error(f"Error getting balance for {wallet_address}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving balance")

@app.get("/transactions/{wallet_address}")
async def get_transactions_endpoint(wallet_address: str, limit: int = 50):
    # Validate inputs
    if not wallet_address.startswith('bqs') or len(wallet_address) < 20:
        raise ValidationError("Invalid wallet address format")
    
    if limit < 1 or limit > 1000:
        raise ValidationError("Limit must be between 1 and 1000")
    
    try:
        transactions = get_transactions(wallet_address, limit)
        return {"wallet_address": wallet_address, "transactions": transactions}
    except Exception as e:
        logger.error(f"Error getting transactions for {wallet_address}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving transactions")

@app.get("/health")
async def health_check(request: Request):
    """Prometheus metrics endpoint"""
    try:
        gossip_client = getattr(request.app.state, 'gossip_client', None)
        
        # Run health checks to update metrics
        await health_monitor.run_health_checks(gossip_client)
        
        # Generate Prometheus metrics
        metrics, content_type = health_monitor.generate_metrics()
        
        from fastapi.responses import Response
        return Response(
            content=metrics,
            media_type=content_type
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content={
                "status": "unhealthy",
                "message": "Health check system error",
                "timestamp": time.time()
            },
            status_code=503
        )

@app.post("/worker")
async def worker_endpoint(request: Request):
    """Process transaction broadcast requests with validation"""
    db = get_db()
    gossip_client = request.app.state.gossip_client  

    try:
        payload = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON in request body")
    
    # Validate request structure
    if not isinstance(payload, dict) or "request_type" not in payload:
        raise ValidationError("Missing or invalid request_type")

    if payload.get("request_type") == "broadcast_tx":
        # Validate required fields
        required_fields = ["message", "signature", "pubkey"]
        for field in required_fields:
            if field not in payload:
                raise ValidationError(f"Missing required field: {field}")
        
        # Validate using Pydantic model
        try:
            tx_request = TransactionRequest(
                message=payload["message"],
                signature=payload["signature"],
                pubkey=payload["pubkey"]
            )
        except Exception as e:
            raise ValidationError(f"Transaction validation failed: {str(e)}")
        
        try:
            message_bytes = base64.b64decode(tx_request.message)
            signature_bytes = base64.b64decode(tx_request.signature)
            pubkey_bytes = base64.b64decode(tx_request.pubkey)
        except Exception:
            raise ValidationError("Invalid base64 encoding")
        
        signature_hex = signature_bytes.hex()
        pubkey_hex = pubkey_bytes.hex()
        message_str = message_bytes.decode("utf-8")
        
        parts = message_str.split(":")
        if len(parts) < 3:
            raise ValidationError("Invalid message format")
        
        sender_, receiver_, send_amount = parts[0], parts[1], parts[2]
        
        # Verify transaction signature
        if not verify_transaction(message_str, signature_hex, pubkey_hex):
            raise InvalidSignatureError("Transaction signature verification failed")

        inputs = []
        total_available = Decimal("0")
        for key, value in db.items():
            if key.startswith(b"utxo:"):
                utxo_data = json.loads(value.decode())
                if utxo_data["receiver"] == sender_ and not utxo_data["spent"]:
                    amount_decimal = Decimal(str(utxo_data.get("amount")))
                    inputs.append({
                        "txid": utxo_data.get("txid"),
                        "utxo_index": utxo_data.get("utxo_index"),
                        "sender": utxo_data.get("sender"),
                        "receiver": utxo_data.get("receiver"),
                        "amount": str(amount_decimal),
                        "spent": False
                    })
                    total_available += amount_decimal

        miner_fee = (Decimal(send_amount) * Decimal("0.001")).quantize(Decimal("0.00000001"))
        total_required = Decimal(send_amount) + Decimal(miner_fee)
        
        if total_available < total_required:
            raise InsufficientFundsError(
                required=str(total_required),
                available=str(total_available)
            )

        outputs = [
            {"utxo_index": 0, "sender": sender_, "receiver": receiver_, "amount": str(send_amount), "spent": False},
        ]

        change = total_available - total_required
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
        #db.put(b"tx:" + txid.encode(), json.dumps(transaction).encode())

        await gossip_client.randomized_broadcast(transaction)

        return {"status": "success", "message": "Transaction broadcast successfully", "tx_id": txid}
    
    else:
        raise ValidationError(f"Unsupported request type: {payload.get('request_type')}")

   

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
                
                # Validate WebSocket message
                try:
                    ws_request = WebSocketSubscription(**data)
                    update_type = ws_request.update_type
                    wallet_address = ws_request.wallet_address
                except Exception as e:
                    await websocket.send_json({
                        "error": "validation_error", 
                        "message": f"Invalid subscription request: {str(e)}"
                    })
                    continue
                if update_type:
                    websocket_manager.subscribe(websocket, update_type, wallet_address if update_type != "all_transactions" else None)
                    if update_type == "combined_update" and wallet_address:
                        asyncio.create_task(simulate_combined_updates(wallet_address))
                        logging.debug(f"Started combined_updates task for {wallet_address}")

                    if update_type == "all_transactions":
                        asyncio.create_task(simulate_all_transactions())

                    #elif update_type == "bridge" and wallet_address and data.get("bridge_address") and data.get("secret"):
                    #    asyncio.create_task(simulate_bridge_updates(wallet_address, data["secret"]))
            except json.JSONDecodeError as e:
                logging.warning(f"Invalid JSON received: {e}")
                await websocket.send_json({"error": "Invalid JSON", "message": str(e)})
    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket)
        logging.info(f"WebSocket disconnected: {websocket.client}")
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}", exc_info=True)
        await websocket.close(code=1008, reason=f"Server error: {str(e)}")


# Security Management Endpoints
@app.get("/admin/security/status")
async def get_security_status_endpoint():
    """Get comprehensive security status (admin only)"""
    try:
        status = await get_security_status()
        return status
    except Exception as e:
        logger.error(f"Failed to get security status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve security status")

@app.post("/admin/security/unblock/{client_ip}")
async def unblock_client_endpoint(client_ip: str):
    """Unblock a specific client IP (admin only)"""
    try:
        # Validate IP format
        import ipaddress
        ipaddress.ip_address(client_ip)
        
        success = await unblock_client(client_ip)
        if success:
            logger.info(f"Client {client_ip} unblocked by admin")
            return {"status": "success", "message": f"Client {client_ip} unblocked"}
        else:
            return {"status": "error", "message": f"Client {client_ip} not found or not blocked"}
    except ValueError:
        raise ValidationError("Invalid IP address format")
    except Exception as e:
        logger.error(f"Failed to unblock client {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to unblock client")

@app.get("/admin/security/client/{client_ip}")
async def get_client_info_endpoint(client_ip: str):
    """Get detailed information about a specific client (admin only)"""
    try:
        # Validate IP format
        import ipaddress
        ipaddress.ip_address(client_ip)
        
        client_info = await get_client_info(client_ip)
        if client_info:
            return client_info
        else:
            raise HTTPException(status_code=404, detail="Client not found")
    except ValueError:
        raise ValidationError("Invalid IP address format")
    except Exception as e:
        logger.error(f"Failed to get client info for {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve client information")
