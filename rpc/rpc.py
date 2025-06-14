import copy
import time
import struct
import json
import logging
from decimal import Decimal
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from config.config import ADMIN_ADDRESS
from wallet.wallet import verify_transaction
from blockchain.blockchain import derive_qsafe_address,Block, bits_to_target, serialize_transaction,scriptpubkey_to_address, read_varint, parse_tx, validate_pow, sha256d, calculate_merkle_root
from state.state import blockchain, state_lock, pending_transactions
from rocksdict import WriteBatch

# Import security components
from models.validation import RPCRequest, BlockSubmissionRequest
from errors.exceptions import ValidationError
from middleware.error_handler import setup_error_handlers
from security.integrated_security import integrated_security_middleware

logger = logging.getLogger(__name__)



rpc_app = FastAPI(title="qBTC RPC API", version="1.0.0")

# Setup security middleware
rpc_app.middleware("http")(integrated_security_middleware)

# Setup error handlers
setup_error_handlers(rpc_app)

# CORS - restrict in production
rpc_app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True, 
    allow_methods=["POST"],  # RPC only needs POST
    allow_headers=["*"]
)



@rpc_app.post("/")
async def rpc_handler(request: Request):
    """Handle RPC requests with validation"""
    # Check authorization header for cpuminer compatibility
    auth_header = request.headers.get("Authorization")
    if auth_header:
        # cpuminer sends basic auth, just accept any credentials for now
        logger.debug(f"Auth header present: {auth_header[:20]}...")
    
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise ValidationError("Invalid JSON in RPC request")
    
    # Validate RPC request structure
    try:
        rpc_request = RPCRequest(**data)
    except Exception as e:
        return {"error": f"Invalid RPC request: {str(e)}", "id": data.get("id")}
    
    method = rpc_request.method
    
    try:
        if method == "getblocktemplate":
            return await get_block_template(data)
        elif method == "submitblock":
            return await submit_block(request, data)
        else:
            return {"error": "unknown method", "id": data.get("id")}
    except Exception as e:
        logger.error(f"RPC method {method} failed: {str(e)}")
        return {"error": f"RPC method failed: {str(e)}", "id": data.get("id")}


async def get_block_template(data):
    print(data)
    db = get_db()
    timestamp = int(time.time())
    height, previous_block_hash = get_current_height(db)
    transactions = []
    txids = [] 

    # Include pending transactions in the block template
    for orig_tx in pending_transactions.values():
        tx = copy.deepcopy(orig_tx)
        txid = tx["txid"]
        if "txid" in tx:
            del tx["txid"]
        for output in tx.get("outputs", []):
            output.pop("txid", None)
        raw_tx = serialize_transaction(tx)
        transactions.append({
            "data": raw_tx,  
            "txid": txid
        })
        txids.append(txid) 


    block_template = {
        "version": 1,
        "previousblockhash": f"{previous_block_hash}",
        "target": f"{bits_to_target(0x1f00ffff):064x}",
        "bits": f"{0x1f00ffff:08x}", 
        "curtime": timestamp,
        "height": height + 1,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "capabilities": ["proposal"],
        "coinbaseaux": {},
        "coinbasevalue": 5000000000,
        "transactions": transactions,
        "longpollid": previous_block_hash,
    }

    return {
        "result": block_template,
        "error": None,
        "id": data["id"]
    }


def rpc_error(code, msg, _id):
    return {"result": None,
            "error": {"code": code, "message": msg},
            "id": _id}


async def submit_block(request: Request, data: dict) -> dict:
    """Submit a new block with comprehensive validation"""
    logger.info(f"Block submission request: {data}")
    
    try:
        gossip_client = request.app.state.gossip_client
        
        # Validate block submission parameters
        if "params" not in data or not isinstance(data["params"], list) or len(data["params"]) == 0:
            return rpc_error(-1, "Missing or invalid block data", data.get("id"))
        
        raw_block_hex = data["params"][0]
        
        # Validate hex format
        try:
            block_request = BlockSubmissionRequest(block_hex=raw_block_hex)
            raw = bytes.fromhex(raw_block_hex)
        except Exception as e:
            return rpc_error(-1, f"Invalid block format: {str(e)}", data.get("id"))
        
        db = get_db()
        batch = WriteBatch()  
        txids = []
        tx_list = []
        hdr = raw[:80]
        version = struct.unpack_from('<I', hdr, 0)[0]
        prev_block = hdr[4:36][::-1].hex()
        merkle_root_block = hdr[36:68][::-1].hex()
        timestamp = struct.unpack_from('<I', hdr, 68)[0]
        bits = struct.unpack_from('<I', hdr, 72)[0] 
        nonce = struct.unpack_from('<I', hdr, 76)[0]
        block = Block(version, prev_block, merkle_root_block, timestamp, bits, nonce)

        if block.hash() in blockchain:
            return rpc_error(-2,"duplicate", data["id"])

        if not validate_pow(block):
            logger.warning(f"Block validation failed - invalid PoW: {block.hash()}")
            return rpc_error(-1, "Block validation failed - invalid proof of work", data.get("id"))
        else:
            logger.info(f"Block PoW validation successful: {block.hash()}")

        height_temp = get_current_height(db)
        local_height = height_temp[0]
        local_tip = height_temp[1]

        print(f"Local height: {local_height}, Local tip: {local_tip}")

        if prev_block != local_tip:
            if db.get(f"block:{prev_block}".encode()):      # we do know that block
                logger.warning(f"Stale block submitted: {block.hash()}")
                return rpc_error(23, "stale", data["id"])   # ➜ miner refreshes template
            logger.error(f"Block references unknown previous block: {prev_block}")
            return rpc_error(-1, "bad-prevblk", data["id"])

        future_limit = int(time.time()) + 2*60 # 2 mins in the future

        if (timestamp > future_limit):
            logger.warning(f"Block timestamp too far in future: {timestamp}")
            return rpc_error(-1, "Block timestamp too far in future", data["id"])


        offset = 80
        tx_count, sz = read_varint(raw, offset)
        offset += sz
        coinbase_start = offset
        coinbase_tx, size = parse_tx(raw, offset)
        print(coinbase_tx)
        coinbase_script_pubkey = coinbase_tx["outputs"][0]["script_pubkey"]
        coinbase_miner_address = scriptpubkey_to_address(coinbase_script_pubkey)
        print(f"****** COINBASE MINER ADDERSS {coinbase_miner_address}")
        coinbase_raw = raw[coinbase_start:coinbase_start + size]
        coinbase_txid = sha256d(coinbase_raw)[::-1].hex() 
        print(f"****** COINBASE TXID: {coinbase_txid}")
        txids.append(coinbase_txid)

        #batch.put(b"tx:" + coinbase_txid.encode(), json.dumps(coinbase_tx).encode())

        #
        # Add mapping to quantum safe miner address here through endpoint 
        #

        offset += size
        
        # Check if there's any data after the coinbase transaction
        if offset < len(raw):
            try:
                blob = raw[offset:].decode('utf-8')
                decoder = json.JSONDecoder()
                pos     = 0
                while pos < len(blob):
                    obj, next_pos = decoder.raw_decode(blob, pos)
                    tx_list.append(obj)
                    pos = next_pos
                    while pos < len(blob) and blob[pos] in ' \t\r\n,':
                        pos += 1
            except Exception as e:
                # No valid JSON data after coinbase, which is fine for cpuminer blocks
                logger.debug(f"No additional transactions after coinbase: {e}")


        for tx in tx_list:
            raw_tx = serialize_transaction(tx)
            txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
            txids.append(txid)
            inputs = tx["inputs"]
            print(f"****** INPUTS : {inputs}")
            outputs = tx["outputs"]
            message_str = tx["body"]["msg_str"]
            pubkey = tx["body"]["pubkey"]
            signature = tx["body"]["signature"]
            if verify_transaction(message_str, signature, pubkey) is True:

                from_ = message_str.split(":")[0]
                to_ = message_str.split(":")[1]
                amount_ = message_str.split(":")[2]
                total_available = Decimal(0)
                total_required = Decimal(0)
                total_authorised = Decimal(amount_)

                assert derive_qsafe_address(pubkey) == from_,"wrong signer"

                for input_ in inputs:
                    input_receiver = input_["receiver"]
                    input_amount = input_["amount"]
                    input_spent = input_["spent"]
                    if (input_receiver == from_):
                        if (input_spent == False):
                            total_available += Decimal(input_amount)
                for output_ in outputs:
                    output_receiver = output_["receiver"]
                    output_amount = output_["amount"]
                    if output_receiver in (to_, ADMIN_ADDRESS):
                        total_required += Decimal(output_amount)
                    else:
                        logger.warning(f"Invalid output receiver in transaction: {output_receiver}")
                        return rpc_error(-1, f"Invalid output receiver: {output_receiver}", data["id"])
                miner_fee = (Decimal(total_authorised) * Decimal("0.001")).quantize(Decimal("0.00000001"))
                total_required = Decimal(total_authorised) + Decimal(miner_fee)
                if (total_required <= total_available):
                       # Spend inputs
                    for input_ in inputs:
                        utxo_key = f"utxo:{input_['txid']}:{input_['utxo_index']}".encode()
                        if utxo_key in db:
                            print(f"****** Marking utxo {utxo_key} as spent")
                            utxo_raw = db.get(utxo_key)
                            if utxo_raw is None:
                                logger.error(f"UTXO not found: {utxo_key}")
                                return rpc_error(-1, f"Input not found: {utxo_key.decode()}", data["id"])
                            utxo = json.loads(utxo_raw.decode())
                            if utxo["spent"]:
                                logger.error(f"Double-spend attempt: {utxo_key}")
                                return rpc_error(-1, f"Double-spend detected: {utxo_key.decode()}", data["id"])
                            utxo["spent"] = True
                            batch.put(utxo_key, json.dumps(utxo).encode())
                            print(f"****** Done marking {utxo_key} as spent")

                    # Create outputs
                    for output_ in outputs:
                        utxo_key = f"utxo:{txid}:{output_['utxo_index']}".encode()
                        utxo_value = {
                            "txid": txid,
                            "utxo_index": output_["utxo_index"],
                            "sender": output_["sender"],
                            "receiver": output_["receiver"],
                            "amount": output_["amount"],
                            "spent": False
                        }
                        batch.put(utxo_key, json.dumps(utxo_value).encode())
                        print(f"****** Created UTXO {utxo_key} → {utxo_value}")

                    # Commit all changes atomically
                    #db.write(batch)
                    #del pending_transactions[txid]


        calculated_merkle = calculate_merkle_root(txids)
        if calculated_merkle != merkle_root_block:
            logger.error(f"Merkle root mismatch: calculated={calculated_merkle}, block={merkle_root_block}")
            return rpc_error(-1, "Merkle root mismatch", data["id"])

        logger.info("Block merkle root validation successful")
        block_data = {
            "version": version,
            "bits": bits,
            "height": get_current_height(db)[0] + 1,
            "block_hash": block.hash(),
            "previous_hash": prev_block,
            "tx_ids": txids,
            "nonce": nonce,
            "timestamp": timestamp,
            "merkle_root": calculated_merkle,
            "miner_address": coinbase_miner_address, 
        }
        batch.put(b"block:" + block.hash().encode(), json.dumps(block_data).encode())
        db.write(batch)

        for tid in txids[1:]:
            pending_transactions.pop(tid, None)

        async with state_lock:
            blockchain.append(block.hash())
        logger.info(f"Block successfully added: {block.hash()} height={block_data['height']} txs={len(tx_list)}")

        full_transactions = []
        for tx_id in block_data.get("tx_ids", []):
            tx_key = f"tx:{tx_id}".encode()
            if tx_key in db:
                tx_data = json.loads(db[tx_key].decode())
                full_transactions.append(tx_data)

        block_data["full_transactions"] = full_transactions


        
        block_gossip = {
                "type": "blocks_response",
                "blocks": block_data,
                "timestamp": int(time.time() * 1000)
        }

        await gossip_client.randomized_broadcast(block_gossip)

        return {"result": None, "error": None, "id": data["id"]}
    
    except Exception as e:
        logger.error(f"Unexpected error in submit_block: {str(e)}")
        return rpc_error(-1, f"Internal error: {str(e)}", data.get("id"))


