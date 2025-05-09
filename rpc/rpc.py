from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from pydantic import BaseModel
from typing import Dict, List, Set, Optional
from decimal import Decimal
from config.config import ADMIN_ADDRESS
from wallet.wallet import verify_transaction
from blockchain.blockchain import Block, bits_to_target, serialize_transaction,scriptpubkey_to_address, read_varint, parse_tx, validate_pow, sha256d, calculate_merkle_root
from state.state import blockchain, state_lock, pending_transactions
from rocksdict import WriteBatch
import asyncio
import copy
import time
import struct
import json


rpc_app = FastAPI()
rpc_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])



@rpc_app.post("/")
async def rpc_handler(request: Request):
    data = await request.json()
    method = data.get("method")

    if method == "getblocktemplate":
        return await get_block_template(data)
    elif method == "submitblock":
        return await submit_block(request,data)
    else:
        return {"error": "unknown method", "id": data.get("id")}


async def get_block_template(data):
    print(data)
    db = get_db()
    timestamp = int(time.time())
    height, previous_block_hash = get_current_height(db)
    transactions = []
    txids = [] 

    #if (len(pending_transactions.values()) == 0):
    #    return "bcdadsfasdf"


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
        "longpollid": "mockid",
    }

    return {
        "result": block_template,
        "error": None,
        "id": data["id"]
    }





async def submit_block(request: Request, data: str) -> dict:
    print(data)
    gossip_client = request.app.state.gossip_client
    raw_block_hex = data["params"][0]
    raw = bytes.fromhex(raw_block_hex)
    db = get_db()
    batch = WriteBatch()  
    txids = []
    tx_list = []
    transactions = []
    hdr = raw[:80]
    version = struct.unpack_from('<I', hdr, 0)[0]
    prev_block = hdr[4:36][::-1].hex()
    merkle_root_block = hdr[36:68][::-1].hex()
    timestamp = struct.unpack_from('<I', hdr, 68)[0]
    bits = struct.unpack_from('<I', hdr, 72)[0] 
    nonce = struct.unpack_from('<I', hdr, 76)[0]
    block = Block(version, prev_block, merkle_root_block, timestamp, bits, nonce)

    if not validate_pow(block):
        print("****** BLOCK VALIDATION FAILED ****")
        return
    else:
        print("****** SUCCESS")

    height_temp = get_current_height(db)
    local_height = height_temp[0]
    local_tip = height_temp[1]

    print(f"Local height: {local_height}, Local tip: {local_tip}")

    if (prev_block != local_tip):
        raise HTTPException(400, "Forked too early / bad prev-hash")

    future_limit = int(time.time()) + 2*60 # 2 mins in the future

    if (timestamp > future_limit):
         raise HTTPException(400, "Block from the future")


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

    batch.put(b"tx:" + coinbase_txid.encode(), json.dumps(coinbase_tx).encode())

    #
    # Add mapping to quantum safe miner address here through endpoint 
    #

    offset += size
    blob = raw[offset:].decode('utf-8')

    decoder = json.JSONDecoder()
    pos     = 0
    while pos < len(blob):
        obj, next_pos = decoder.raw_decode(blob, pos)
        tx_list.append(obj)
        pos = next_pos
        while pos < len(blob) and blob[pos] in ' \t\r\n,':
            pos += 1
  


    for i, tx in enumerate(tx_list, start=1):
        raw_tx = serialize_transaction(tx)
        txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
        txids.append(txid)
        inputs = tx["inputs"]
        print(f"****** INPUTS : {inputs}")
        outputs = tx["outputs"]
        message_str = tx["body"]["msg_str"]
        pubkey = tx["body"]["pubkey"]
        signature = tx["body"]["signature"]
        if(verify_transaction(message_str, signature, pubkey) == True):
            from_ = message_str.split(":")[0]
            to_ = message_str.split(":")[1]
            amount_ = message_str.split(":")[2]
            total_available = Decimal(0)
            total_required = Decimal(0)
            total_authorised = Decimal(amount_)
            for input_ in inputs:
                input_txid = input_["txid"]
                input_sender = input_["sender"]
                input_receiver = input_["receiver"]
                input_amount = input_["amount"]
                input_spent = input_["spent"]
                if (input_receiver == from_):
                    if (input_spent == False):
                        total_available += Decimal(input_amount)
            for output_ in outputs:
                output_sender = output_["sender"]
                output_receiver = output_["receiver"]
                output_amount = output_["amount"]
                output_spent = output_["spent"]
                if output_receiver in (to_, ADMIN_ADDRESS):
                    total_required += Decimal(output_amount)
                else:
                    raise HTTPException(status_code=400, detail="Output receiver is invalid")
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
                            raise HTTPException(400, "Input not found")
                        utxo = json.loads(utxo_raw.decode())
                        if utxo["spent"]:
                            raise HTTPException(400, "Double-spend")
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
        raise HTTPException(400, "Merkle root mismatch")

    print("****** MERKLE HEADERS MATCH")
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
    print(f"Block added: {block.hash()} with {len(tx_list)} transactions")

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


