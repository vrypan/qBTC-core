from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from pydantic import BaseModel
from typing import Dict, List, Set, Optional
from decimal import Decimal
from state.state import pending_transactions
from gossip.gossip import sha256d, calculate_merkle_root
from wallet.wallet import verify_transaction
from blockchain.blockchain import Block, bits_to_target, serialize_transaction,scriptpubkey_to_address, read_varint, parse_tx, validate_pow
from state.state import blockchain
import logger
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
        return await submit_block(data)
    else:
        return {"error": "unknown method", "id": data.get("id")}


async def get_block_template(data):
    print(data)
    timestamp = int(time.time())
    db = get_db()
    height, previous_block_hash = get_current_height(db)
    transactions = []
    txids = [] 

    #if (len(pending_transactions.values()) == 0):
    #    return "bcdadsfasdf"

    for tx in pending_transactions.values():

        txid = tx["txid"]
        db.put(b"tx:" + txid.encode(), json.dumps(tx).encode())
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





async def submit_block(data: str) -> dict:
    raw_block_hex = data["params"][0]
    raw = bytes.fromhex(raw_block_hex)
    db = get_db()
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
    db.put(b"tx:" + coinbase_txid.encode(), json.dumps(coinbase_tx).encode())

    #
    # Add mapping to quantum safe miner address here through endpoint 
    #

    txids.append(coinbase_txid)
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
    if not validate_pow(block):
        print("****** BLOCK VALIDATION FAILED ****")
        return
    else:
        print("****** SUCCESS")


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
                if output_receiver in (to_, ADMIN_ADDRESS, TREASURY_ADDRESS):
                    total_required += Decimal(output_amount)
                else:
                    return "Fuck hack"
            miner_fee = (Decimal(total_authorised) * Decimal("0.001")).quantize(Decimal("0.00000001"))
            treasury_fee = (Decimal(total_authorised) * Decimal("0.001")).quantize(Decimal("0.00000001"))
            total_required = Decimal(total_authorised) + Decimal(miner_fee) + Decimal(treasury_fee)
            if (total_required <= total_available):
                batch = WriteBatch()
                # Spend inputs
                for input_ in inputs:
                    utxo_key = f"utxo:{input_['txid']}:{input_['utxo_index']}".encode()
                    if utxo_key in db:
                        print(f"****** Marking utxo {utxo_key} as spent")
                        utxo = json.loads(db.get(utxo_key).decode())
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
                db.write(batch)
                del pending_transactions[txid]


    calculated_merkle = calculate_merkle_root(txids)
    print(calculated_merkle)
    print(merkle_root_block)
    if (calculated_merkle == merkle_root_block):
        print("****** MERKLE HEADERS MATCH")


        block_data = {
            "height": get_current_height(db)[0] + 1,
            "block_hash": block.hash(),
            "previous_hash": prev_block,
            "tx_ids": txids,
            "nonce": nonce,
            "timestamp": timestamp,
            "merkle_root": calculated_merkle,
            "miner_address": coinbase_miner_address, 
        }
        db.put(b"block:" + block.hash().encode(), json.dumps(block_data).encode())
        blockchain.append(block.hash())
        print(f"Block added: {block.hash()} with {len(tx_list)} transactions")
        return {"result": None, "error": None, "id": data["id"]}