from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from database.database import get_db, get_current_height
from pydantic import BaseModel
from typing import Dict, List, Set, Optional
from decimal import Decimal
from config.config import ADMIN_ADDRESS
from wallet.wallet import verify_transaction
from blockchain.blockchain import  derive_qsafe_address, Block, bits_to_target, serialize_transaction,scriptpubkey_to_address, read_varint, parse_tx, validate_pow, sha256d, calculate_merkle_root
from blockchain.protobuf_class import  Input, Output, TxBody, Transaction 
from state.state import blockchain, state_lock, pending_transactions
from rocksdict import WriteBatch
import hashlib
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
    db = get_db()
    timestamp = int(time.time())
    height, previous_block_hash = get_current_height(db)
    txids = []
    blob = ""

    # ---- Add pending transactions ----
    for tx in pending_transactions.values():
        blob += tx.raw + "7c7c"
        txids.append(tx.txid)


    block_template = {
        "version": 1,
        "previousblockhash": previous_block_hash,
        "target": f"{bits_to_target(0x1f00ffff):064x}",
        "bits": f"{0x1f00ffff:08x}",
        "curtime": timestamp,
        "height": height + 1,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "capabilities": ["proposal"],
        "coinbaseaux": {},
        "coinbasevalue": 5000000000,
        "transactions": [{
            "data": blob,
            "hash": txids  # still exclude coinbase
        }],
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

    print(version)
    print(prev_block)
    print(merkle_root_block)
    print(timestamp)
    print(bits)
    print(nonce)

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
    print(f"Coinbase raw hex: {coinbase_raw.hex()}")
    print(f"Coinbase txid: {coinbase_txid}")
    txids.append(coinbase_txid)

    print(f"****** COINBASE TXID: {coinbase_txid}")
   
    offset += size
    blob = raw[offset:] #.decode('utf-8')

    print("**** IM NOW AT BLOB")

    segments = blob.hex().split("7c7c")
    for segment in segments:
        if not segment.strip():
            continue

        tx_bytes = bytes.fromhex(segment)
        txid = sha256d(tx_bytes)[::-1].hex()
        tx = Transaction()
        tx.ParseFromString(tx_bytes)
        tx.raw = segment  # store the original raw tx for later if needed
        transactions.append(tx)
        txids.append(txid)

        print(f"***** {txid}")

        # -- signature check and state update --
        message_str = tx.body.msg_str
        signature = tx.body.signature
        pubkey = tx.body.pubkey

        if verify_transaction(message_str, signature, pubkey):
            print("pubkey is")
            print(pubkey)

            from_ = message_str.split(":")[0]
            to_ = message_str.split(":")[1]
            amount_ = message_str.split(":")[2]

            assert derive_qsafe_address(pubkey) == from_, "Wrong signature"

            total_amount = Decimal(0)
            spent_keys = []

            for input_ in tx.inputs:
                input_txid = input_.txid
                input_utxo_index = input_.utxo_index
                print(f"Input txid is {input_txid}")
                utxo_key = f"utxo:{input_txid}:{input_utxo_index}".encode()
                if utxo_key in db:
                    db_output = Output()
                    db_output.ParseFromString(db.get(utxo_key))
                    if db_output.receiver == from_ and not db_output.spent:
                        total_amount += Decimal(db_output.amount)
                        spent_keys.append((utxo_key, db_output))

            if Decimal(amount_) > total_amount:
                return {"status": "error", "message": "Insufficient funds"}

            for utxo_key, output in spent_keys:
                output.spent = True
                batch.put(utxo_key, output.SerializeToString())

            # Build and store outputs
            outputs = [Output(
                utxo_index=0,
                sender=from_,
                receiver=to_,
                amount=str(amount_),
                spent=False
            )]

            change = total_amount - Decimal(amount_)
            if change > 0:
                outputs.append(Output(
                    utxo_index=1,
                    sender=from_,
                    receiver=from_,
                    amount=str(change),
                    spent=False
                ))

            for i, output in enumerate(outputs):
                output.txid = txid
                output.utxo_index = i
                utxo_key = f"utxo:{txid}:{i}".encode()
                batch.put(utxo_key, output.SerializeToString())



    calculated_merkle = calculate_merkle_root(txids)

    print(f"merkle_root_block is {merkle_root_block}")
    calculated_merkle = print_merkle_debug(txids)
    if calculated_merkle != merkle_root_block:
        raise HTTPException(400, "Merkle root mismatch")

    print("****** MERKLE HEADERS MATCH")








def print_merkle_debug(txids: list[str]):
    print("\n📦 Merkle Tree Debug:")
    print("TXIDs used for Merkle Root Calculation:")
    for i, txid in enumerate(txids):
        print(f"  [{i}] {txid}")

    def sha256d(b):
        return hashlib.sha256(hashlib.sha256(b).digest()).digest()

    hashes = [bytes.fromhex(t)[::-1] for t in txids]
    level = 0
    while len(hashes) > 1:
        print(f"\n🧱 Level {level} ({len(hashes)} items):")
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i] if i + 1 == len(hashes) else hashes[i + 1]
            print(f"  Pair {i // 2}:")
            print(f"    Left : {left[::-1].hex()}")
            print(f"    Right: {right[::-1].hex()}")
            combined = sha256d(left + right)
            print(f"    Hash : {combined[::-1].hex()}")
        # Next level
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        hashes = [sha256d(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]
        level += 1

    final_merkle = hashes[0][::-1].hex()
    print(f"\n✅ Final Merkle Root: {final_merkle}\n")
    return final_merkle

