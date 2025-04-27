import time
import hashlib
import json
from gossip.gossip import GENESIS_ADDRESS, ADMIN_ADDRESS
from state.state import blockchain

async def create_genesis_block(db, is_bootstrap: bool, admin_address: str):
    genesis_tx_id = "genesis_tx"
    genesis_utxo_key = b"utxo:" + genesis_tx_id.encode() + b":0"
    genesis_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    if genesis_utxo_key not in db:
        genesis_amount = "21000000"
        genesis_tx = {
            "txid": genesis_tx_id,
            "inputs": [],
            "outputs": [{
                "txid": genesis_tx_id,
                "utxo_index": 0,
                "sender": "0000000000000000000000000000000000000000",
                "receiver": GENESIS_ADDRESS,
                "amount": genesis_amount,
                "spent": True
            }],
            "body": {
                "msg_str": "genesis",
                "signature": "genesis_sig",
                "pubkey": "genesis_key"
            },
            "timestamp": 0
        }
        db.put(genesis_utxo_key, json.dumps(genesis_tx["outputs"][0]).encode())
        db.put(b"tx:" + genesis_tx_id.encode(), json.dumps(genesis_tx).encode())

        genesis_block_data = {
            "height": 0,
            "block_hash": genesis_block_hash,
            "previous_hash": None,
            "tx_ids": [genesis_tx_id],
            "nonce": 0,
            "timestamp": 0,
            "miner_address": GENESIS_ADDRESS,
        }
        db.put(b"block:" + genesis_block_hash.encode(), json.dumps(genesis_block_data).encode())
        blockchain.append(genesis_block_hash)

        await create_initial_distribution_block(db, genesis_block_hash,ADMIN_ADDRESS,genesis_amount)


async def create_initial_distribution_block(db, prev_hash, admin_address, genesis_amount):
    tx_input = f"{GENESIS_ADDRESS}:{admin_address}:{genesis_amount}".encode()
    initial_tx_id = hashlib.sha256(hashlib.sha256(tx_input).digest()).hexdigest()
    inital_utxo_key = b"utxo:" + initial_tx_id.encode() + b":0"

    if inital_utxo_key not in db:

        initial_tx = {
            "txid": initial_tx_id,
            "inputs": [{
                "txid": "genesis_tx",
                "sender": "0000000000000000000000000000000000000000",
                "receiver": GENESIS_ADDRESS,
                "amount": genesis_amount,
                "spent": True
            }],
            "outputs": [{
                "txid": initial_tx_id,
                "utxo_index": 0,
                "sender": GENESIS_ADDRESS,
                "receiver": admin_address,
                "amount": genesis_amount,
                "spent": False
            }],
            "body": {
                "transaction_data": "initial_distribution",
                "signature": "initial_sig",
                "pubkey": "initial_key"
            },
            "timestamp": int(time.time() * 1000)
        }
        initial_utxo_key = f"utxo:{initial_tx_id}:0".encode()
        db.put(initial_utxo_key, json.dumps(initial_tx["outputs"][0]).encode())
        db.put(b"tx:" + initial_tx_id.encode(), json.dumps(initial_tx).encode())

        block_1_hash = hashlib.sha256(
            hashlib.sha256(f"{prev_hash}{initial_tx_id}".encode()).digest()
        ).hexdigest()

        block_1_data = {
            "height": 1,
            "block_hash": block_1_hash,
            "previous_hash": prev_hash,
            "tx_ids": [initial_tx_id],
            "nonce": 1,
            "timestamp": int(time.time() * 1000),
            "miner_address": admin_address,
        }
        db.put(b"block:" + block_1_hash.encode(), json.dumps(block_1_data).encode())
        blockchain.append(block_1_hash)
