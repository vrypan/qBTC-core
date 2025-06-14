import json
import os
from config.config import GENESIS_ADDRESS
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
                "sender": GENESIS_ADDRESS,
                "receiver": os.getenv("ADMIN_ADDRESS", "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"),
                "amount": genesis_amount,
                "spent": False
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




