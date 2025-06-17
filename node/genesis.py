import json
import os
import logging
from config.config import GENESIS_ADDRESS
from state.state import blockchain

logger = logging.getLogger(__name__)

async def create_genesis_block(db, is_bootstrap: bool, admin_address: str):
    logger.info(f"Checking for genesis block (is_bootstrap={is_bootstrap}, admin={admin_address})...")
    genesis_tx_id = "genesis_tx"
    genesis_utxo_key = b"utxo:" + genesis_tx_id.encode() + b":0"
    genesis_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Check if genesis block exists by looking for the block itself
    genesis_block_key = b"block:" + genesis_block_hash.encode()
    
    if genesis_block_key not in db:
        logger.info("Genesis block not found, creating...")
        logger.info(f"Database has {len(list(db.items()))} entries before genesis creation")
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
            "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "tx_ids": [genesis_tx_id],
            "nonce": 0,
            "timestamp": 0,
            "miner_address": GENESIS_ADDRESS,
            "version": 1,
            "merkle_root": "0000000000000000000000000000000000000000000000000000000000000000",
            "bits": 0x1d00ffff,  # Genesis difficulty
        }
        db.put(b"block:" + genesis_block_hash.encode(), json.dumps(genesis_block_data).encode())
        blockchain.append(genesis_block_hash)
        logger.info(f"Genesis block created with hash: {genesis_block_hash}")
        logger.info(f"Database now has {len(list(db.items()))} entries after genesis creation")
        logger.info(f"Blockchain list now has {len(blockchain)} blocks")
    else:
        logger.info("Genesis block already exists")




