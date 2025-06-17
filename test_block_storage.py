#!/usr/bin/env python3
"""Test script to check block storage and propagation"""

import json
import logging
from database.database import get_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_block_storage():
    """Check what's actually stored in the database"""
    db = get_db()
    
    blocks = []
    transactions = []
    utxos = []
    
    # Scan all keys
    for key, value in db.items():
        key_str = key.decode() if isinstance(key, bytes) else key
        
        if key_str.startswith("block:"):
            block_data = json.loads(value.decode() if isinstance(value, bytes) else value)
            blocks.append({
                "key": key_str,
                "height": block_data.get("height"),
                "hash": block_data.get("block_hash"),
                "has_full_txs": "full_transactions" in block_data,
                "num_full_txs": len(block_data.get("full_transactions", [])),
                "num_tx_ids": len(block_data.get("tx_ids", []))
            })
        elif key_str.startswith("tx:"):
            transactions.append(key_str)
        elif key_str.startswith("utxo:"):
            utxos.append(key_str)
    
    # Sort blocks by height
    blocks.sort(key=lambda x: x.get("height", -1))
    
    print("\n=== DATABASE ANALYSIS ===")
    print(f"Total blocks: {len(blocks)}")
    print(f"Total transactions: {len(transactions)}")
    print(f"Total UTXOs: {len(utxos)}")
    
    print("\n=== BLOCK DETAILS ===")
    for block in blocks[:10]:  # Show first 10 blocks
        print(f"Height {block['height']}: {block['hash'][:16]}...")
        print(f"  - Has full_transactions: {block['has_full_txs']}")
        print(f"  - Full transactions: {block['num_full_txs']}")
        print(f"  - Transaction IDs: {block['num_tx_ids']}")
    
    # Check for missing transactions
    print("\n=== CHECKING TRANSACTION CONSISTENCY ===")
    missing_txs = 0
    for block in blocks[:5]:  # Check first 5 blocks
        block_key = block["key"]
        block_data = json.loads(db.get(block_key.encode()).decode())
        
        for txid in block_data.get("tx_ids", []):
            tx_key = f"tx:{txid}"
            if tx_key.encode() not in db:
                print(f"  - Missing transaction {txid} from block at height {block['height']}")
                missing_txs += 1
    
    if missing_txs == 0:
        print("  ✓ All transactions found in database")
    else:
        print(f"  ✗ {missing_txs} transactions missing!")
    
    # Check chain tip
    chain_tip = db.get(b"chain:best_tip")
    if chain_tip:
        tip_data = json.loads(chain_tip.decode())
        print(f"\n=== CHAIN TIP ===")
        print(f"Best tip hash: {tip_data.get('hash')}")
        print(f"Best tip height: {tip_data.get('height')}")

if __name__ == "__main__":
    check_block_storage()