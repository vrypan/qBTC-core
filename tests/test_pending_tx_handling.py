#!/usr/bin/env python3
"""
Test pending transaction handling and identify duplicates
"""

import sys
import os
import json
import copy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain import sha256d, serialize_transaction
from state.state import pending_transactions

def analyze_pending_transactions():
    """Analyze current pending transactions for issues"""
    print("=== Analyzing Pending Transactions ===\n")
    
    if not pending_transactions:
        print("No pending transactions found")
        return
    
    print(f"Total entries in pending_transactions: {len(pending_transactions)}")
    
    # Check for duplicates and consistency
    txid_to_keys = {}
    calculated_txids = {}
    
    for key, tx in pending_transactions.items():
        print(f"\nKey: {key}")
        
        # Get stored txid
        stored_txid = tx.get("txid")
        print(f"  Stored TXID field: {stored_txid}")
        
        # Calculate txid
        tx_clean = copy.deepcopy(tx)
        if "txid" in tx_clean:
            del tx_clean["txid"]
        for output in tx_clean.get("outputs", []):
            output.pop("txid", None)
        
        raw_tx = serialize_transaction(tx_clean)
        calculated_txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
        print(f"  Calculated TXID: {calculated_txid}")
        
        # Check consistency
        if stored_txid and stored_txid != calculated_txid:
            print(f"  WARNING: TXID mismatch!")
        
        if key != calculated_txid:
            print(f"  WARNING: Key doesn't match calculated TXID!")
        
        # Track duplicates
        if calculated_txid in calculated_txids:
            print(f"  WARNING: Duplicate transaction!")
            print(f"  Previous key: {calculated_txids[calculated_txid]}")
        else:
            calculated_txids[calculated_txid] = key
        
        # Show transaction details
        if "body" in tx:
            msg = tx["body"].get("msg_str", "")
            print(f"  Message: {msg[:60]}...")
        
        print(f"  Timestamp: {tx.get('timestamp', 'unknown')}")
        print(f"  Type: {tx.get('type', 'unknown')}")
    
    print(f"\nSummary:")
    print(f"  Total entries: {len(pending_transactions)}")
    print(f"  Unique transactions: {len(calculated_txids)}")
    print(f"  Duplicates: {len(pending_transactions) - len(calculated_txids)}")


def test_transaction_addition():
    """Test how transactions are added to pending_transactions"""
    print("\n\n=== Testing Transaction Addition ===\n")
    
    # Create a test transaction
    test_tx = {
        "type": "transaction",
        "body": {
            "msg_str": "from:to:100:12345",
            "pubkey": "test_key",
            "signature": "test_sig"
        },
        "inputs": [{"test": "input"}],
        "outputs": [{"test": "output"}],
        "timestamp": 12345
    }
    
    # Method 1: Add without txid (as done in web.py initially)
    tx1 = copy.deepcopy(test_tx)
    raw1 = serialize_transaction(tx1)
    txid1 = sha256d(bytes.fromhex(raw1))[::-1].hex()
    print(f"Method 1 (no txid field):")
    print(f"  TXID: {txid1}")
    
    # Method 2: Add with txid field (as done in web.py after calculation)
    tx2 = copy.deepcopy(test_tx)
    tx2["txid"] = txid1
    raw2 = serialize_transaction(tx2)  # This should remove txid before serialization
    txid2 = sha256d(bytes.fromhex(raw2))[::-1].hex()
    print(f"\nMethod 2 (with txid field):")
    print(f"  TXID: {txid2}")
    print(f"  Same as method 1: {txid1 == txid2}")
    
    # Method 3: What happens if txid is in outputs too
    tx3 = copy.deepcopy(test_tx)
    tx3["txid"] = txid1
    for output in tx3.get("outputs", []):
        output["txid"] = txid1
    raw3 = serialize_transaction(tx3)
    txid3 = sha256d(bytes.fromhex(raw3))[::-1].hex()
    print(f"\nMethod 3 (txid in outputs):")
    print(f"  TXID: {txid3}")
    print(f"  Same as method 1: {txid1 == txid3}")


def simulate_block_template_issue():
    """Simulate the issue with block templates and cpuminer"""
    print("\n\n=== Simulating Block Template Issue ===\n")
    
    # Create mock pending transaction (as it would be stored)
    mock_tx = {
        "type": "transaction",
        "txid": "mock_txid_12345",  # This would be added by web.py
        "body": {"msg_str": "test:test:100:12345"},
        "inputs": [],
        "outputs": [{"txid": "mock_txid_12345"}],  # This would also be added
        "timestamp": 12345
    }
    
    # Simulate getblocktemplate processing
    print("1. getblocktemplate processing:")
    tx_copy = copy.deepcopy(mock_tx)
    stored_txid = tx_copy.get("txid")
    
    # Remove txid fields
    if "txid" in tx_copy:
        del tx_copy["txid"]
    for output in tx_copy.get("outputs", []):
        output.pop("txid", None)
    
    raw_tx = serialize_transaction(tx_copy)
    calc_txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
    
    print(f"   Stored TXID: {stored_txid}")
    print(f"   Calculated TXID: {calc_txid}")
    print(f"   Raw TX sent to cpuminer: {raw_tx[:100]}...")
    
    # Simulate cpuminer echoing it back
    print("\n2. cpuminer echoes back the JSON:")
    print("   cpuminer includes this in the block exactly as sent")
    print("   But might include it multiple times!")
    
    # When we parse it back
    print("\n3. Parsing from submitted block:")
    parsed_tx = json.loads(bytes.fromhex(raw_tx).decode())
    print(f"   Parsed TX has 'txid' field: {'txid' in parsed_tx}")
    print(f"   Outputs have 'txid' field: {any('txid' in o for o in parsed_tx.get('outputs', []))}")
    
    # Calculate txid from parsed transaction
    parsed_raw = serialize_transaction(parsed_tx)
    parsed_txid = sha256d(bytes.fromhex(parsed_raw))[::-1].hex()
    print(f"   TXID from parsed: {parsed_txid}")
    print(f"   Matches calculated: {parsed_txid == calc_txid}")


if __name__ == "__main__":
    print("qBTC Pending Transaction Analysis")
    print("=" * 50)
    
    analyze_pending_transactions()
    test_transaction_addition()
    simulate_block_template_issue()
    
    print("\n" + "=" * 50)
    print("Analysis completed!")