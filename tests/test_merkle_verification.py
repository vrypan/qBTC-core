#!/usr/bin/env python3
"""
Test script to verify merkle tree calculations and identify why cpuminer blocks fail
"""

import sys
import os
import json
import struct
import copy
from decimal import Decimal

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain import sha256d, calculate_merkle_root, serialize_transaction, read_varint, parse_tx
from state.state import pending_transactions

def test_merkle_calculation():
    """Test basic merkle root calculation"""
    print("=== Testing Merkle Root Calculation ===\n")
    
    # Test 1: Single transaction (coinbase only)
    print("Test 1: Single transaction")
    txids = ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]
    merkle = calculate_merkle_root(txids)
    print(f"  TXIDs: {txids}")
    print(f"  Merkle: {merkle}")
    print(f"  Should equal TXID: {merkle == txids[0]}")
    assert merkle == txids[0], "Single transaction merkle should equal the txid"
    
    # Test 2: Two transactions
    print("\nTest 2: Two transactions")
    txids = [
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "2e7d2c03a83e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c"
    ]
    merkle = calculate_merkle_root(txids)
    print(f"  TXIDs: {txids}")
    print(f"  Merkle: {merkle}")
    
    # Manual calculation
    h1 = bytes.fromhex(txids[0])[::-1]
    h2 = bytes.fromhex(txids[1])[::-1]
    manual_merkle = sha256d(h1 + h2)[::-1].hex()
    print(f"  Manual: {manual_merkle}")
    print(f"  Match: {merkle == manual_merkle}")
    
    # Test 3: Three transactions (odd number)
    print("\nTest 3: Three transactions (odd, last should be duplicated)")
    txids = [
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        "2e7d2c03a83e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c0e5e4e4c",
        "3f8e3d14b94f5f5d1f6f5f5d1f6f5f5d1f6f5f5d1f6f5f5d1f6f5f5d1f6f5f5d"
    ]
    merkle = calculate_merkle_root(txids)
    print(f"  Merkle: {merkle}")


def test_transaction_serialization():
    """Test transaction serialization consistency"""
    print("\n\n=== Testing Transaction Serialization ===\n")
    
    # Create a sample quantum transaction
    sample_tx = {
        "type": "transaction",
        "body": {
            "msg_str": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV:bqs1NoaFdBFxgaKoUzf4nn3peMwT8P32meFg8:5E+2:1750023931501",
            "pubkey": "37767715d7165274b9e7909d351f30a7254b4ee1c07b026e411ea7c9985de34d...",  # truncated
            "signature": "47446b1df47df810981208da78cf6eb0779224cd540c23acfa99ef432d88d9eb..."  # truncated
        },
        "inputs": [{
            "amount": "21000000",
            "receiver": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV",
            "sender": "bqs1genesis00000000000000000000000000000000",
            "spent": False,
            "txid": "genesis_tx",
            "utxo_index": 0
        }],
        "outputs": [{
            "amount": "5E+2",
            "receiver": "bqs1NoaFdBFxgaKoUzf4nn3peMwT8P32meFg8",
            "sender": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV",
            "spent": False,
            "utxo_index": 0
        }, {
            "amount": "20999499.50000000",
            "receiver": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV",
            "sender": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV",
            "spent": False,
            "utxo_index": 1
        }],
        "timestamp": 1750023931517
    }
    
    # Test with and without txid
    print("Test 1: Transaction without txid field")
    tx1 = copy.deepcopy(sample_tx)
    raw1 = serialize_transaction(tx1)
    txid1 = sha256d(bytes.fromhex(raw1))[::-1].hex()
    print(f"  TXID: {txid1}")
    
    print("\nTest 2: Transaction with txid field")
    tx2 = copy.deepcopy(sample_tx)
    tx2["txid"] = "dummy_txid"
    raw2 = serialize_transaction(tx2)
    txid2 = sha256d(bytes.fromhex(raw2))[::-1].hex()
    print(f"  TXID: {txid2}")
    print(f"  Should be same: {txid1 == txid2}")
    
    print("\nTest 3: Transaction with txid in outputs")
    tx3 = copy.deepcopy(sample_tx)
    for output in tx3["outputs"]:
        output["txid"] = "dummy_txid"
    raw3 = serialize_transaction(tx3)
    txid3 = sha256d(bytes.fromhex(raw3))[::-1].hex()
    print(f"  TXID: {txid3}")
    print(f"  Should be same: {txid1 == txid3}")


def simulate_cpuminer_block():
    """Simulate what cpuminer does with our transactions"""
    print("\n\n=== Simulating cpuminer Block Creation ===\n")
    
    # Mock pending transaction
    sample_tx = {
        "type": "transaction",
        "body": {
            "msg_str": "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV:bqs1NoaFdBFxgaKoUzf4nn3peMwT8P32meFg8:5E+2:1750023931501",
            "pubkey": "test_pubkey",
            "signature": "test_signature"
        },
        "inputs": [{"amount": "100", "receiver": "test", "sender": "test", "spent": False, "txid": "test", "utxo_index": 0}],
        "outputs": [{"amount": "50", "receiver": "test", "sender": "test", "spent": False, "utxo_index": 0}],
        "timestamp": 1750023931517
    }
    
    # Simulate block template creation
    print("1. Creating block template with transaction")
    tx_copy = copy.deepcopy(sample_tx)
    if "txid" in tx_copy:
        del tx_copy["txid"]
    for output in tx_copy.get("outputs", []):
        output.pop("txid", None)
    
    raw_tx = serialize_transaction(tx_copy)
    template_txid = sha256d(bytes.fromhex(raw_tx))[::-1].hex()
    print(f"   Template TXID: {template_txid}")
    print(f"   Raw TX length: {len(raw_tx)} chars")
    
    # Simulate cpuminer echoing back the transaction
    print("\n2. cpuminer echoes back transaction data")
    print("   cpuminer includes: coinbase + our JSON transaction")
    
    # Create mock block with coinbase + JSON tx
    coinbase_txid = "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6"
    
    # Calculate merkle root with both
    txids = [coinbase_txid, template_txid]
    calculated_merkle = calculate_merkle_root(txids)
    print(f"\n3. Merkle root calculation:")
    print(f"   Coinbase TXID: {coinbase_txid}")
    print(f"   JSON TX TXID:  {template_txid}")
    print(f"   Merkle root:   {calculated_merkle}")
    
    # Test with duplicate transaction (as seen in logs)
    print("\n4. Testing with duplicate transaction (cpuminer bug?)")
    txids_dup = [coinbase_txid, template_txid, template_txid]
    merkle_dup = calculate_merkle_root(txids_dup)
    print(f"   TXIDs: {len(txids_dup)} transactions")
    print(f"   Merkle: {merkle_dup}")
    print(f"   Different from non-dup: {merkle_dup != calculated_merkle}")


def test_real_block_data():
    """Test with actual block data from the logs"""
    print("\n\n=== Testing with Real Block Data ===\n")
    
    # From the logs
    coinbase_txid = "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6"
    json_txid = "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873"
    
    # Block header merkle root from logs
    block_merkle = "f3eec5e3d114b10834a0916e735c5cc357ff3e08f8f2d20fa884e1041a2fb555"
    
    print(f"From logs:")
    print(f"  Coinbase TXID: {coinbase_txid}")
    print(f"  JSON TX TXID:  {json_txid}")
    print(f"  Block merkle:  {block_merkle}")
    
    # Test different combinations
    print("\n1. Two transactions (what we calculate):")
    txids = [coinbase_txid, json_txid]
    calc_merkle = calculate_merkle_root(txids)
    print(f"   Calculated: {calc_merkle}")
    print(f"   Match: {calc_merkle == block_merkle}")
    
    print("\n2. Three transactions (header says 3):")
    txids3 = [coinbase_txid, json_txid, json_txid]
    calc_merkle3 = calculate_merkle_root(txids3)
    print(f"   Calculated: {calc_merkle3}")
    print(f"   Match: {calc_merkle3 == block_merkle}")
    
    # Try to reverse engineer what cpuminer did
    print("\n3. Reverse engineering cpuminer's merkle calculation:")
    print("   cpuminer might be calculating merkle root differently...")
    
    # Maybe cpuminer included an empty transaction?
    empty_txid = sha256d(b"")[::-1].hex()
    txids_empty = [coinbase_txid, json_txid, empty_txid]
    calc_empty = calculate_merkle_root(txids_empty)
    print(f"   With empty tx: {calc_empty}")
    print(f"   Match: {calc_empty == block_merkle}")


def monkey_patch_test():
    """Monkey patch to intercept and debug merkle calculations"""
    print("\n\n=== Monkey Patching for Debug ===\n")
    
    # Save original function
    original_calculate_merkle_root = calculate_merkle_root
    
    def debug_calculate_merkle_root(txids):
        print(f"\n[MERKLE DEBUG] calculate_merkle_root called with {len(txids)} txids:")
        for i, txid in enumerate(txids):
            print(f"  [{i}] {txid}")
        
        result = original_calculate_merkle_root(txids)
        print(f"[MERKLE DEBUG] Result: {result}")
        
        # Show step by step
        if len(txids) > 1:
            print("[MERKLE DEBUG] Step by step:")
            hashes = [bytes.fromhex(txid)[::-1] for txid in txids]
            level = 0
            while len(hashes) > 1:
                print(f"  Level {level}: {len(hashes)} hashes")
                if len(hashes) % 2 == 1:
                    hashes.append(hashes[-1])
                    print(f"    Duplicated last hash")
                new_hashes = []
                for i in range(0, len(hashes), 2):
                    combined = hashes[i] + hashes[i + 1]
                    new_hash = sha256d(combined)
                    new_hashes.append(new_hash)
                hashes = new_hashes
                level += 1
        
        return result
    
    # Monkey patch
    import blockchain.blockchain
    blockchain.blockchain.calculate_merkle_root = debug_calculate_merkle_root
    
    # Test with real data
    print("Testing patched function:")
    txids = [
        "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6",
        "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873"
    ]
    result = blockchain.blockchain.calculate_merkle_root(txids)
    
    # Restore
    blockchain.blockchain.calculate_merkle_root = original_calculate_merkle_root


if __name__ == "__main__":
    print("qBTC Merkle Tree Verification Tests")
    print("=" * 50)
    
    test_merkle_calculation()
    test_transaction_serialization()
    simulate_cpuminer_block()
    test_real_block_data()
    monkey_patch_test()
    
    print("\n" + "=" * 50)
    print("Tests completed!")