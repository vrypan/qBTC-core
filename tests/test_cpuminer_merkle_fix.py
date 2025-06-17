#!/usr/bin/env python3
"""
Test script to verify merkle tree calculations handle cpuminer duplicate transactions correctly
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blockchain.blockchain import sha256d, calculate_merkle_root

def test_merkle_with_duplicates():
    """Test merkle root calculation with duplicate transactions (cpuminer issue)"""
    print("=== Testing Merkle Root with Duplicate Transactions ===\n")
    
    # Simulated block data from logs
    coinbase_txid = "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6"
    json_txid = "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873"
    expected_merkle = "f3eec5e3d114b10834a0916e735c5cc357ff3e08f8f2d20fa884e1041a2fb555"
    
    print("Test Case: cpuminer sends 3 transactions (1 coinbase + 2 duplicates)")
    print(f"Coinbase TXID: {coinbase_txid}")
    print(f"JSON TX TXID:  {json_txid}")
    print(f"Expected merkle: {expected_merkle}")
    
    # Test 1: Calculate with 2 unique transactions (what we currently do)
    print("\n1. Current approach (2 unique transactions):")
    txids_unique = [coinbase_txid, json_txid]
    merkle_unique = calculate_merkle_root(txids_unique)
    print(f"   Calculated: {merkle_unique}")
    print(f"   Matches: {merkle_unique == expected_merkle}")
    
    # Test 2: Calculate with 3 transactions (including duplicate)
    print("\n2. With duplicate (3 transactions total):")
    txids_with_dup = [coinbase_txid, json_txid, json_txid]
    merkle_with_dup = calculate_merkle_root(txids_with_dup)
    print(f"   Calculated: {merkle_with_dup}")
    print(f"   Matches: {merkle_with_dup == expected_merkle}")
    
    # Test 3: Verify our fix logic
    print("\n3. Testing fix logic:")
    unique_txids = [coinbase_txid, json_txid]
    tx_count = 3  # From block header
    
    merkle_txids = unique_txids.copy()
    if tx_count > len(unique_txids):
        print(f"   Header says {tx_count} txs but only {len(unique_txids)} unique")
        while len(merkle_txids) < tx_count:
            merkle_txids.append(unique_txids[-1])
        print(f"   Extended to {len(merkle_txids)} txids for merkle")
    
    fixed_merkle = calculate_merkle_root(merkle_txids)
    print(f"   Calculated: {fixed_merkle}")
    print(f"   Matches: {fixed_merkle == expected_merkle}")
    
    assert fixed_merkle == expected_merkle, f"Expected merkle {expected_merkle}, but got {fixed_merkle}"


def test_edge_cases():
    """Test edge cases for merkle calculation"""
    print("\n\n=== Testing Edge Cases ===\n")
    
    # Test with only coinbase
    print("1. Only coinbase (no duplicates):")
    coinbase_only = ["aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6"]
    merkle = calculate_merkle_root(coinbase_only)
    print(f"   Input: 1 transaction")
    print(f"   Merkle: {merkle}")
    print(f"   Should equal txid: {merkle == coinbase_only[0]}")
    
    # Test with 4 transactions (2 unique + 2 duplicates)
    print("\n2. Four transactions (2 unique + 2 duplicates):")
    txids = [
        "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6",
        "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873",
        "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873",
        "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873"
    ]
    merkle = calculate_merkle_root(txids)
    print(f"   Input: {len(txids)} transactions")
    print(f"   Merkle: {merkle}")


def simulate_rpc_logic():
    """Simulate the exact logic in rpc.py"""
    print("\n\n=== Simulating RPC Logic ===\n")
    
    # Simulate block submission
    tx_count = 3  # From block header
    unique_txids = [
        "aef139308f4fe19a56dcb1b75d8eeefab93d7f1f7c48eecc8f903a71773748f6",  # coinbase
        "8f7c883f850e474c545d4493f97bfff73e553c6b996ae7838d0ff87604dfa873"   # json tx
    ]
    block_merkle = "f3eec5e3d114b10834a0916e735c5cc357ff3e08f8f2d20fa884e1041a2fb555"
    
    print(f"Block header says: {tx_count} transactions")
    print(f"Unique transactions found: {len(unique_txids)}")
    
    # Apply fix
    merkle_txids = unique_txids.copy()
    if tx_count > len(unique_txids):
        print(f"\nApplying fix: Header has more txs than unique ones")
        if len(unique_txids) > 1:
            while len(merkle_txids) < tx_count:
                merkle_txids.append(unique_txids[-1])
            print(f"Extended txid list to {len(merkle_txids)} for merkle calculation")
    
    calculated_merkle = calculate_merkle_root(merkle_txids)
    print(f"\nCalculated merkle: {calculated_merkle}")
    print(f"Block merkle:      {block_merkle}")
    print(f"Match: {calculated_merkle == block_merkle}")
    
    if calculated_merkle == block_merkle:
        print("\n✅ FIX SUCCESSFUL! Merkle roots match.")
    else:
        print("\n❌ FIX FAILED! Merkle roots still don't match.")


if __name__ == "__main__":
    print("qBTC cpuminer Merkle Fix Verification")
    print("=" * 50)
    
    # Run tests
    success = test_merkle_with_duplicates()
    test_edge_cases()
    simulate_rpc_logic()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed! The fix should work.")
    else:
        print("❌ Tests failed. Need to investigate further.")