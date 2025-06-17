#!/usr/bin/env python3
"""Simple script to mine a block via RPC"""
import requests
import json
import hashlib
import struct
import time

def double_sha256(data):
    """SHA256d hash function"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def mine_block(rpc_url="http://localhost:8332", coinbase_addr="bqs1Azf6oZDhEhK3Gc3GSwbgH2MMrfStLoGzd"):
    # Get block template
    template_request = {
        "jsonrpc": "2.0",
        "method": "getblocktemplate",
        "params": [{"capabilities": ["coinbasetxn", "coinbasevalue", "longpoll", "workid"]}],
        "id": 1
    }
    
    print("Getting block template...")
    response = requests.post(rpc_url, json=template_request)
    template = response.json()["result"]
    
    print(f"Mining block at height {template['height']} with difficulty {template['difficulty']}")
    print(f"Target: {template['target']}")
    
    # Extract block header components
    version = template["version"]
    previousblockhash = template["previousblockhash"]
    merkleroot = template["merkleroot"]
    curtime = template["curtime"]
    bits = template["bits"]
    
    # Convert target to integer for comparison
    target = int(template["target"], 16)
    
    # Try different nonces
    nonce = 0
    start_time = time.time()
    
    while True:
        # Construct block header (80 bytes)
        header = struct.pack("<I", version)  # Version
        header += bytes.fromhex(previousblockhash)[::-1]  # Previous block hash (reversed)
        header += bytes.fromhex(merkleroot)[::-1]  # Merkle root (reversed)
        header += struct.pack("<I", curtime)  # Timestamp
        header += struct.pack("<I", int(bits, 16))  # Bits
        header += struct.pack("<I", nonce)  # Nonce
        
        # Calculate hash
        hash_result = double_sha256(header)
        hash_int = int.from_bytes(hash_result[::-1], 'big')
        
        if hash_int < target:
            block_hash = hash_result[::-1].hex()
            print(f"\nBlock found! Nonce: {nonce}")
            print(f"Block hash: {block_hash}")
            print(f"Time taken: {time.time() - start_time:.2f} seconds")
            
            # Submit block
            # For this simple miner, we'll just submit the header
            # In reality, we'd need to construct the full block with transactions
            submit_request = {
                "jsonrpc": "2.0",
                "method": "submitblock",
                "params": [template["blocktemplate_hex"]],  # This should be the full block
                "id": 2
            }
            
            print("\nNote: Full block submission not implemented in this simple script")
            print("Use cpuminer for actual mining")
            return block_hash
            
        nonce += 1
        if nonce % 100000 == 0:
            print(f"Tried {nonce} nonces... ({time.time() - start_time:.1f}s)")
            
        if nonce > 0xffffffff:
            print("Exhausted nonce space!")
            break

if __name__ == "__main__":
    mine_block()