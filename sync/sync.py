from database.database import get_db, get_current_height
from rocksdict import WriteBatch
from blockchain.blockchain import Block, calculate_merkle_root, validate_pow
from blockchain.chain_manager import ChainManager
from config.config import ADMIN_ADDRESS, GENESIS_ADDRESS
from wallet.wallet import verify_transaction
import json
import logging
from decimal import Decimal, ROUND_DOWN
from typing import List, Dict, Tuple, Optional

# Global chain manager instance
chain_manager = None

def get_chain_manager() -> ChainManager:
    """Get or create the global chain manager instance"""
    global chain_manager
    if chain_manager is None:
        chain_manager = ChainManager()
    return chain_manager

def process_blocks_from_peer(blocks: list[dict]):
    logging.info("***** IN GOSSIP MSG RECEIVE BLOCKS RESPONSE")
    
    # Wrap entire function to catch any error
    try:
        _process_blocks_from_peer_impl(blocks)
    except Exception as e:
        logging.error(f"CRITICAL ERROR in process_blocks_from_peer: {e}", exc_info=True)
        # Re-raise to maintain original behavior
        raise

def _process_blocks_from_peer_impl(blocks: list[dict]):
    """Actual implementation of process_blocks_from_peer"""
    
    try:
        db = get_db()
        cm = get_chain_manager()
        raw_blocks = blocks

        print("**** RAW BLOCkS ****")
        print(raw_blocks)
        
        # Log the type and structure for debugging
        logging.info(f"Received blocks type: {type(blocks)}")
        if blocks and len(blocks) > 0:
            logging.info(f"First block type: {type(blocks[0])}")
            logging.info(f"First block keys: {list(blocks[0].keys()) if isinstance(blocks[0], dict) else 'Not a dict'}")
            
        if isinstance(raw_blocks, dict):
            raw_blocks = [raw_blocks]

        blocks = sorted(raw_blocks, key=lambda b: b["height"])
        logging.info("Received %d blocks", len(blocks))
    except Exception as e:
        logging.error(f"Error in process_blocks_from_peer setup: {e}", exc_info=True)
        raise

    accepted_count = 0
    rejected_count = 0
    
    for block in blocks:
        try:
            height = block.get("height")
            block_hash = block.get("block_hash")
            prev_hash = block.get("previous_hash")
            
            # Log block structure for debugging
            logging.info(f"Processing block at height {height} with hash {block_hash}")
            logging.info(f"Block has bits field: {'bits' in block}")
            
            # Add full_transactions to block if not present
            if "full_transactions" not in block:
                block["full_transactions"] = block.get("full_transactions", [])
            
            # Let ChainManager handle consensus
            success, error = cm.add_block(block)
            
            if success:
                accepted_count += 1
                # Only process if block is in main chain
                if cm.is_block_in_main_chain(block_hash):
                    # Process the block transactions
                    _process_block_in_chain(block)
                else:
                    logging.info("Block %s accepted but not in main chain yet", block_hash)
            else:
                rejected_count += 1
                logging.warning("Block %s rejected: %s", block_hash, error)
                continue
                
        except Exception as e:
            logging.error("Error processing block %s: %s", block.get("block_hash", "unknown"), e)
            rejected_count += 1

    logging.info("Block processing complete: %d accepted, %d rejected", accepted_count, rejected_count)
    
    # Check if we need to request more blocks
    best_tip, best_height = cm.get_best_chain_tip()
    logging.info("Current best chain height: %d", best_height)
    
    return accepted_count > 0

def _process_block_in_chain(block: dict):
    """Process a block that is confirmed to be in the main chain"""
    db = get_db()
    batch = WriteBatch()
    
    height = block.get("height")
    block_hash = block.get("block_hash")
    prev_hash = block.get("previous_hash")
    tx_ids = block.get("tx_ids", [])
    nonce = block.get("nonce")
    timestamp = block.get("timestamp")
    miner_address = block.get("miner_address")
    full_transactions = block.get("full_transactions", [])
    block_merkle_root = block.get("merkle_root")
    version = block.get("version")
    bits = block.get("bits")
    
    logging.info("[SYNC] Processing confirmed block height %s with hash %s", height, block_hash)

    for raw in full_transactions:
        if raw is None:
            continue
        tx = raw
        if "transaction" in tx:
            tx = tx["transaction"]
        if tx.get("txid") == "genesis_tx":
            logging.debug("[SYNC] Genesis transaction detected")
            continue

        is_probable_coinbase = all(k in tx for k in ("version", "inputs", "outputs")) and not tx.get("txid")
        if is_probable_coinbase:
            logging.debug("[SYNC] Coinbase transaction detected")
            coinbase_tx_id = f"coinbase_{height}"
            batch.put(f"tx:{coinbase_tx_id}".encode(), json.dumps(tx).encode())

            for idx, output in enumerate(tx.get("outputs", [])):
                output_key = f"utxo:{coinbase_tx_id}:{idx}".encode()
                utxo = {
                    "txid": coinbase_tx_id,
                    "utxo_index": idx,
                    "sender": "coinbase",
                    "receiver": miner_address,   
                    "amount": output.get("value"), ##value here assumes 50BTC however we need to update this to reflect inputs-outputs (tx feees)
                    "spent": False,
                }
                batch.put(output_key, json.dumps(utxo).encode())
            continue

        if "txid" in tx:
            txid = tx["txid"]
            inputs = tx.get("inputs", [])
            outputs = tx.get("outputs", [])
            body = tx.get("body", {})

            pubkey = body.get("pubkey", "unknown")
            signature = body.get("signature", "unknown")

            from_ = to_ = total_authorized = time_ = None
            if body.get("transaction_data") == "initial_distribution" and height == 1:
                total_authorized = "21000000"  
                to_ = ADMIN_ADDRESS
                from_ = GENESIS_ADDRESS
            else:
                msg_str = body.get("msg_str", "")
                parts = msg_str.split(":")
                if len(parts) != 4:
                    raise ValueError(f"Malformed msg_str in tx {txid}: {msg_str}")
                from_, to_, total_authorized, time_ = parts

            total_available = Decimal("0")
            total_required = Decimal("0")

            for inp in inputs:
                if "txid" not in inp:
                    continue
                spent_key = f"utxo:{inp['txid']}:{inp.get('utxo_index', 0)}".encode()
                utxo_raw = db.get(spent_key)
                if not utxo_raw:
                    raise ValueError(f"Missing UTXO for input: {spent_key}")
                utxo = json.loads(utxo_raw.decode())

                if utxo["spent"]:
                    raise ValueError(f"UTXO {spent_key} already spent")
                if utxo["receiver"] != from_:
                    raise ValueError(f"UTXO {spent_key} not owned by sender {from_}")

                total_available += Decimal(utxo["amount"])

            for out in outputs:
                recv = out.get("receiver")
                amt = Decimal(out.get("amount", "0"))
                print(out)
                print("receiver:")
                print(recv)
                print("to:")
                print(to_)
                print(ADMIN_ADDRESS)
                if recv in (to_, from_, ADMIN_ADDRESS):
                    total_required += amt
                else:
                    raise ValueError(
                        f"Hack detected: unauthorized output to {recv} in tx {txid}")

            miner_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(
                Decimal("0.00000001"), rounding=ROUND_DOWN)
            grand_total_required = Decimal(total_authorized) + miner_fee

            if height > 1 and grand_total_required > total_available:
                raise ValueError(
                    f"Invalid tx {txid}: balance {total_available} < required {grand_total_required}")

            if height != 1 and not verify_transaction(msg_str, signature, pubkey):
                raise ValueError(f"Signature check failed for tx {txid}")

            batch.put(f"tx:{txid}".encode(), json.dumps(tx).encode())

            for inp in inputs:
                if "txid" not in inp:
                    continue
                spent_key = f"utxo:{inp['txid']}:{inp.get('utxo_index', 0)}".encode()
                if spent_key in db:
                    utxo_rec = json.loads(db.get(spent_key).decode())
                    utxo_rec["spent"] = True
                    batch.put(spent_key, json.dumps(utxo_rec).encode())

  
            for out in outputs:
                # Ensure amount is always stored as string to avoid scientific notation
                if 'amount' in out:
                    out['amount'] = str(out['amount'])
                out_key = f"utxo:{txid}:{out.get('utxo_index', 0)}".encode()
                batch.put(out_key, json.dumps(out).encode())

    calculated_root = calculate_merkle_root(tx_ids)
    if calculated_root != block_merkle_root:
        raise ValueError(
            f"Merkle root mismatch at height {height}: {calculated_root} != {block_merkle_root}")


    block_record = {
        "height": height,
        "block_hash": block_hash,
        "previous_hash": prev_hash,
        "tx_ids": tx_ids,
        "nonce": nonce,
        "timestamp": timestamp,
        "miner_address": miner_address,
        "merkle_root": calculated_root,
        "version": version,
        "bits": bits,
    }
    
    # Store the block (ChainManager already validated it)
    block_key = f"block:{block_hash}".encode()
    batch.put(block_key, json.dumps(block_record).encode())
    
    db.write(batch)
    logging.info("[SYNC] Stored block %s (height %s) successfully", block_hash, height)

def get_blockchain_info() -> Dict:
    """Get current blockchain information"""
    cm = get_chain_manager()
    best_hash, best_height = cm.get_best_chain_tip()
    
    return {
        "best_block_hash": best_hash,
        "height": best_height,
        "chain_tips": list(cm.chain_tips),
        "orphan_count": len(cm.orphan_blocks),
        "index_size": len(cm.block_index)
    }