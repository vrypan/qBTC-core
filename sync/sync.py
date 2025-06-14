from database.database import get_db, get_current_height
from rocksdict import WriteBatch
from blockchain.blockchain import Block ,calculate_merkle_root, validate_pow
from config.config import ADMIN_ADDRESS, GENESIS_ADDRESS
from wallet.wallet import verify_transaction
import json
import logging
from decimal import Decimal, ROUND_DOWN



def process_blocks_from_peer(blocks: list[dict]):
        logging.info("***** IN GOSSIP MSG RECEIVE BLOCKS RESPONSE")
        db = get_db()
        raw_blocks = blocks

        print("**** RAW BLOCkS ****")
        print(raw_blocks)
        if isinstance(raw_blocks, dict):
            raw_blocks = [raw_blocks]

        blocks = sorted(raw_blocks, key=lambda b: b["height"])
        logging.info("Received %d blocks", len(blocks))

        for block in blocks:
            db_height, db_hash = get_current_height(db)
            height = block.get("height")
            block_hash = block.get("block_hash")
            prev_hash = block.get("previous_hash")


            if height != db_height + 1:
                print("Height mismatch")
                logging.debug("Out-of-sequence block %s (height %s)", block_hash, height)
                continue

            if prev_hash != db_hash:
                print("tip mismatch")
                logging.debug("Previous hash %s doesn’t match tip %s", prev_hash, db_hash)
                continue

            block_key = f"block:{block_hash}".encode()

            if block_key in db:
                logging.debug("Block %s already exists in DB – skipping", block_hash)
                continue

            tx_ids = block.get("tx_ids", [])
            nonce = block.get("nonce")
            timestamp = block.get("timestamp")
            miner_address = block.get("miner_address")
            full_transactions = block.get("full_transactions", [])
            block_merkle_root = block.get("merkle_root")
            version = block.get("version")
            bits = block.get("bits")
            print(f"version {version}")
            print(f"prevhash {prev_hash}")
            print(f"block_merkle_root {block_merkle_root}")
            print(f"timestamp {timestamp}")
            print(f"bits {bits}")
            print(f"nonce {nonce}")
            block_header = Block(version,prev_hash,block_merkle_root,timestamp,bits,nonce)

            if not validate_pow(block_header):
                raise ValueError(f"PoW validation failed for block {height} {block_hash}")


            logging.info("[SYNC] Processing block height %s with hash %s", height, block_hash)

            batch = WriteBatch()


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
            batch.put(block_key, json.dumps(block_record).encode())

 
            db.write(batch)

            logging.info("[SYNC] Stored block %s (height %s) successfully", block_hash, height)