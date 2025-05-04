import asyncio
import json
import time
import logging
import random
from decimal import Decimal, ROUND_HALF_UP
from asyncio import StreamReader, StreamWriter
from config.config import DEFAULT_GOSSIP_PORT, VALIDATOR_ID, ROCKSDB_PATH
from state.state import pending_transactions, mined_blocks
from wallet.wallet import verify_transaction
from database.database import get_db, get_current_height
from blockchain.blockchain import sha256d, calculate_merkle_root
from dht.dht import push_blocks
from rocksdict import WriteBatch
import hashlib

GENESIS_HASH = "0" * 64
MAX_LINE_BYTES = 30 * 1024 * 1024  




class GossipNode:
    def __init__(self, node_id, wallet=None, is_bootstrap=False, is_full_node=True):
        self.node_id = node_id
        self.wallet = wallet
        self.seen_tx = set()
        self.dht_peers = set()  # Persistent peers from DHT
        self.client_peers = set()  # Temporary peers from incoming connections
        self.failed_peers = {}
        self.server_task = None
        self.server = None
        self.partition_task = None
        self.is_bootstrap = is_bootstrap
        self.is_full_node = is_full_node
        #if not is_bootstrap:
            # Temporary workaround until DHT is fully debugged
        #    self.dht_peers.add(('api.bitcoinqs.org', 7002))

     

    async def start_server(self, host="0.0.0.0", port=DEFAULT_GOSSIP_PORT):
        self.server = await asyncio.start_server(self.handle_client, host, port, limit=MAX_LINE_BYTES)
        self.server_task = asyncio.create_task(self.server.serve_forever())
        #self.partition_task = asyncio.create_task(self.check_partition())

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        peer_info = writer.get_extra_info('peername')
        print(f"******* PEER INFO IS {peer_info}")
        if peer_info not in self.client_peers and peer_info not in self.dht_peers:
            self.client_peers.add(peer_info)
            logging.info(f"Added temporary client peer {peer_info}")
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line:
                    break
                msg = json.loads(line.decode('utf-8').strip())
                await self.handle_gossip_message(msg, peer_info, writer)
        except Exception as e:
            logging.error(f"Error handling client {peer_info}: {e}")
        finally:
            if peer_info in self.client_peers:
                self.client_peers.remove(peer_info)
                logging.info(f"Removed temporary client peer {peer_info}")

    async def handle_gossip_message(self, msg, from_peer, writer):
        db = get_db()  
        msg_type = msg.get("type")
        timestamp = msg.get("timestamp", int(time.time() * 1000))
        tx_id = msg.get("tx_id")

        print(msg)


        if timestamp < int(time.time() * 1000) - 60000:  
            print("**** TRANSACTION IS STALE")
            return


        if msg_type == "transaction":
            print(msg)
            if tx_id in self.seen_tx or tx_id in pending_transactions:
                return
            if not verify_transaction(msg["body"]["msg_str"], msg["body"]["signature"], msg["body"]["pubkey"]):
                return
            tx_lock = asyncio.Lock()
            async with tx_lock:
                if tx_id in pending_transactions:
                    return
                pending_transactions[tx_id] = msg
            await self.randomized_broadcast(msg)
            self.seen_tx.add(tx_id)

        elif msg_type == "blocks_response":
            logging.info("***** IN GOSSIP MSG RECEIVE BLOCKS RESPONSE")
            db = get_db()
            raw_blocks = msg.get("blocks", [])
            if isinstance(raw_blocks, dict):
                raw_blocks = [raw_blocks]

            blocks = sorted(raw_blocks, key=lambda b: b["height"])
            logging.info("Received %d blocks from %s", len(blocks), from_peer)

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

                logging.info("[SYNC] Processing block height %s with hash %s", height, block_hash)

                batch = WriteBatch()


                for tx in full_transactions:
                    if tx.get("tx_id") == "genesis_tx":
                        logging.debug("[SYNC] Genesis transaction detected")
                        batch.put(b"tx:genesis_tx", json.dumps(tx).encode())
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
                                "amount": output.get("value"),
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
                            if inp.get("receiver") != from_:
                                continue
                            if inp.get("spent", False):
                                continue
                            total_available += Decimal(inp.get("amount", "0"))

                        for out in outputs:
                            recv = out.get("receiver")
                            amt = Decimal(out.get("amount", "0"))
                            print(out)
                            print("receiver:")
                            print(recv)
                            print("to:")
                            print(to_)
                            print(ADMIN_ADDRESS)
                            if recv in (to_, ADMIN_ADDRESS):
                                total_required += amt
                            else:
                                raise ValueError(
                                    f"Hack detected: unauthorized output to {recv} in tx {txid}")

                        miner_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(
                            Decimal("0.00000001"), rounding=ROUND_HALF_UP)
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
                }
                batch.put(block_key, json.dumps(block_record).encode())

     
                db.write(batch)

                logging.info("[SYNC] Stored block %s (height %s) successfully", block_hash, height)

                

                




   

        elif msg_type == "get_height":
            height, tip_hash = get_current_height(db)

            response = {"type": "height_response", "height": height, "current_tip": tip_hash}
            writer.write((json.dumps(response) + "\n").encode('utf-8'))
            await writer.drain()

        elif msg_type == "get_blocks":
            print(msg)
            start_height = msg.get("start_height")
            end_height = msg.get("end_height")
            if start_height is None or end_height is None:
                return

            blocks = []

            for h in range(start_height, end_height + 1):
                found_block = None

                for key in db.keys():
                    if key.startswith(b"block:"):
                        block = json.loads(db[key].decode())

                        if block.get("height") == h:
                            expanded_txs = []
                            for tx_id in block["tx_ids"]:
                                tx_key = f"tx:{tx_id}".encode()
                                if tx_key in db:
                                    tx_data = json.loads(db[tx_key].decode())
                                    expanded_txs.append({
                                        "tx_id": tx_id,
                                        "transaction": tx_data
                                    })
                                else:
                                    expanded_txs.append({
                                        "tx_id": tx_id,
                                        "transaction": None
                                    })

                            block["full_transactions"] = expanded_txs
                            found_block = block
                            break

                if found_block:
                    blocks.append(found_block)

            response = {"type": "blocks_response", "blocks": blocks}
            writer.write((json.dumps(response) + "\n").encode('utf-8'))
            await writer.drain()

  

    async def randomized_broadcast(self, msg_dict):
        peers = self.dht_peers | self.client_peers 
        if not peers:
            return
        num_peers = max(2, int(len(peers) ** 0.5))
        peers_to_send = random.sample(list(peers), min(len(peers), num_peers))
        payload = (json.dumps(msg_dict) + "\n").encode('utf-8')
        results = await asyncio.gather(
            *[self._send_message(p, payload) for p in peers_to_send],
            return_exceptions=True          
        )
        for peer, result in zip(peers_to_send, results):
            if isinstance(result, Exception):
                logging.warning("broadcast → %s failed: %s", peer, result)

    async def _send_message(self, peer, payload):
        for attempt in range(3):
            try:
                r, w = await asyncio.open_connection(peer[0], peer[1], limit=MAX_LINE_BYTES)
                w.write(payload)
                await w.drain()
                w.close()
                await w.wait_closed()
                self.failed_peers[peer] = 0
                return
            except Exception as e:
                self.failed_peers[peer] = self.failed_peers.get(peer, 0) + 1
                await asyncio.sleep(2 ** attempt)
        if peer in self.dht_peers:
            self.dht_peers.remove(peer)
            logging.info(f"Removed failed DHT peer {peer}")

    async def check_partition(self):
        while True:
            alive_peers = sum(1 for peer in self.dht_peers if self.failed_peers.get(peer, 0) < 3)
            if alive_peers < len(self.dht_peers) // 2 and len(self.dht_peers) > 0:
                for peer, fails in list(self.failed_peers.items()):
                    if fails >= 3 and peer in self.dht_peers:
                        try:
                            r, w = await asyncio.open_connection(peer[0], peer[1])
                            w.write(b"PING\n")
                            await w.drain()
                            w.close()
                            await w.wait_closed()
                            self.failed_peers[peer] = 0
                        except Exception:
                            self.dht_peers.remove(peer)
                            logging.info(f"Removed partitioned DHT peer {peer}")
            await asyncio.sleep(60)

    def add_peer(self, ip: str, port: int):
        peer = (ip, port)
        if peer not in self.dht_peers:
            self.dht_peers.add(peer)
            logging.info(f"Added DHT peer {peer} to validator list")
            asyncio.create_task(push_blocks(ip,port))

    def remove_peer(self, ip: str, port: int):
        peer = (ip, port)
        if peer in self.dht_peers:
            self.dht_peers.remove(peer)
            self.failed_peers.pop(peer, None)
            logging.info(f"Removed DHT peer {peer} from validator list")

    async def stop(self):
        if self.server_task:
            self.server_task.cancel()
        if self.partition_task:
            self.partition_task.cancel()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
