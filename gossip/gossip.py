import asyncio
import json
import time
import logging
import random
from decimal import Decimal
from asyncio import StreamReader, StreamWriter
from config.config import DEFAULT_GOSSIP_PORT, VALIDATOR_ID, ROCKSDB_PATH
from state.state import pending_transactions, mined_blocks
from wallet.wallet import verify_transaction
from database.database import get_db, get_current_height
from dht.dht import push_blocks
from rocksdict import WriteBatch
import hashlib

GENESIS_HASH = "0" * 64
# Blockchain state 
TREASURY_ADDRESS = "bqs1GPSETB9KzXeYWHfs2zMGPv5VKhLTPSvhm"
GENESIS_ADDRESS = "bqs1genesis00000000000000000000000000000000"
ADMIN_ADDRESS = "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def calculate_merkle_root(txids: list[str]) -> str:
    if not txids:
        return sha256d(b"").hex()
    
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]  # little-endian

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # duplicate last if odd

        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_hashes.append(sha256d(combined))
        hashes = new_hashes

    return hashes[0][::-1].hex()  # return as hex, big-endian

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
        self.server = await asyncio.start_server(self.handle_client, host, port)
        self.server_task = asyncio.create_task(self.server.serve_forever())
        self.partition_task = asyncio.create_task(self.check_partition())

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        peer_info = writer.get_extra_info('peername')
        if peer_info not in self.client_peers and peer_info not in self.dht_peers:
            self.client_peers.add(peer_info)
            logging.info(f"Added temporary client peer {peer_info}")
        try:
            while True:
                line = await reader.readline()
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


        if timestamp < int(time.time() * 1000) - 60000:  # Ignore messages older than 60 seconds
            print("**** TRANSACTION IS STALE")
            return


        if msg_type == "transaction":
            if tx_id in self.seen_tx or tx_id in pending_transactions:
                return
            if not verify_transaction(msg["body"]["transaction_data"], msg["body"]["signature"], msg["body"]["pubkey"]):
                return
            pending_transactions[tx_id] = msg
            await self.randomized_broadcast(msg)
            self.seen_tx.add(tx_id)

        elif msg_type == "blocks_response":
            print("***** IN GOSSIP MSG RECEIVE BLOCKS RESPONSE")
            blocks = sorted(msg.get("blocks", []), key=lambda x: x["height"])
            logging.info(f"Received {len(blocks)} blocks from {from_peer}")

            db = get_db()

            for block in blocks:
                height = block.get("height")
                print(height)
                block_hash = block.get("block_hash")
                print(block_hash)
                prev_hash = block.get("previous_hash")
                block_key = f"block:{block_hash}".encode()
                if block_key in db:
                    logging.info(f"Block {block_hash} already exists in DB. Skipping.")
                    continue 
                print(prev_hash)
                tx_ids = block.get("tx_ids", [])
                print(tx_ids)
                nonce = block.get("nonce")
                print(nonce)
                timestamp = block.get("timestamp")
                print(timestamp)
                miner_address = block.get("miner_address")
                print(miner_address)
                full_transactions = block.get("full_transactions", [])
                print(full_transactions)
                block_merkle_root = block.get("merkle_root")

                print(f"[SYNC] Processing block height {height} with hash {block_hash}")

                for tx in full_transactions:
                    # 1. Genesis Transaction
                    if tx.get("tx_id") == "genesis_tx":
                        print("[SYNC] Genesis transaction detected.")
                        db.put(b"tx:genesis_tx", json.dumps(tx).encode())
                        continue

                    # 2. Coinbase Transaction (special case)
                    if "version" in tx and "inputs" in tx and "outputs" in tx:
                        print("[SYNC] Coinbase transaction detected.")
                        coinbase_tx_id = "coinbase_" + str(height)
                        print("coinbase_tx_id")
                        print(coinbase_tx_id)
                        db.put(f"tx:{coinbase_tx_id}".encode(), json.dumps(tx).encode())

                        for idx, output in enumerate(tx.get("outputs", [])):
                            output_key = f"utxo:{coinbase_tx_id}:{idx}".encode()
                            print(output_key)
                            utxo = {
                                "txid": coinbase_tx_id,
                                "utxo_index": idx,
                                "sender": "coinbase",
                                "receiver": "unknown",
                                "amount": output.get("value"),
                                "spent": False
                            }
                            print(utxo)
                            db.put(output_key, json.dumps(utxo).encode())
                        continue

                    # 3. Regular Transaction
                    if "txid" in tx:
                        txid = tx["txid"]

                        print("txid is")
                        print(txid)

                        # Perform **inline validation** before accepting
                        inputs = tx.get("inputs", [])
                        print("inputs are")
                        print(inputs)
                        outputs = tx.get("outputs", [])
                        print("outputs are")
                        print(outputs)
                        body = tx.get("body", {})
                        print("body is")
                        print(body)

                        pubkey = body.get("pubkey", "unknown") 
                        signature = body.get("signature","unknown")
                        to_ = None
                        from_ = None

                        if (body.get("transaction_data") == "initial_distribution") and (height == 1):
                            print("im in initial distribution")
                            total_authorized = 21000000
                            to_ = ADMIN_ADDRESS
                            from_ = GENESIS_ADDRESS
                        else:
                            message_str = body["msg_str"]
                            print(message_str)
                            from_ = message_str.split(":")[0]
                            print(from_)
                            to_ = message_str.split(":")[1]  # extract 'to' address from msg
                            print(to_)
                            total_authorized = message_str.split(":")[2]
                            time_ = message_str.split(":")[3]
                            print(time_)

                        total_available = Decimal("0")
                        total_required = Decimal("0")

                        print("im here")

                        # Calculate available balance from inputs
                        for input_ in inputs:
                            input_receiver = input_.get("receiver")
                            input_spent = input_.get("spent", False)
                            input_amount = input_.get("amount", "0")

                            print(f"input receiver {input_receiver}")
                            print(f"to {to_}")
                            print(f"from: {from_}")
                            print(f"input_spent {input_spent}")
                            print(f"input amount {input_amount}")

                            print("im past inputs")

                            if (input_receiver == from_):
                                print("input receiver is from")

                                if (height == 1):
                                    print("coins not spent")
                                    total_available += Decimal(input_amount)
                                    print(f"total available increased by {input_amount}")

                                else:
                                    if (input_spent == False):
                                        print("coins not spent")
                                        total_available += Decimal(input_amount)
                                        print(f"total available increased by {input_amount}")

                        print(f"**** TOTAL AVAILABLE IS {total_available} ")

                        # Calculate required amount from outputs
                        for output_ in outputs:
                            output_receiver = output_.get("receiver")
                            output_amount = output_.get("amount", "0")
                            if output_receiver in (to_, ADMIN_ADDRESS, TREASURY_ADDRESS):
                                total_required += Decimal(output_amount)
                            else:
                                print(f"❌ Hack detected! Unauthorized output to {output_receiver}")
                                raise ValueError("Hack detected, invalid transaction.")

                        print(total_authorized)

                        miner_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(Decimal("0.00000001"))
                        treasury_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(Decimal("0.00000001"))
                        grand_total_required = Decimal(total_authorized) + miner_fee + treasury_fee

                        if (height > 1):
                            if grand_total_required > total_available:
                                print(f"❌ Not enough balance! {total_available} < {grand_total_required}")
                                raise ValueError("Invalid transaction: insufficient balance.")
                        

                        if height == 1 or (verify_transaction(message_str, signature, pubkey) == True):
                            print("✅ Transaction validated successfully.")
                            batch = WriteBatch()

                            # Store the transaction
                            batch.put(f"tx:{txid}".encode(), json.dumps(tx).encode())

                            # Spend each input UTXO
                            for input_ in inputs:
                                if "txid" in input_:
                                    spent_utxo_key = f"utxo:{input_['txid']}:{input_.get('utxo_index', 0)}".encode()
                                    if spent_utxo_key in db:
                                        utxo = json.loads(db.get(spent_utxo_key).decode())
                                        utxo["spent"] = True
                                        batch.put(spent_utxo_key, json.dumps(utxo).encode())
                                    else:
                                        print(f"[SYNC] Warning: input UTXO not found {spent_utxo_key}")

                            # Create UTXOs from outputs
                            for output in outputs:
                                output_key = f"utxo:{txid}:{output.get('utxo_index', 0)}".encode()
                                batch.put(output_key, json.dumps(output).encode())

                            # Atomic commit
                            db.write(batch)
                        else:
                            print("❌ Transaction verification failed.")

                print("tx_ids are")
                print(tx_ids)
                calculated_merkle_root = calculate_merkle_root(tx_ids)

                print(calculated_merkle_root)
                print(block_merkle_root)

                if (calculated_merkle_root == block_merkle_root):
                    # Store the block itself after processing all txs
                    block_data = {
                        "height": height,
                        "block_hash": block_hash,
                        "previous_hash": prev_hash,
                        "tx_ids": tx_ids,
                        "nonce": nonce,
                        "timestamp": timestamp,
                        "miner_address": miner_address,
                        "merkle_root": calculated_merkle_root
                    }
                    db.put(f"block:{block_hash}".encode(), json.dumps(block_data).encode())

                    print(f"[SYNC] Stored block {height} successfully.")

                

                




   

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
        peers = self.dht_peers | self.client_peers  # Use both DHT and client peers for broadcasting
        if not peers:
            return
        num_peers = max(2, int(len(peers) ** 0.5))
        peers_to_send = random.sample(list(peers), min(len(peers), num_peers))
        payload = (json.dumps(msg_dict) + "\n").encode('utf-8')
        await asyncio.gather(*[self._send_message(peer, payload) for peer in peers_to_send])

    async def _send_message(self, peer, payload):
        for attempt in range(3):
            try:
                r, w = await asyncio.open_connection(peer[0], peer[1])
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