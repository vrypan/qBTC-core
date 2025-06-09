import asyncio
import json
import time
import logging
import random
from decimal import Decimal, ROUND_DOWN
from asyncio import StreamReader, StreamWriter
from config.config import DEFAULT_GOSSIP_PORT, VALIDATOR_ID, ROCKSDB_PATH, ADMIN_ADDRESS,GENESIS_ADDRESS
from state.state import pending_transactions, mined_blocks
from wallet.wallet import verify_transaction
from database.database import get_db, get_current_height
from blockchain.blockchain import Block ,sha256d, calculate_merkle_root, validate_pow
from dht.dht import push_blocks
from rocksdict import WriteBatch
from sync.sync import process_blocks_from_peer
import hashlib

GENESIS_HASH = "0" * 64
MAX_LINE_BYTES = 30 * 1024 * 1024  




class GossipNode:
    def __init__(self, node_id, wallet=None, is_bootstrap=False, is_full_node=True):
        self.node_id = node_id
        self.wallet = wallet
        self.seen_tx = set()
        self.dht_peers = set()  
        self.client_peers = set()  
        self.failed_peers = {}
        self.server_task = None
        self.server = None
        self.partition_task = None
        self.is_bootstrap = is_bootstrap
        self.is_full_node = is_full_node
        self.synced_peers = set()
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
            process_blocks_from_peer(msg["blocks"])
   

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
                                    expanded_txs.append({
                                        "tx_id": tx_id,
                                        "transaction": json.loads(db[tx_key].decode())
                                    })
                                    #expanded_txs.append({
                                    #    "tx_id": tx_id,
                                    #    "transaction": tx_data
                                    #})
                                else:
                                    continue
                                    #expanded_txs.append({
                                    #    "tx_id": tx_id,
                                    #    "transaction": None
                                    #})

                            cb_key = f"tx:coinbase_{h}".encode()
                            if cb_key in db:
                                expanded_txs.append(json.loads(db[cb_key].decode()))

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
                logging.warning("broadcast  %s failed: %s", peer, result)

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
            if peer not in self.synced_peers:
                self.synced_peers.add(peer)
                asyncio.create_task(push_blocks(ip, port))

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
