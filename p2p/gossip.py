import asyncio
import socket
import json
import logging

from protobuf.blockchain_pb2 import Block, Transaction
from protobuf.gossip_pb2 import GossipMessage, GossipMessageType
from .dht import KademliaNode
from blockchain.mempool import mempool
from blockchain.utils import calculate_tx_hash
from database import database2 as db
from .utils import random_transaction
BUF_SIZE = 65536

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("kademlia").setLevel(logging.WARNING)

"""
The gossip node uses a Kademlia DHT to discover peers.

It broadcasts and receives messages from the network. Messages are
encoded as protobuf GossipMessage. (See /protobufs/)

"""
class GossipNode:
    def __init__(self, address, bootstrap_addr=None, is_full_node=True):
        self.address = address  # (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.is_full_node = is_full_node
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Use our custom KademliaNode wrapper
        self.dht_node = KademliaNode(
            host=address[0],
            port=address[1] + 1000,
            bootstrap=bootstrap_addr
        )

    async def republish_loop(self):
        # Republish the gossip port on DHT, every 60 seconds.
        # This is a workaround for a kademlia DHT limitation, that affects the bootstrap node.
        while True:
            peer_key = f"peer:{self.address[0]}:{self.address[1]+1000}"
            try:
                # Register the ip:port for DHT, and the gossip port
                data = json.dumps({
                    "gossip_port": self.address[1]
                })
                await self.dht_set(peer_key, data)
                print(f"[✓] Set key={peer_key} value={data}")
            except Exception as e:
                print(f"DHT set error: {e}")
            await asyncio.sleep(60)

    async def gossip_block(self, block: Block):
            message = GossipMessage(
                type = GossipMessageType.BLOCK,
                block=block,
            )
            message_bytes = message.SerializeToString()
            peers = self.dht_node.get_peers()
            for peer in peers:
                node_data = await self.dht_get(f"peer:{peer[0]}:{peer[1]}")
                if not node_data:
                    print(f"[!] Failed to get gossip port for {peer}")
                    continue
                try:
                    node_json = json.loads(node_data)
                    port = node_json["gossip_port"]
                    self.sock.sendto(message_bytes, (peer[0], port))
                    print(f"[>] {self.address} Gossiped block to {peer[0]}:{port}, hash={block.hash.hex()}")
                except Exception as e:
                    print(f"[!] Failed to gossip to {peer}: {e}")

    async def gossip_transaction(self, transaction: Transaction, exclude_peers=()):
            message = GossipMessage(
                type = GossipMessageType.TRANSACTION,
                transaction=transaction,
            )
            message_bytes = message.SerializeToString()
            peers = self.dht_node.get_peers()
            for peer in peers:
                node_data = await self.dht_get(f"peer:{peer[0]}:{peer[1]}")
                if not node_data:
                    print(f"[!] Failed to get gossip port for {peer}")
                    continue
                try:
                    node_json = json.loads(node_data)
                    port = node_json["gossip_port"]
                    if f"{peer[0]}:{port}" in exclude_peers:
                        continue
                    self.sock.sendto(message_bytes, (peer[0], port))
                    tx_hash = calculate_tx_hash(transaction)
                    print(f"[<] Gossiped transaction to {peer[0]}:{port}, hash={tx_hash.hex()}")
                except Exception as e:
                    print(f"[!] Failed to gossip to {peer}: {e}")

    async def listen_for_messages(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, BUF_SIZE)
            message = GossipMessage()
            try:
                message.ParseFromString(data)
                if message.type == GossipMessageType.BLOCK:
                    print(f"[>] {self.address} received block from {addr}: hash={message.block.hash.hex()}")
                    if db.block_exists(message.block.hash):
                        print(f"[!] Block {message.block.hash.hex()} already exists")
                    else:
                        db.block_set(message.block)
                if message.type == GossipMessageType.TRANSACTION:
                    tx_hash = calculate_tx_hash(message.transaction)
                    print(f"[>] Received transaction from {addr[0]}:{addr[1]}: hash={tx_hash.hex()}")
                    if mempool.hash_exists(tx_hash):
                        print(f"[!] Transaction {tx_hash.hex()} already in mempool")
                    else:
                        mempool.add(message.transaction)
                        print(f"[✓] Added transaction {tx_hash.hex()} to mempool")
                        asyncio.create_task(self.gossip_transaction(message.transaction, exclude_peers=(f"{addr[0]}:{addr[1]}",)))
            except Exception as e:
                print(f"[!] Failed to parse block from {addr}: {e}")

    async def broadcast_loop(self):
        while True:
            # block = random_block(height=10)
            transaction = random_transaction()
            asyncio.create_task(self.gossip_transaction(transaction))
            await asyncio.sleep(10)

    async def dht_set(self, key, value):
        await self.dht_node.set(key, value)

    async def dht_get(self, key):
        return await self.dht_node.get(key)

    async def run(self):
        self.sock.bind(self.address)
        self.sock.setblocking(False)
        print(f"Listening on {self.address}")

        await self.dht_node.start()
        asyncio.create_task(self.republish_loop())
        asyncio.create_task(self.listen_for_messages())
        if self.is_full_node:
            asyncio.create_task(self.broadcast_loop())
        while True:
            await asyncio.sleep(3600)
