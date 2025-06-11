"""
GossipNode:
- Initialized using (ip, port)
- Uses a Kademlia DHT to discover peers. DHT uses port+1000
- Broadcasts and receives messages from the network over udp (port)
- Messages are encoded as protobuf GossipMessage. (See /protobufs/)
- Messages can contain new blocks (blockchain), or transactions (mempool)

`broadcast_loop()` currently broadcasts a random transaction every 10 seconds.
"""
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


class GossipNode:
    def __init__(self, address, bootstrap_addr=None, is_full_node=True):
        """
        Initialize a GossipNode instance.

        `is_full_node` is currently used to start a dummy simullation, where
        `broadcast_loop()` sends random transactions to the network.

        :param address: tuple (host, port), the address of the node.
        :param bootstrap_addr: tuple (host, port), optional. The address of the bootstrap node. Default is None.
        :param is_full_node: bool, optional. Whether the node is a full node. Default is True.
        """
        self._address = address  # (host, port)
        self._bootstrap_addr = bootstrap_addr
        self._is_full_node = is_full_node
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Use our custom KademliaNode wrapper
        self._dht_node = KademliaNode(
            host=address[0],
            port=address[1] + 1000,
            bootstrap=bootstrap_addr
        )

    async def republish_loop(self):
        """
        Republish the gossip port on DHT, every 60 seconds.
        This is a workaround for a kademlia DHT limitation, that affects the bootstrap node.
        """
        while True:
            peer_key = f"peer:{self._address[0]}:{self._address[1]+1000}"
            try:
                # Register the ip:port for DHT, and the gossip port
                data = json.dumps({
                    "gossip_port": self._address[1]
                })
                await self._dht_node.set(peer_key, data)
                print(f"[✓] Set key={peer_key} value={data}")
            except Exception as e:
                print(f"DHT set error: {e}")
            await asyncio.sleep(60)

    async def gossip_block(self, block: Block):
        """
        Gossip a block to all peers in the DHT.
        """
        message = GossipMessage(
            type = GossipMessageType.BLOCK,
            block=block,
        )
        message_bytes = message.SerializeToString()
        peers = self._dht_node.get_peers()
        for peer in peers:
            node_data = await self._dht_node.get(f"peer:{peer[0]}:{peer[1]}")
            if not node_data:
                print(f"[!] Failed to get gossip port for {peer}")
                continue
            try:
                node_json = json.loads(node_data)
                port = node_json["gossip_port"]
                self._sock.sendto(message_bytes, (peer[0], port))
                print(f"[>] {self._address} Gossiped block to {peer[0]}:{port}, hash={block.hash.hex()}")
            except Exception as e:
                print(f"[!] Failed to gossip to {peer}: {e}")

    async def gossip_transaction(self, transaction: Transaction, exclude_peers=()):
        """
        Gossip a transaction to all peers in the network.
        """
        message = GossipMessage(
            type = GossipMessageType.TRANSACTION,
            transaction=transaction,
        )
        message_bytes = message.SerializeToString()
        peers = self._dht_node.get_peers()
        for peer in peers:
            node_data = await self._dht_node.get(f"peer:{peer[0]}:{peer[1]}")
            if not node_data:
                print(f"[!] Failed to get gossip port for {peer}")
                continue
            try:
                node_json = json.loads(node_data)
                port = node_json["gossip_port"]
                if f"{peer[0]}:{port}" in exclude_peers:
                    continue
                self._sock.sendto(message_bytes, (peer[0], port))
                tx_hash = calculate_tx_hash(transaction)
                print(f"[<] Gossiped transaction to {peer[0]}:{port}, hash={tx_hash.hex()}")
            except Exception as e:
                print(f"[!] Failed to gossip to {peer}: {e}")

    async def listen_for_messages(self):
        """
        Listen for incoming messages on the gossip socket.
        """
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self._sock, BUF_SIZE)
            message = GossipMessage()
            try:
                message.ParseFromString(data)
                if message.type == GossipMessageType.BLOCK:
                    print(f"[>] {self._address} received block from {addr}: hash={message.block.hash.hex()}")
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
        """
        Broadcast transactions and blocks to peers.
        Currently a simulation with random transactions.
        """
        while True:
            # block = random_block(height=10)
            transaction = random_transaction()
            asyncio.create_task(self.gossip_transaction(transaction))
            await asyncio.sleep(10)

    async def run(self):
        """
        Run the Gossip node.
        """
        self._sock.bind(self._address)
        self._sock.setblocking(False)
        print(f"Listening on {self._address}")

        await self._dht_node.start()
        asyncio.create_task(self.republish_loop())
        asyncio.create_task(self.listen_for_messages())
        if self._is_full_node:
            asyncio.create_task(self.broadcast_loop())
        while True:
            await asyncio.sleep(3600)
