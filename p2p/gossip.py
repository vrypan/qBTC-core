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
import random

from protobuf.blockchain_pb2 import Block, Transaction
from protobuf.gossip_pb2 import GossipMessage, GossipMessageType, GossipStatusData, GossipTransactionData
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
    def __init__(self,
        host: tuple[str, int],
        bootstrap: tuple[str, int] | None = None,
        is_full_node: bool = True,
        grpc_port: int = 0
    ):
        """
        Initialize a GossipNode instance.

        `is_full_node` is currently used to start a dummy simullation, where
        `broadcast_loop()` sends random transactions to the network.

        :param address: tuple (host, port), the address of the node.
        :param bootstrap_addr: tuple (host, port), optional. The address of the bootstrap node. Default is None.
        :param is_full_node: bool, optional. Whether the node is a full node. Default is True.
        """
        self._address = host
        self._bootstrap = bootstrap
        self._is_full_node = is_full_node
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Use our custom KademliaNode wrapper
        self._dht_node = KademliaNode(
            host=(self._address[0],self._address[1] + 1000),
            bootstrap=bootstrap,
            properties={"gossip_port": self._address[1], "grpc_port":grpc_port}
        )

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

    async def gossip_message(self, message: GossipMessage, exclude_peers=()):
        """
        Gossip a messages to peers in the network.
        """
        MAX_PEERS = 3
        message_bytes = message.SerializeToString()
        peers = self._dht_node.get_peers()
        if len(peers) > MAX_PEERS:
            peers = random.sample(peers, MAX_PEERS)
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
                message_type_str = GossipMessageType.Name(message.type)
                print(f"[<] {message_type_str} to {peer[0]}:{port}")
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
                message_type_str = GossipMessageType.Name(message.type)
                if message.type == GossipMessageType.STATUS:
                    print(f"[>] {message_type_str} from {addr}: mempool_size={message.status_data.mempool_size}, tip={message.status_data.tip_hash.hex()}")
                    # Add logic here to handle status message
                if message.type == GossipMessageType.BLOCK:
                    print(f"[>] {self._address} Block from {addr}: hash={message.block.hash.hex()}")
                    if db.block_exists(message.block.hash):
                        print(f"[#] {message_type_str} {message.block.hash.hex()} already exists")
                    else:
                        db.block_set(message.block)
                if message.type == GossipMessageType.TRANSACTION:
                    tx_hash = calculate_tx_hash(message.transaction_data.transaction)
                    print(f"[>] {message_type_str} from {addr[0]}:{addr[1]}: hash={tx_hash.hex()}")
                    if mempool.hash_exists(tx_hash):
                        print(f"[#] Transaction {tx_hash.hex()} already in mempool")
                    else:
                        mempool.add(message.transaction_data.transaction)
                        print(f"[✓] Added transaction {tx_hash.hex()} to mempool")
                        # Propagate the transaction to other peers
                        asyncio.create_task(self.gossip_message(message, exclude_peers=(f"{addr[0]}:{addr[1]}",)))
            except Exception as e:
                print(f"[!] Failed to parse message from {addr}: {e}")

    async def broadcast_loop(self):
        """
        Broadcast transactions and blocks to peers.
        Currently a simulation with random transactions.
        """
        while True:
            # block = random_block(height=10)
            transaction = random_transaction()
            message = GossipMessage(
                type=GossipMessageType.TRANSACTION,
                transaction_data=GossipTransactionData(
                    transaction=transaction
                )
            )
            asyncio.create_task(self.gossip_message(message))
            await asyncio.sleep(10)

    async def broadcast_status(self):
        """
        Broadcast node status to peers.
        """
        INTERVAL_SECONDS = 60
        while True:
            status = GossipStatusData()
            status.mempool_size = mempool.len()
            status.tip_hash = db.tip_get().hash
            message = GossipMessage(
                type = GossipMessageType.STATUS,
                status_data=status,
            )
            asyncio.create_task(self.gossip_message(message))
            await asyncio.sleep(INTERVAL_SECONDS)
    async def run(self):
        """
        Run the Gossip node.
        """
        self._sock.bind(self._address)
        self._sock.setblocking(False)
        print(f"Listening on {self._address}")

        await self._dht_node.start()
        asyncio.create_task(self._dht_node.announce_properties())
        asyncio.create_task(self.listen_for_messages())
        asyncio.create_task(self.broadcast_status())
        if self._is_full_node:
            asyncio.create_task(self.broadcast_loop())
        while True:
            await asyncio.sleep(3600)
