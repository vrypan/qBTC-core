import asyncio
import socket
import time
import os
import json

from kademlia.network import Server as DHTServer
from protobuf.message_pb2 import Block

import logging

# Set up global logging config
logging.basicConfig(level=logging.INFO)  # or DEBUG if you want everything

# Only increase verbosity for Kademlia
logging.getLogger("kademlia").setLevel(logging.DEBUG)

BUF_SIZE = 65536

class GossipNode:
    def __init__(self, address, bootstrap_addr=None, is_full_node=True):
        self.address = address  # (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.is_full_node = is_full_node
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.known_nonces = set()
        self.peers = []
        self.dht_server = DHTServer()

    def serialize_block(self) -> bytes:
        block = Block(
            version=1,
            previous_hash=b"prevhash",
            block_hash=b"blockhash",
            merkle_root=b"merkle",
            timestamp=int(time.time()),
            bits=0x1d00ffff,
            nonce=int.from_bytes(os.urandom(4), 'big'),
            miner_address=b"miner123",
        )
        tx = block.tx.add()
        tx.txid = b"tx1"
        tx.timestamp = int(time.time())
        tx.body.msg_str = b"hello"
        tx.body.pubkey = b"pub"
        tx.body.signature = b"sig"
        return block.SerializeToString()

    async def gossip_block(self, block_bytes):
        for peer in self.peers:
            await asyncio.sleep(0)
            self.sock.sendto(block_bytes, peer)
            print(f"{self.address} Gossiped block to {peer}")

    async def listen_for_blocks(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, BUF_SIZE)
            block = Block()
            try:
                block.ParseFromString(data)
                print(f"{self.address} received block from {addr}: nonce={block.nonce}")
                if block.nonce not in self.known_nonces:
                    self.known_nonces.add(block.nonce)
                    await self.gossip_block(data)
            except Exception as e:
                print(f"Failed to parse block from {addr}: {e}")

    async def broadcast_loop(self):
        while True:
            block_bytes = self.serialize_block()
            await self.gossip_block(block_bytes)
            await asyncio.sleep(10)

    async def refresh_peers_loop(self):
        while True:
            try:
                self.peers = []
                registry_raw = await self.dht_server.get("peer-registry")
                if registry_raw:
                    print(f"{self.address} raw registry: {registry_raw}")
                    peer_keys = json.loads(registry_raw)
                    for key in peer_keys:
                        if key == self.peer_key:
                            continue
                        value = await self.dht_server.get(key)
                        if value == "alive":
                            _, ip, port = key.split(":")
                            self.peers.append((ip, int(port)))
                print(f"{self.address} updated peer list: {self.peers}")
            except Exception as e:
                print(f"DHT peer discovery error: {e}")
            await asyncio.sleep(10)

    async def run(self):
        self.sock.bind(self.address)
        self.sock.setblocking(False)

        print(f"Listening on {self.address}")
        dht_port = self.address[1] + 1000
        await self.dht_server.listen(dht_port)

        if self.bootstrap_addr:
            await self.dht_server.bootstrap([self.bootstrap_addr])
            await asyncio.sleep(1)

        self.peer_key = f"peer:{self.address[0]}:{self.address[1]}"

        # Register self in DHT
        try:
            await self.dht_server.set(self.peer_key, "alive")
            print(f"{self.address} registered in DHT as {self.peer_key}")

            # Add to global peer-registry
            registry_raw = await self.dht_server.get("peer-registry")
            peer_keys = set(json.loads(registry_raw)) if registry_raw else set()
            peer_keys.add(self.peer_key)
            await self.dht_server.set("peer-registry", json.dumps(list(peer_keys)))
        except Exception as e:
            print(f"DHT set error: {e}")

        tasks = [
            self.listen_for_blocks(),
            self.refresh_peers_loop()
        ]
        if self.is_full_node:
            tasks.append(self.broadcast_loop())

        await asyncio.gather(*tasks)
