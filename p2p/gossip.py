import asyncio
import socket
import time
import os
import json
import logging

from protobuf.message_pb2 import Block, GossipMessage, GossipMessageType
from .dht import KademliaNode

BUF_SIZE = 65536

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("kademlia").setLevel(logging.WARNING)


class GossipNode:
    def __init__(self, address, bootstrap_addr=None, is_full_node=True):
        self.address = address  # (host, port)
        self.bootstrap_addr = bootstrap_addr
        self.is_full_node = is_full_node
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.known_nonces = set()

        # Use our custom KademliaNode wrapper
        self.dht_node = KademliaNode(
            host=address[0],
            port=address[1] + 1000,
            bootstrap=bootstrap_addr
        )

    def random_block(self) -> Block:
        ''' Create a rendom block, for test purposes
        '''
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
        return block


    async def gossip_block(self, block: Block):
            message = GossipMessage(
                type = GossipMessageType.BLOCK,
                block=block,
            )
            message_bytes = message.SerializeToString()
            registry_raw = await self.dht_get("peer-registry")
            if not registry_raw:
                return
            peer_keys = json.loads(registry_raw)
            for key in peer_keys:
                if key == self.peer_key:
                    continue
                try:
                    value = await self.dht_get(key)
                    if value is None:
                        raise ValueError("Received None value from DHT")
                    info = json.loads(value)
                    ip = key.split(":")[1]
                    port = info["gossip_port"]
                    self.sock.sendto(message_bytes, (ip, port))
                    print(f"[>] {self.address} Gossiped block to {ip}:{port}, nonce={block.nonce}")
                except Exception as e:
                    print(f"[!] Failed to gossip to {key}: {e}")

    async def listen_for_blocks(self):
        loop = asyncio.get_running_loop()
        while True:
            data, addr = await loop.sock_recvfrom(self.sock, BUF_SIZE)
            message = GossipMessage()
            try:
                message.ParseFromString(data)
                if message.type == GossipMessageType.BLOCK:
                    print(f"[<] {self.address} received block from {addr}: nonce={message.block.nonce}")
                    if message.block.nonce not in self.known_nonces:
                        self.known_nonces.add(message.block.nonce)
                        await self.gossip_block(message.block)
            except Exception as e:
                print(f"[!] Failed to parse block from {addr}: {e}")

    async def broadcast_loop(self):
        while True:
            block = self.random_block()
            await self.gossip_block(block)
            await asyncio.sleep(10)

    async def dht_set(self, key, value):
        await self.dht_node.set(key, value)

    async def dht_get(self, key):
        return await self.dht_node.get(key)

    async def run(self):
        self.sock.bind(self.address)
        self.sock.setblocking(False)

        print(f"Listening on {self.address}")

        # Start Kademlia DHT node in background
        asyncio.create_task(self.dht_node.start())
        await asyncio.sleep(2)  # Allow DHT time to bootstrap

        self.peer_key = f"peer:{self.address[0]}:{self.address[1]}"

        try:
            # Register the ip:port for DHT, and the gossip port
            await self.dht_set(self.peer_key, json.dumps({
                "gossip_port": self.address[1]
            }))
            print(f"{self.address} registered in DHT as {self.peer_key}")

            # Update peer registry
            registry_raw = await self.dht_get("peer-registry")
            peer_keys = set(json.loads(registry_raw)) if registry_raw else set()
            peer_keys.add(self.peer_key)
            await self.dht_set("peer-registry", json.dumps(list(peer_keys)))
        except Exception as e:
            print(f"DHT set error: {e}")

        tasks = [
            self.listen_for_blocks(),
            #self.refresh_peers_loop()
        ]
        if self.is_full_node:
            tasks.append(self.broadcast_loop())

        await asyncio.gather(*tasks)
