import asyncio
import json
from kademlia.network import Server

class KademliaNode:
    """
    This is a Kademlia wrapper. It is used by the gossip module
    for peer discovery.
    """
    def __init__(self, host: tuple[str, int], bootstrap: tuple[str, int] | None = None, properties: dict = {}):
        """
        Initialize a KademliaNode instance.
        """
        self._host = host[0]
        self._port = host[1]
        self._bootstrap = bootstrap
        self._server = Server()
        self._properties = properties
        self._peer_key = f"peer:{self._host}:{self._port}"

    async def start(self):
        """
        Starts the Kademlia node.
        """
        await self._server.listen(self._port)
        print(f"[+] DHT node listening on {self._host}:{self._port}")

        if self._bootstrap:
            print(f"[*] DHT bootstrapping to {self._bootstrap}")
            await self._server.bootstrap([self._bootstrap])
            print("[+] DHT bootstrapping complete")

        # Start periodic peer logging
        asyncio.create_task(self.log_peers())
        asyncio.create_task(self.announce_properties())
        asyncio.create_task(self.prune_stale_peers())

        print("[*] DHT node is now running.")
        # await asyncio.Event().wait()

    async def log_peers(self):
        """
        Convinience method to log peers, mostly for debugging.
        """
        while True:
            if self._server.protocol and self._server.protocol.router:
                contacts = self._server.protocol.router.find_neighbors(self._server.node)
                peer_list = [f"{c.id.hex()}@({c.ip}:{c.port})" for c in contacts]
                print(f"[#] DHT known peers ({len(peer_list)}): {peer_list}")
            else:
                print("[-] DHT unable to find neighbors: Router or Protocol not initialized properly.")
            await asyncio.sleep(10)

    def get_peers(self) -> list[tuple[str, int]]:
        """
        Returns a list of known peers in the network.
        """
        if self._server.protocol and self._server.protocol.router:
            contacts = self._server.protocol.router.find_neighbors(self._server.node)
            peer_list = [(c.ip, c.port) for c in contacts]
            return peer_list
        else:
            return []

    async def _ping(self, ip: str, port: int) -> bool:
        try:
            response = await self._server.protocol.ping((ip, port), self._server.node.id)
            if response is None:
                return False
            return True
        except Exception:
            return False
    async def prune_stale_peers(self):
        """
        Periodically pings known peers and removes unreachable ones
        based on (ip, port), regardless of node ID.
        """
        while True:
            if self._server.protocol and self._server.protocol.router:
                for bucket in self._server.protocol.router.buckets:
                    nodes_to_remove = []

                    # Identify dead peers
                    for node_id_bytes, (node_id_int, ip, port) in list(bucket.nodes.items()):
                        alive = await self._ping(ip, port)
                        if not alive:
                            nodes_to_remove.append((ip, port))
                            print(f"[-] DHT: Detected dead peer {ip}:{port}")

                    # Remove all node IDs with the same (ip, port)
                    for ip, port in nodes_to_remove:
                        for node_id_bytes, (_, node_ip, node_port) in list(bucket.nodes.items()):
                            if node_ip == ip and node_port == port:
                                del bucket.nodes[node_id_bytes]
                                print(f"[✓] DHT: Removed {ip}:{port} (node id {node_id_bytes.hex()})")
                for bucket in self._server.protocol.router.buckets:
                    ip_port_to_nodes = {}
                    # Collect all node_ids for each (ip, port)
                    for node_id_bytes, (node_id_int, ip, port) in list(bucket.nodes.items()):
                        ip_port_to_nodes.setdefault((ip, port), []).append(node_id_bytes)

                    # For each duplicate group, remove the first (or all but last)
                    for (ip, port), node_ids in ip_port_to_nodes.items():
                        if len(node_ids) > 1:
                            # Keep only the last entry
                            for node_id_bytes in node_ids:  # remove all
                                del bucket.nodes[node_id_bytes]
                                print(f"[✓] DHT: Removed earlier duplicate at {ip}:{port} (node id {node_id_bytes.hex()})")
            await asyncio.sleep(60)

    async def stop(self):
        """
        Stops the Kademlia node.
        """
        self._server.stop()
        print("[-] DHT node stopped")

    async def set(self, key: str, value: str):
        """
        Sets a key-value pair in the Kademlia DHT.
        """
        await self._server.set(key, value)
        # print(f"[✓] Set key={key} value={value}")

    async def get(self, key: str):
        """
        Retrieves a value from the Kademlia DHT.
        """
        value = await self._server.get(key)
        # print(f"[?] Get key={key} → {value}")
        return value

    async def announce_properties(self):
        """
        Announce other services (gossip_port for example), every 60 seconds.
        This is a workaround for a kademlia DHT limitation, that affects the bootstrap node.
        """
        while True:
            try:
                data = json.dumps(self._properties)
                await self.set(self._peer_key, data)
                print(f"[✓] DHT set key={self._peer_key} to value={data}")
            except Exception as e:
                print(f"[!] DHT set error: {e}")
            await asyncio.sleep(60)

"""
Can be run as a standaline server, for testing purposes.
"""
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Kademlia DHT Node")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--bootstrap", type=str, help="host:port of bootstrap node (optional)")
    args = parser.parse_args()
    bootstrap_addr = None
    if args.bootstrap:
        host, port = args.bootstrap.split(":")
        bootstrap_addr = (host, int(port))

    node = KademliaNode(host=(args.host, args.port), bootstrap=bootstrap_addr)

    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        asyncio.run(node.stop())
