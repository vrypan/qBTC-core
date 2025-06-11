import asyncio
from kademlia.network import Server

class KademliaNode:
    """
    This is a Kademlia wrapper. It is used by the gossip module
    for peer discovery.
    """
    def __init__(self, host: str, port: int, bootstrap: tuple[str, int] | None = None):
        """
        Initialize a KademliaNode instance.
        """
        self._host = host
        self._port = port
        self._bootstrap = bootstrap
        self._server = Server()

    async def start(self):
        """
        Starts the Kademlia node.
        """
        await self._server.listen(self._port)
        print(f"[+] Kademlia node listening on {self._host}:{self._port}")

        if self._bootstrap:
            print(f"[*] Bootstrapping to {self._bootstrap}")
            await self._server.bootstrap([self._bootstrap])
            print("[+] Bootstrapping complete")

        # Start periodic peer logging
        asyncio.create_task(self.log_peers())

        print("[*] Node is now running. Press Ctrl+C to exit.")

    async def log_peers(self):
        """
        Convinience method to log peers, mostly for debugging.
        """
        while True:
            if self._server.protocol and self._server.protocol.router:
                contacts = self._server.protocol.router.find_neighbors(self._server.node)
                peer_list = [f"{c.id.hex()}@({c.ip}:{c.port})" for c in contacts]
                print(f"[#] Known peers ({len(peer_list)}): {peer_list}")
            else:
                print("[-] Unable to find neighbors: Router or Protocol not initialized properly.")
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

    async def stop(self):
        """
        Stops the Kademlia node.
        """
        self._server.stop()
        print("[-] Kademlia node stopped")

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

    node = KademliaNode(args.host, args.port, bootstrap_addr)

    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        asyncio.run(node.stop())
