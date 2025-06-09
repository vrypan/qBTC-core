import asyncio
from kademlia.network import Server

class KademliaNode:
    def __init__(self, host: str, port: int, bootstrap: tuple[str, int] | None = None):
        self.host = host
        self.port = port
        self.bootstrap = bootstrap
        self.server = Server()

    async def start(self):
        await self.server.listen(self.port)
        print(f"[+] Kademlia node listening on {self.host}:{self.port}")

        if self.bootstrap:
            print(f"[*] Bootstrapping to {self.bootstrap}")
            await self.server.bootstrap([self.bootstrap])
            print("[+] Bootstrapping complete")

        # Start periodic peer logging
        asyncio.create_task(self.log_peers())

        print("[*] Node is now running. Press Ctrl+C to exit.")
        await asyncio.Event().wait()

    async def log_peers(self):
        while True:
            if self.server.protocol and self.server.protocol.router:
                contacts = self.server.protocol.router.find_neighbors(self.server.node)
                peer_list = [f"{c.id.hex()}@({c.ip}:{c.port})" for c in contacts]
                print(f"[#] Known peers ({len(peer_list)}): {peer_list}")
            else:
                print("[-] Unable to find neighbors: Router or Protocol not initialized properly.")
            await asyncio.sleep(10)

    async def stop(self):
        self.server.stop()
        print("[-] Kademlia node stopped")

    async def set(self, key: str, value: str):
        await self.server.set(key, value)
        print(f"[✓] Set key={key} value={value}")

    async def get(self, key: str):
        value = await self.server.get(key)
        print(f"[?] Get key={key} → {value}")
        return value

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
