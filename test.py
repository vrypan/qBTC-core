import argparse
import asyncio
from p2p.gossip import GossipNode

def parse_args():
    parser = argparse.ArgumentParser(description="Run a GossipNode.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host IP address to bind to and advertise")
    parser.add_argument("--port", type=int, required=True, help="UDP port to bind to")
    parser.add_argument("--broadcast", action="store_true", help="Broadcast random blocks")
    parser.add_argument("--bootstrap", type=str, help="Bootstrap node address (format: host:port)")
    return parser.parse_args()

async def main():
    args = parse_args()
    bootstrap_address = None
    if args.bootstrap:
        host, port = args.bootstrap.split(":")
        bootstrap_address = (host, int(port))
    node = GossipNode(
        address=(args.host, args.port),
        is_full_node=args.broadcast,
        bootstrap_addr=bootstrap_address
    )
    await node.run()

if __name__ == "__main__":
    asyncio.run(main())
