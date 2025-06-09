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


"""
Example:

This will start a node. It is the first node, and will be used to bootstrap the network.
DHT is listening started on port 9000+1000
python test.py --host 127.0.0.1 --port 9000

Start a second node. Bootstrap if from the previous one
python test.py --host 127.0.0.1 --port 9001 --bootstrap 127.0.0.1:10000

Start a third node.
python test.py --host 127.0.0.1 --port 9002 --bootstrap 127.0.0.1:10000

Start a fourth node. Use --broadcast to broadcast random blocks to the network.
python test.py --host 127.0.0.1 --port 9003 --bootstrap 127.0.0.1:10000 --broadcast

"""
