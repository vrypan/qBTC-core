import argparse
import asyncio
import threading
# import uvicorn
from p2p.gossip import GossipNode
from grpcservice.server import grpc_serve
# from web import app  # FastAPI app instance
from database.database2 import init_db

def parse_args():
    parser = argparse.ArgumentParser(description="Run a GossipNode.")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host IP address to bind to and advertise")
    parser.add_argument("--port", type=int, required=True, help="UDP port to bind to")
    parser.add_argument("--broadcast", action="store_true", help="Broadcast random blocks")
    parser.add_argument("--bootstrap", type=str, help="Bootstrap node address (format: host:port)")
    return parser.parse_args()

# --- Async Gossip Node ---
async def start_gossip_node(
    host: tuple[str, int],
    bootstrap: tuple[str, int] | None = None,
    full_node: bool = False,
    grpc_port: int = 0,
):
    node = GossipNode(host=host, bootstrap=bootstrap, is_full_node=full_node, grpc_port=grpc_port)
    await node.run()

# --- Blocking gRPC in Thread ---
def start_grpc_server(port: int):
    grpc_serve(port)

# --- Blocking FastAPI in Thread ---
def start_json_api():
    # uvicorn.run(app, host="0.0.0.0", port=8000)
    pass

# --- Async Main Orchestration ---
async def main():
    args = parse_args()
    bootstrap_address: tuple[str, int] | None = None
    if args.bootstrap:
        boot_ip, boot_port = args.bootstrap.split(":")
        bootstrap_address = (boot_ip, int(boot_port))
    # Rdict can not be opened by multiple processes at the same time
    # Create a db path based on port, to simplify testing.
    db_name = f"test_db_{args.port}.db"
    init_db(db_name)

    # Start DHT node as asyncio task
    gossip_task = asyncio.create_task(start_gossip_node(
        host=(args.host, args.port),
        bootstrap=bootstrap_address,
        full_node=args.broadcast,
        grpc_port=args.port+2000,
    ))

    # Start gRPC and API in threads
    grpc_thread = threading.Thread(target=start_grpc_server, args=(args.port+2000,), name="gRPC", daemon=True)
    # api_thread = threading.Thread(target=start_json_api, name="FastAPI", daemon=True)

    grpc_thread.start()
    # api_thread.start()

    # Wait for DHT to run forever (or use asyncio.Event())
    await gossip_task

if __name__ == "__main__":
    asyncio.run(main())
