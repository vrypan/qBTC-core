import asyncio
import logging
from node.cli import args
from node.wallet_setup import load_wallet, setup_validator_wallet
from node.database_setup import setup_database
from node.genesis import create_genesis_block
from dht.dht import run_kad_server, announce_gossip_port, get_external_ip, update_heartbeat, discover_peers_periodically
from gossip.gossip import GossipNode
from config.config import BOOTSTRAP_NODES, VALIDATOR_ID
from state.state import ledger, blockchain
from database.database import get_db
from web.web import app
from rpc.rpc import rpc_app
import uvicorn

gossip_client = None
tasks = []
db = None
validator_wallet = None

async def startup():
    global gossip_client, tasks, db, validator_wallet

    bootstrap = [(args.Bootstrap_ip, args.Bootstrap_port)] if args.Bootstrap_ip else BOOTSTRAP_NODES
    is_bootstrap = args.validator_port == 8001 and not args.Bootstrap_ip
    ip_address = "127.0.0.1" if args.local else await get_external_ip()

    validator_wallet = setup_validator_wallet(args.wallet)
    admin_address = validator_wallet["address"]

    db = setup_database()
    await create_genesis_block(db, is_bootstrap, admin_address)

    gossip_client = GossipNode(VALIDATOR_ID, wallet=validator_wallet, is_bootstrap=is_bootstrap)
    await run_kad_server(args.validator_port, bootstrap, wallet=validator_wallet, gossip_node=gossip_client)
    await gossip_client.start_server(port=args.gossip_port)

    await announce_gossip_port(wallet=validator_wallet, ip=ip_address, port=args.gossip_port)

    # Background tasks
    tasks = [
        asyncio.create_task(update_heartbeat()),
        asyncio.create_task(discover_peers_periodically(gossip_client))
    ]

async def shutdown():
    global gossip_client, tasks
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if gossip_client:
        await gossip_client.stop()
    logging.info("Shutdown complete.")
