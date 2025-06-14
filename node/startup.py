import asyncio
import logging
import os
import socket
from node.cli import args
from node.wallet_setup import setup_validator_wallet
from node.database_setup import setup_database
from node.genesis import create_genesis_block
from dht.dht import run_kad_server, announce_gossip_port, update_heartbeat, discover_peers_periodically
from gossip.gossip import GossipNode
from config.config import BOOTSTRAP_NODES, VALIDATOR_ID
from web.web import app
from rpc.rpc import rpc_app

# Import NAT traversal
try:
    from network.nat_traversal import nat_traversal
except ImportError:
    nat_traversal = None

gossip_client = None
tasks = []
db = None
validator_wallet = None

def is_running_in_docker():
    """Detect if we're running inside a Docker container"""
    if os.path.exists('/.dockerenv'):
        return True
    try:
        if os.path.exists('/proc/self/cgroup'):
            with open('/proc/self/cgroup', 'r') as f:
                return 'docker' in f.read()
    except:
        pass
    return False

def get_container_ip():
    """Get the container's IP address within Docker network"""
    try:
        # Try to get the container's internal IP
        hostname = socket.gethostname()
        container_ip = socket.gethostbyname(hostname)
        logging.info(f"Container hostname: {hostname}, IP: {container_ip}")
        return container_ip
    except Exception as e:
        logging.warning(f"Failed to get container IP: {e}, using 127.0.0.1")
        return "127.0.0.1"

async def get_appropriate_ip():
    """Get appropriate IP address based on environment"""
    if args.local:
        logging.info("Using local IP: 127.0.0.1")
        return "127.0.0.1"
    elif is_running_in_docker():
        # In Docker, use container IP for internal networking
        container_ip = get_container_ip()
        logging.info(f"Detected Docker environment, using container IP: {container_ip}")
        return container_ip
    else:
        # Outside Docker, get external IP
        # Import here to avoid circular imports
        from dht.dht import get_external_ip
        external_ip = await get_external_ip()
        logging.info(f"Using external IP: {external_ip}")
        return external_ip

async def startup():
    global gossip_client, tasks, db, validator_wallet

    bootstrap = [(args.Bootstrap_ip, args.Bootstrap_port)] if args.Bootstrap_ip else BOOTSTRAP_NODES
    is_bootstrap = args.validator_port == 8001 and not args.Bootstrap_ip
    ip_address = await get_appropriate_ip()

    validator_wallet = setup_validator_wallet(args.wallet)
    admin_address = validator_wallet["address"]

    db = setup_database()
    await create_genesis_block(db, is_bootstrap, admin_address)

    # Setup NAT traversal only if:
    # 1. NAT traversal is available
    # 2. Not running in Docker (Docker handles networking)
    # 3. Not in local mode
    # 4. Not a bootstrap node in test environment
    # 5. Not explicitly disabled via environment variable
    nat_disabled = os.environ.get('DISABLE_NAT_TRAVERSAL', '').lower() in ('true', '1', 'yes')
    
    should_setup_nat = (
        nat_traversal and 
        not nat_disabled and
        not is_running_in_docker() and 
        not args.local and
        not (is_bootstrap and len(bootstrap) == 0)  # Bootstrap with no peers = test network
    )
    
    if should_setup_nat:
        logging.info("Setting up NAT traversal...")
        nat_results = await nat_traversal.setup_all_ports(
            dht_port=args.validator_port,
            gossip_port=args.gossip_port
        )
        if nat_results['dht'] or nat_results['gossip']:
            logging.info(f"NAT traversal results: {nat_results}")
            # Update IP if we got external IP
            if nat_traversal.external_ip:
                logging.info(f"Using external IP from UPnP: {nat_traversal.external_ip}")
                ip_address = nat_traversal.external_ip
    else:
        if is_running_in_docker():
            logging.info("Running in Docker - using container networking")
        elif args.local:
            logging.info("Local mode - skipping NAT traversal")
        else:
            logging.info("Test network mode - using private network")
    
    gossip_client = GossipNode(VALIDATOR_ID, wallet=validator_wallet, is_bootstrap=is_bootstrap)
    await run_kad_server(args.validator_port, bootstrap, wallet=validator_wallet, gossip_node=gossip_client, ip_address=ip_address, gossip_port=args.gossip_port)
    await gossip_client.start_server(port=args.gossip_port)

    await announce_gossip_port(wallet=validator_wallet, ip=ip_address, port=args.gossip_port)

    # Save gossip_client into FastAPI apps
    app.state.gossip_client = gossip_client
    rpc_app.state.gossip_client = gossip_client

    # Background tasks
    tasks = [
        asyncio.create_task(update_heartbeat()),
        asyncio.create_task(discover_peers_periodically(gossip_client, ip_address))
    ]

async def shutdown():
    global gossip_client, tasks
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if gossip_client:
        await gossip_client.stop()
    
    # Cleanup NAT mappings
    if nat_traversal:
        await nat_traversal.cleanup_upnp()
        
    logging.info("Shutdown complete.")
