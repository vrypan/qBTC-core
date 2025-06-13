import asyncio
import json
import logging
import time
import aiohttp
from kademlia.network import Server as KademliaServer
from config.config import  shutdown_event, VALIDATOR_ID, HEARTBEAT_INTERVAL, VALIDATOR_TIMEOUT, VALIDATORS_LIST_KEY, DEFAULT_GOSSIP_PORT
from state.state import validator_keys, known_validators
from database.database import get_db,get_current_height
from sync.sync import process_blocks_from_peer

kad_server = None
own_ip = None

def b2s(v: bytes | str | None) -> str | None:
    """Decode bytes from DB/DHT to str; leave str or None unchanged."""
    return v.decode() if isinstance(v, bytes) else v

async def get_external_ip():
    global own_ip
    if own_ip:
        return own_ip
    async with aiohttp.ClientSession() as session:
        async with session.get("https://api.ipify.org") as resp:
            own_ip = await resp.text()
    return own_ip

async def run_kad_server(port, bootstrap_addr=None, wallet=None, gossip_node=None):
    global kad_server
    kad_server = KademliaServer()
    await kad_server.listen(port)
    if bootstrap_addr:
        bootstrap_addr = [addr for addr in bootstrap_addr if addr[1] != port]
        if bootstrap_addr:
            await kad_server.bootstrap(bootstrap_addr)
            logging.info(f"Bootstrapped to {bootstrap_addr}")
    logging.info(f"Validator {VALIDATOR_ID} running DHT on port {port}")
    await register_validator_once()
    if wallet and gossip_node:
        ip_address = await get_external_ip()
        await announce_gossip_port(wallet, ip=ip_address, port=DEFAULT_GOSSIP_PORT, gossip_node=gossip_node)
        #if bootstrap_addr:  # Only discover peers if not bootstrap
        #    await discover_peers_once(gossip_node)
    return kad_server

async def register_validator_once():
    existing_json = b2s(await kad_server.get(VALIDATORS_LIST_KEY))
    existing = set(json.loads(existing_json)) if existing_json else set()
    if VALIDATOR_ID not in existing:
        existing.add(VALIDATOR_ID)
        await kad_server.set(VALIDATORS_LIST_KEY, json.dumps(list(existing)))
        logging.info(f"Validator joined: {VALIDATOR_ID}")
    known_validators.clear()
    known_validators.update(existing)

async def announce_gossip_port(wallet, ip="127.0.0.1", port=DEFAULT_GOSSIP_PORT, gossip_node=None, is_bootstrap=False):
    key = f"gossip_{VALIDATOR_ID}"
    #info = {"ip": ip, "port": port, "publicKey": wallet["publicKey"]}
    info = {"ip": ip, "port": port}
    for _ in range(5):
        await kad_server.set(key, json.dumps(info))
        stored_value = await kad_server.get(key)
        if stored_value and json.loads(stored_value) == info:
            logging.info(f"Announced gossip info: {key} -> {info}")
            if gossip_node and is_bootstrap:
                gossip_node.add_peer(ip, port)
            return
        await asyncio.sleep(2)
    logging.error("Failed to announce gossip port")

async def discover_peers_once(gossip_node):
    validators_json = await kad_server.get(VALIDATORS_LIST_KEY)
    validator_ids = json.loads(validators_json) if validators_json else []
    logging.info(f"Discovered validators: {validator_ids}")
    for vid in validator_ids:
        if vid == VALIDATOR_ID:
            continue
        gossip_key = f"gossip_{vid}"
        gossip_info_json = await kad_server.get(gossip_key)
        if gossip_info_json:
            info = json.loads(gossip_info_json)
            if (info["ip"] == own_ip):
                continue
            peer = (info["ip"], info["port"])
            gossip_node.add_peer(info["ip"], info["port"])
            #validator_keys[vid] = info["publicKey"]
            logging.info(f"Initially connected to peer {vid} at {peer}")
        else:
            logging.warning(f"No gossip info found for validator {vid}")


async def push_blocks(peer_ip, peer_port):
    print("******* IM IN PUSH BLOCKS ******")
    print(peer_ip)
    print(peer_port)
    db = get_db()

    height_request = {
        "type": "get_height",
        "timestamp": int(time.time() * 1000)
    }

    height_temp = get_current_height(db)
    local_height = height_temp[0]
    local_tip = height_temp[1]

    print(f"Local height: {local_height}, Local tip: {local_tip}")

    print("Opening connection...")
    try:
        r, w = await asyncio.open_connection(peer_ip, peer_port)
        print("Opened connection.")

        # Ask peer for its height
        w.write((json.dumps(height_request) + "\n").encode('utf-8'))
        await w.drain()
        line = await r.readline()
        if not line:
            raise ValueError("Empty response when querying height")

        msg = json.loads(line.decode('utf-8').strip())

        if msg.get("type") == "height_response":
            print(msg)
            peer_height = msg.get("height")
            #peer_tip = msg.get("current_tip")
            logging.info(f"*** Peer {peer_ip} responded with height {peer_height}")

        # Only push if our height is greater
        if int(peer_height) < local_height:
            print("***** WILL PUSH BLOCKS TO PEER ****")

            start_height = int(peer_height+1)
            end_height = local_height

            blocks_to_send = []

            for h in range(start_height, end_height+1):
                found_block = None

                print(f"Looking for block at height {h}")

                # Search for the block at height h
                for key in db.keys():
                    if key.startswith(b"block:"):
                        block = json.loads(db[key].decode())
                        if block.get("height") == h:
                            found_block = block
                            break

                if not found_block:
                    print(f"Block at height {h} not found!")
                    continue

                # Now fetch full transaction objects
                full_transactions = []

                for tx_id in found_block.get("tx_ids", []):
                    tx_key = f"tx:{tx_id}".encode()
                    if tx_key in db:
                        tx_obj = json.loads(db[tx_key].decode())
                        full_transactions.append({
                            "tx_id": tx_id,
                            "transaction": tx_obj
                        })

                cbase_key = f"tx:coinbase_{h}".encode()
                if cbase_key in db:
                    full_transactions.append(json.loads(db[cbase_key].decode()))

                found_block["full_transactions"] = full_transactions

                blocks_to_send.append(found_block)

            # Now send the blocks
            blocks_message = {
                "type": "blocks_response",
                "blocks": blocks_to_send,
                "timestamp": int(time.time() * 1000)
            }
            w.write((json.dumps(blocks_message) + "\n").encode('utf-8'))
            await w.drain()
            print(f"Sent {len(blocks_to_send)} blocks to {peer_ip}")
        
        elif peer_height > local_height:
            print("***** WILL PULL BLOCKS FROM PEER *****")
            start_height = local_height + 1
            end_height = peer_height

            get_blocks_request = {
                "type": "get_blocks",
                "start_height": start_height,
                "end_height": end_height,
                "timestamp": int(time.time() * 1000)
            }
            w.write((json.dumps(get_blocks_request) + "\n").encode('utf-8'))
            await w.drain()

            raw = await r.readline()
            if not raw:
                raise ConnectionError("Peer closed the connection")
            try:
                response = json.loads(raw.decode())   # dict now
            except json.JSONDecodeError as e:
                raise ValueError(f"Bad JSON from peer: {e} — payload was {raw!r}")

            blocks = sorted(response.get("blocks", []), key=lambda x: x["height"])
            logging.info(f"Received {len(blocks)} blocks from from peer")
            process_blocks_from_peer(blocks)

        else:
            print("Peer up to date")

        w.close()
        await w.wait_closed()
    except Exception as e:
        print(f"**** Could not connect to peer: {e}")




async def discover_peers_periodically(gossip_node):
    known_peers = set()
    while not shutdown_event.is_set():
        validators_json = await kad_server.get(VALIDATORS_LIST_KEY)
        validator_ids = json.loads(validators_json) if validators_json else []
        for vid in validator_ids:
            if vid == VALIDATOR_ID:
                continue
            gossip_key = f"gossip_{vid}"
            gossip_info_json = await kad_server.get(gossip_key)
            if gossip_info_json:
                info = json.loads(gossip_info_json)
                print("*** in discover peers periodically")
                print(info["ip"])
                print(own_ip)
                if (info["ip"] == own_ip):
                    continue
                peer = (info["ip"], info["port"])
                if peer not in known_peers:
                    gossip_node.add_peer(info["ip"], info["port"])
                    #validator_keys[vid] = info["publicKey"]
                    logging.info(f"Connected to peer {vid} at {peer}")
                    #await push_blocks(info["ip"],info["port"])

                    known_peers.add(peer)
            else:
                logging.warning(f"No gossip info found for validator {vid}")
        await asyncio.sleep(5)

async def update_heartbeat():
    heartbeat_key = f"validator_{VALIDATOR_ID}_heartbeat"
    while not shutdown_event.is_set():
        if kad_server.bootstrappable_neighbors():
            await kad_server.set(heartbeat_key, str(time.time()))
        await asyncio.sleep(HEARTBEAT_INTERVAL)

async def maintain_validator_list(gossip_node):
    while not shutdown_event.is_set():
        try:
            dht_list_json = await kad_server.get(VALIDATORS_LIST_KEY)
            dht_set = set(json.loads(dht_list_json)) if dht_list_json else set()
        except Exception as e:
            logging.error(f"Failed to fetch validator list from DHT: {e}")
            dht_set = set()

        current_time = time.time()
        alive = set()

        # Preload all heartbeats in parallel
        tasks = {v: asyncio.create_task(kad_server.get(f"validator_{v}_heartbeat")) for v in dht_set}
        for v in tasks.items():
            try:
                last_seen_raw = await kad_server.get(f"validator_{v}_heartbeat")
                last_seen_str = b2s(last_seen_raw)
                last_seen = float(last_seen_str) if last_seen_str else None
                if last_seen and (current_time - last_seen) <= VALIDATOR_TIMEOUT:
                    alive.add(v)
            except Exception as e:
                logging.warning(f"Failed to fetch heartbeat for {v}: {e}")

        alive.add(VALIDATOR_ID)

        if alive != dht_set:
            try:
                await kad_server.set(VALIDATORS_LIST_KEY, json.dumps(list(alive)))
            except Exception as e:
                logging.error(f"Failed to update validator list in DHT: {e}")

        # Process newly joined validators
        newly_joined = alive - known_validators
        for v in newly_joined:
            if v == VALIDATOR_ID:
                continue
            try:
                gossip_info_json = await kad_server.get(f"gossip_{v}")
                if gossip_info_json:
                    info = json.loads(gossip_info_json)
                    if info["ip"] != own_ip:
                        gossip_node.add_peer(info["ip"], info["port"])
                        #await push_blocks(info["ip"], info["port"])
                        validator_keys[v] = info["publicKey"]
                        logging.info(f"New validator joined: {v} at {info['ip']}:{info['port']}")
            except Exception as e:
                logging.warning(f"Failed to process new validator {v}: {e}")

        # Process validators that have left
        just_left = known_validators - alive
        for v in just_left:
            try:
                gossip_info_json = await kad_server.get(f"gossip_{v}")
                if gossip_info_json:
                    info = json.loads(gossip_info_json)
                    gossip_node.remove_peer(info["ip"], info["port"])
                validator_keys.pop(v, None)
                logging.info(f"Validator left: {v}")
            except Exception as e:
                logging.warning(f"Failed to remove validator {v}: {e}")

        # Update known validators
        known_validators.clear()
        known_validators.update(alive)

        await asyncio.sleep(HEARTBEAT_INTERVAL)