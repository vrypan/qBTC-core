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

# Import NAT traversal
try:
    from network.nat_traversal import nat_traversal, SimpleSTUN
    NAT_TRAVERSAL_AVAILABLE = True
except ImportError:
    nat_traversal = None
    SimpleSTUN = None
    NAT_TRAVERSAL_AVAILABLE = False

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

async def run_kad_server(port, bootstrap_addr=None, wallet=None, gossip_node=None, ip_address=None, gossip_port=None):
    global kad_server
    kad_server = KademliaServer()
    await kad_server.listen(port)
    
    if bootstrap_addr:
        # Resolve hostnames to IPs if needed
        resolved_bootstrap = []
        for addr in bootstrap_addr:
            if isinstance(addr[0], str) and not addr[0].replace('.', '').isdigit():
                # It's a hostname, resolve it
                try:
                    import socket
                    ip = socket.gethostbyname(addr[0])
                    resolved_bootstrap.append((ip, addr[1]))
                    logging.info(f"Resolved {addr[0]} to {ip}")
                except Exception as e:
                    logging.error(f"Failed to resolve {addr[0]}: {e}")
                    # In Docker, try using the hostname directly
                    resolved_bootstrap.append(addr)
            else:
                resolved_bootstrap.append(addr)
        
        # Filter out our own address from bootstrap list
        bootstrap_addr = [addr for addr in resolved_bootstrap if addr[1] != port]
        if bootstrap_addr:
            await kad_server.bootstrap(bootstrap_addr)
            logging.info(f"Bootstrapped to {bootstrap_addr}")
            
            # Verify bootstrap success
            await asyncio.sleep(2)
            neighbors = kad_server.bootstrappable_neighbors()
            if not neighbors:
                logging.warning("Bootstrap may have failed - no neighbors found")
            else:
                logging.info(f"Bootstrap successful - {len(neighbors)} neighbors found")
    
    logging.info(f"Validator {VALIDATOR_ID} running DHT on port {port}")
    
    # Wait a bit more before registering to ensure DHT is ready
    await asyncio.sleep(2)
    await register_validator_once()
    
    if wallet and gossip_node and ip_address:
        # Use the provided IP address and gossip port instead of defaults
        actual_gossip_port = gossip_port if gossip_port else DEFAULT_GOSSIP_PORT
        await announce_gossip_port(wallet, ip=ip_address, port=actual_gossip_port, gossip_node=gossip_node)
        #if bootstrap_addr:  # Only discover peers if not bootstrap
        #    await discover_peers_once(gossip_node)
    return kad_server

async def register_validator_once():
    max_retries = 5
    for attempt in range(max_retries):
        try:
            existing_json = b2s(await kad_server.get(VALIDATORS_LIST_KEY))
            existing = set(json.loads(existing_json)) if existing_json else set()
            
            if VALIDATOR_ID not in existing:
                existing.add(VALIDATOR_ID)
                await kad_server.set(VALIDATORS_LIST_KEY, json.dumps(list(existing)))
                logging.info(f"Validator joined: {VALIDATOR_ID}")
            else:
                logging.info(f"Validator {VALIDATOR_ID} already registered")
            
            known_validators.clear()
            known_validators.update(existing)
            return  # Success
            
        except Exception as e:
            logging.error(f"Registration attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            else:
                logging.error(f"Failed to register validator after {max_retries} attempts")

async def announce_gossip_port(wallet, ip="127.0.0.1", port=None, gossip_node=None, is_bootstrap=False):
    if not kad_server:
        logging.error("Cannot announce gossip port: kad_server not initialized")
        return
    
    if port is None:
        port = DEFAULT_GOSSIP_PORT
    
    # Determine if we should use NAT traversal
    external_ip = ip
    external_port = port
    nat_type = "direct"
    
    # Check if we're in a Docker/private network environment
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        is_private = ip_obj.is_private
    except:
        is_private = False
    
    # Only try NAT traversal if:
    # - NAT traversal is available
    # - We're not using a private IP (Docker/local network)
    # - We're not explicitly in bootstrap mode with private IP
    if NAT_TRAVERSAL_AVAILABLE and nat_traversal and not is_private:
        # Try UPnP mapping
        upnp_port = await nat_traversal.setup_upnp(port, 'TCP')
        if upnp_port and nat_traversal.external_ip:
            external_ip = nat_traversal.external_ip
            external_port = upnp_port
            nat_type = "upnp"
            logging.info(f"UPnP mapping successful: {ip}:{port} -> {external_ip}:{external_port}")
        elif SimpleSTUN:
            # Try STUN as fallback
            stun_result = await SimpleSTUN.get_external_address(port)
            if stun_result:
                external_ip, external_port = stun_result
                nat_type = "stun"
                logging.info(f"STUN discovery successful: {external_ip}:{external_port}")
    elif is_private:
        logging.info(f"Using private network address {ip}:{port} - NAT traversal not needed")
    
    key = f"gossip_{VALIDATOR_ID}"
    # Enhanced info with NAT details
    info = {
        "ip": external_ip,
        "port": external_port,
        "local_ip": ip,
        "local_port": port,
        "nat_type": nat_type,
        "supports_nat_traversal": NAT_TRAVERSAL_AVAILABLE,
        "publicKey": wallet.get("publicKey", "")  # Include publicKey for validator_keys
    }
    
    for attempt in range(5):
        try:
            logging.info(f"Attempting to announce gossip port (attempt {attempt+1}/5): {key} -> {info}")
            await kad_server.set(key, json.dumps(info))
            stored_value = await kad_server.get(key)
            if stored_value:
                stored_info = json.loads(stored_value)
                # Check if essential fields match
                if stored_info.get("ip") == info["ip"] and stored_info.get("port") == info["port"]:
                    logging.info(f"Successfully announced gossip info with NAT type '{nat_type}': {key} -> {info}")
                    if gossip_node and is_bootstrap:
                        gossip_node.add_peer(external_ip, external_port)
                    return
                else:
                    logging.warning(f"Stored info doesn't match: expected {info}, got {stored_info}")
            else:
                logging.warning(f"Failed to retrieve stored value for {key}")
        except Exception as e:
            logging.error(f"Error during gossip announcement: {e}")
        await asyncio.sleep(2)
    logging.error("Failed to announce gossip port after 5 attempts")

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
            
            # Handle both old format (just ip/port) and new NAT-aware format
            if isinstance(info, dict):
                ip = info.get("ip", info.get("external_ip"))
                port = info.get("port", info.get("external_port"))
                
                # Skip if it's our own external IP
                if ip == own_ip or ip == nat_traversal.external_ip if nat_traversal else False:
                    continue
                    
                # Store full peer info for NAT traversal
                gossip_node.add_peer(ip, port, peer_info=info)
                
                nat_type = info.get("nat_type", "unknown")
                logging.info(f"Connected to peer {vid} at {ip}:{port} (NAT type: {nat_type})")
            else:
                # Old format compatibility
                logging.warning(f"Old peer info format for {vid}: {info}")
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
            message_json = json.dumps(blocks_message)
            print(f"Sending message of {len(message_json)} bytes to {peer_ip}")
            w.write((message_json + "\n").encode('utf-8'))
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




async def discover_peers_periodically(gossip_node, local_ip=None):
    known_peers = set()
    # Use provided local IP or fall back to global own_ip
    current_ip = local_ip if local_ip else own_ip
    while not shutdown_event.is_set():
        try:
            validators_json = await kad_server.get(VALIDATORS_LIST_KEY)
            validator_ids = json.loads(validators_json) if validators_json else []
            print("*** in discover peers periodically")
            logging.info(f"Discovered {len(validator_ids)} validators in DHT")
            
            for vid in validator_ids:
                if vid == VALIDATOR_ID:
                    continue
                gossip_key = f"gossip_{vid}"
                gossip_info_json = await kad_server.get(gossip_key)
                if gossip_info_json:
                    info = json.loads(gossip_info_json)
                    print("*** in discover peers periodically")
                    print(info.get("ip", info.get("external_ip", "unknown")))
                    print(current_ip)
                    
                    # Handle both old and new format
                    ip = info.get("ip", info.get("external_ip"))
                    port = info.get("port", info.get("external_port"))
                    
                    if ip == current_ip:
                        continue
                    peer = (ip, port)
                    
                    # Always call add_peer - it will handle re-adding failed peers
                    gossip_node.add_peer(ip, port, peer_info=info)
                    
                    if peer not in known_peers:
                        logging.info(f"Connected to peer {vid} at {peer}")
                        known_peers.add(peer)
                    else:
                        # Peer already known, but add_peer will reset failure count if needed
                        logging.debug(f"Re-checking peer {vid} at {peer}")
                else:
                    logging.warning(f"No gossip info found for validator {vid}")
        except Exception as e:
            logging.error(f"Error in discover_peers_periodically: {e}")
        await asyncio.sleep(5)

async def update_heartbeat():
    heartbeat_key = f"validator_{VALIDATOR_ID}_heartbeat"
    while not shutdown_event.is_set():
        try:
            # Always try to update heartbeat, not just when bootstrapped
            await kad_server.set(heartbeat_key, str(time.time()))
            logging.debug(f"Updated heartbeat for {VALIDATOR_ID}")
        except Exception as e:
            logging.warning(f"Failed to update heartbeat: {e}")
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

        # Check heartbeats for all validators
        for v in dht_set:
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
                    # Handle both old and new format
                    ip = info.get("ip", info.get("external_ip"))
                    port = info.get("port", info.get("external_port"))
                    public_key = info.get("publicKey", "")
                    
                    if ip and port and ip != own_ip:
                        gossip_node.add_peer(ip, port, peer_info=info)
                        #await push_blocks(ip, port)
                        if public_key:
                            validator_keys[v] = public_key
                        logging.info(f"New validator joined: {v} at {ip}:{port}")
            except Exception as e:
                logging.warning(f"Failed to process new validator {v}: {e}")

        # Process validators that have left
        just_left = known_validators - alive
        for v in just_left:
            try:
                gossip_info_json = await kad_server.get(f"gossip_{v}")
                if gossip_info_json:
                    info = json.loads(gossip_info_json)
                    # Handle both old and new format
                    ip = info.get("ip", info.get("external_ip"))
                    port = info.get("port", info.get("external_port"))
                    if ip and port:
                        gossip_node.remove_peer(ip, port)
                validator_keys.pop(v, None)
                logging.info(f"Validator left: {v}")
            except Exception as e:
                logging.warning(f"Failed to remove validator {v}: {e}")

        # Update known validators
        known_validators.clear()
        known_validators.update(alive)

        await asyncio.sleep(HEARTBEAT_INTERVAL)