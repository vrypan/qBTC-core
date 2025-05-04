import asyncio
import json
import logging
import aiohttp
import time
import socket
from decimal import Decimal
from kademlia.network import Server as KademliaServer
from config.config import shutdown_event, VALIDATOR_ID, HEARTBEAT_INTERVAL, VALIDATOR_TIMEOUT, VALIDATORS_LIST_KEY, BOOTSTRAP_NODES, DEFAULT_GOSSIP_PORT
from state.state import validator_keys, known_validators
from blockchain.blockchain import calculate_merkle_root
from database.database import get_db,get_current_height
from wallet.wallet import verify_transaction

kad_server = None

async def get_external_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

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
    existing_json = await kad_server.get(VALIDATORS_LIST_KEY)
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
            validator_keys[vid] = info["publicKey"]
            logging.info(f"Initially connected to peer {vid} at {peer}")
        else:
            logging.warning(f"No gossip info found for validator {vid}")


async def push_blocks(peer_ip, peer_port):
    from gossip.gossip import calculate_merkle_root
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
            peer_tip = msg.get("current_tip")
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
                            tx_data = json.loads(db[tx_key].decode())
                            full_transactions.append(tx_data)
                        else:
                            print(f"Warning: Transaction {tx_id} not found in DB!")

                # Attach the full transactions to the block
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

            db = get_db()

            for block in blocks:
                height = block.get("height")
                print(height)
                block_hash = block.get("block_hash")
                print(block_hash)
                prev_hash = block.get("previous_hash")
                block_key = f"block:{block_hash}".encode()
                if block_key in db:
                    logging.info(f"Block {block_hash} already exists in DB. Skipping.")
                    continue 
                print(prev_hash)
                tx_ids = block.get("tx_ids", [])
                print(tx_ids)
                nonce = block.get("nonce")
                print(nonce)
                timestamp = block.get("timestamp")
                print(timestamp)
                miner_address = block.get("miner_address")
                print(miner_address)
                full_transactions = block.get("full_transactions", [])
                print(full_transactions)
                block_merkle_root = block.get("merkle_root")

                print(f"[SYNC] Processing block height {height} with hash {block_hash}")

                for tx in full_transactions:

                    if tx.get("tx_id") == "genesis_tx":
                        print("[SYNC] Genesis transaction detected.")
                        db.put(b"tx:genesis_tx", json.dumps(tx).encode())
                        continue

      
                    if "version" in tx and "inputs" in tx and "outputs" in tx:
                        print("[SYNC] Coinbase transaction detected.")
                        coinbase_tx_id = "coinbase_" + str(height)
                        print("coinbase_tx_id")
                        print(coinbase_tx_id)
                        db.put(f"tx:{coinbase_tx_id}".encode(), json.dumps(tx).encode())

                        for idx, output in enumerate(tx.get("outputs", [])):
                            output_key = f"utxo:{coinbase_tx_id}:{idx}".encode()
                            print(output_key)
                            utxo = {
                                "txid": coinbase_tx_id,
                                "utxo_index": idx,
                                "sender": "coinbase",
                                "receiver": "unknown",
                                "amount": output.get("value"),
                                "spent": False
                            }
                            print(utxo)
                            db.put(output_key, json.dumps(utxo).encode())
                        continue

 
                    if "txid" in tx:
                        txid = tx["txid"]

                        print("txid is")
                        print(txid)


                        inputs = tx.get("inputs", [])
                        print("inputs are")
                        print(inputs)
                        outputs = tx.get("outputs", [])
                        print("outputs are")
                        print(outputs)
                        body = tx.get("body", {})
                        print("body is")
                        print(body)

                        pubkey = body.get("pubkey", "unknown") 
                        signature = body.get("signature","unknown")
                        to_ = None
                        from_ = None

                        if (body.get("transaction_data") == "initial_distribution") and (height == 1):
                            print("im in initial distribution")
                            total_authorized = 21000000
                            to_ = ADMIN_ADDRESS
                            from_ = GENESIS_ADDRESS
                        else:
                            message_str = body["msg_str"]
                            print(message_str)
                            from_ = message_str.split(":")[0]
                            print(from_)
                            to_ = message_str.split(":")[1]  
                            print(to_)
                            total_authorized = message_str.split(":")[2]
                            time_ = message_str.split(":")[3]
                            print(time_)

                        total_available = Decimal("0")
                        total_required = Decimal("0")

                        print("im here")

      
                        for input_ in inputs:
                            input_receiver = input_.get("receiver")
                            input_spent = input_.get("spent", False)
                            input_amount = input_.get("amount", "0")

                            print(f"input receiver {input_receiver}")
                            print(f"to {to_}")
                            print(f"from: {from_}")
                            print(f"input_spent {input_spent}")
                            print(f"input amount {input_amount}")

                            print("im past inputs")

                            if (input_receiver == from_):
                                print("input receiver is from")

                                if (height == 1):
                                    print("coins not spent")
                                    total_available += Decimal(input_amount)
                                    print(f"total available increased by {input_amount}")

                                else:
                                    if (input_spent == False):
                                        print("coins not spent")
                                        total_available += Decimal(input_amount)
                                        print(f"total available increased by {input_amount}")

                        print(f"**** TOTAL AVAILABLE IS {total_available} ")


                        for output_ in outputs:
                            output_receiver = output_.get("receiver")
                            output_amount = output_.get("amount", "0")
                            if output_receiver in (to_, ADMIN_ADDRESS):
                                total_required += Decimal(output_amount)
                            else:
                                print(f"❌ Hack detected! Unauthorized output to {output_receiver}")
                                raise ValueError("Hack detected, invalid transaction.")

                        print(total_authorized)

                        miner_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(Decimal("0.00000001"))
                        treasury_fee = (Decimal(total_authorized) * Decimal("0.001")).quantize(Decimal("0.00000001"))
                        grand_total_required = Decimal(total_authorized) + miner_fee + treasury_fee

                        if (height > 1):
                            if grand_total_required > total_available:
                                print(f"❌ Not enough balance! {total_available} < {grand_total_required}")
                                raise ValueError("Invalid transaction: insufficient balance.")
                        

                        if height == 1 or (verify_transaction(message_str, signature, pubkey) == True):
                            print("✅ Transaction validated successfully.")
                            batch = WriteBatch()

  
                            batch.put(f"tx:{txid}".encode(), json.dumps(tx).encode())

                            # Spend each input UTXO
                            for input_ in inputs:
                                if "txid" in input_:
                                    spent_utxo_key = f"utxo:{input_['txid']}:{input_.get('utxo_index', 0)}".encode()
                                    if spent_utxo_key in db:
                                        utxo = json.loads(db.get(spent_utxo_key).decode())
                                        utxo["spent"] = True
                                        batch.put(spent_utxo_key, json.dumps(utxo).encode())
                                    else:
                                        print(f"[SYNC] Warning: input UTXO not found {spent_utxo_key}")

                            # Create UTXOs from outputs
                            for output in outputs:
                                output_key = f"utxo:{txid}:{output.get('utxo_index', 0)}".encode()
                                batch.put(output_key, json.dumps(output).encode())

                            # Atomic commit
                            db.write(batch)
                        else:
                            print("❌ Transaction verification failed.")

                print("tx_ids are")
                print(tx_ids)
                calculated_merkle_root = calculate_merkle_root(tx_ids)

                print(calculated_merkle_root)
                print(block_merkle_root)

                if (calculated_merkle_root == block_merkle_root):

                    block_data = {
                        "height": height,
                        "block_hash": block_hash,
                        "previous_hash": prev_hash,
                        "tx_ids": tx_ids,
                        "nonce": nonce,
                        "timestamp": timestamp,
                        "miner_address": miner_address,
                        "merkle_root": calculated_merkle_root
                    }
                    db.put(f"block:{block_hash}".encode(), json.dumps(block_data).encode())

                    print(f"[SYNC] Stored block {height} successfully.")

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
                    await push_blocks(info["ip"],info["port"])

                    known_peers.add(peer)
            else:
                logging.warning(f"No gossip info found for validator {vid}")
        await asyncio.sleep(60)

async def update_heartbeat():
    heartbeat_key = f"validator_{VALIDATOR_ID}_heartbeat"
    while not shutdown_event.is_set():
        if kad_server.bootstrappable_neighbors():
            await kad_server.set(heartbeat_key, time.time())
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
        for v, task in tasks.items():
            try:
                last_seen = await task
                if last_seen and (current_time - float(last_seen)) <= VALIDATOR_TIMEOUT:
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
                        await push_blocks(info["ip"], info["port"])
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