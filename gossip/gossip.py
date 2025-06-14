import asyncio
import json
import time
import logging
import random
from asyncio import StreamReader, StreamWriter
from config.config import DEFAULT_GOSSIP_PORT
from state.state import pending_transactions
from wallet.wallet import verify_transaction
from database.database import get_db, get_current_height
from dht.dht import push_blocks
from sync.sync import process_blocks_from_peer
from network.peer_reputation import peer_reputation_manager

# Import NAT traversal
try:
    from network.nat_traversal import TCPHolePuncher, nat_traversal
    NAT_TRAVERSAL_AVAILABLE = True
except ImportError:
    TCPHolePuncher = None
    nat_traversal = None
    NAT_TRAVERSAL_AVAILABLE = False

GENESIS_HASH = "0" * 64
MAX_LINE_BYTES = 30 * 1024 * 1024  

class GossipNode:
    def __init__(self, node_id, wallet=None, is_bootstrap=False, is_full_node=True):
        self.node_id = node_id
        self.wallet = wallet
        self.seen_tx = set()
        self.dht_peers = set()  
        self.client_peers = set()  
        self.failed_peers = {}
        self.peer_info = {}  # Store full peer info for NAT traversal
        self.server_task = None
        self.server = None
        self.partition_task = None
        self.is_bootstrap = is_bootstrap
        self.is_full_node = is_full_node
        self.gossip_port = None  # Will be set when server starts
        self.synced_peers = set()
        #if not is_bootstrap:
            # Temporary workaround until DHT is fully debugged
        #    self.dht_peers.add(('api.bitcoinqs.org', 7002))

    async def start_server(self, host="0.0.0.0", port=DEFAULT_GOSSIP_PORT):
        self.gossip_port = port  # Store for NAT traversal
        self.server = await asyncio.start_server(self.handle_client, host, port, limit=MAX_LINE_BYTES)
        self.server_task = asyncio.create_task(self.server.serve_forever())
        #self.partition_task = asyncio.create_task(self.check_partition())
        logging.info(f"Gossip server started on {host}:{port}")

    async def handle_client(self, reader: StreamReader, writer: StreamWriter):
        peer_info = writer.get_extra_info('peername')
        peer_ip, peer_port = peer_info[0], peer_info[1]
        
        logging.info(f"New peer connection: {peer_ip}:{peer_port}")
        
        # Check peer reputation before accepting connection
        if not peer_reputation_manager.should_connect_to_peer(peer_ip, peer_port):
            logging.warning(f"Rejecting connection from banned/malicious peer {peer_ip}:{peer_port}")
            writer.close()
            await writer.wait_closed()
            return
        
        # Record successful connection
        peer_reputation_manager.record_connection_success(peer_ip, peer_port)
        
        if peer_info not in self.client_peers and peer_info not in self.dht_peers:
            self.client_peers.add(peer_info)
            logging.info(f"Added temporary client peer {peer_info}")
        
        start_time = time.time()
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line:
                    break
                
                try:
                    msg = json.loads(line.decode('utf-8').strip())
                    await self.handle_gossip_message(msg, peer_info, writer)
                    
                    # Record valid message
                    peer_reputation_manager.record_valid_message(
                        peer_ip, peer_port, msg.get("type", "unknown")
                    )
                    
                except json.JSONDecodeError as e:
                    logging.warning(f"Invalid JSON from {peer_info}: {e}")
                    peer_reputation_manager.record_invalid_message(
                        peer_ip, peer_port, "invalid_json"
                    )
                except Exception as e:
                    logging.error(f"Error processing message from {peer_info}: {e}")
                    peer_reputation_manager.record_invalid_message(
                        peer_ip, peer_port, str(e)
                    )
                    
        except asyncio.TimeoutError:
            logging.warning(f"Timeout handling client {peer_info}")
            peer_reputation_manager.record_timeout(peer_ip, peer_port)
        except Exception as e:
            logging.error(f"Error handling client {peer_info}: {e}")
            peer_reputation_manager.record_connection_failure(
                peer_ip, peer_port, str(e)
            )
        finally:
            # Record disconnection
            peer_reputation_manager.record_disconnection(peer_ip, peer_port)
            
            # Record response time
            response_time = time.time() - start_time
            peer_reputation_manager.record_response_time(peer_ip, peer_port, response_time)
            
            if peer_info in self.client_peers:
                self.client_peers.remove(peer_info)
                logging.info(f"Removed temporary client peer {peer_info}")
            
            writer.close()
            await writer.wait_closed()


    

   



    async def handle_gossip_message(self, msg, from_peer, writer):
        db = get_db()  
        msg_type = msg.get("type")
        timestamp = msg.get("timestamp", int(time.time() * 1000))
        tx_id = msg.get("tx_id")

        print(msg)


        if timestamp < int(time.time() * 1000) - 60000:  
            print("**** TRANSACTION IS STALE")
            return

        if msg_type == "transaction":
            print(msg)
            if tx_id in self.seen_tx or tx_id in pending_transactions:
                return
            if not verify_transaction(msg["body"]["msg_str"], msg["body"]["signature"], msg["body"]["pubkey"]):
                return
            tx_lock = asyncio.Lock()
            
            async with tx_lock:
                if tx_id in pending_transactions:
                    return
                pending_transactions[tx_id] = msg
            await self.randomized_broadcast(msg)
            self.seen_tx.add(tx_id)

        elif msg_type == "blocks_response":
            process_blocks_from_peer(msg["blocks"])
   

        elif msg_type == "get_height":
            height, tip_hash = get_current_height(db)

            response = {"type": "height_response", "height": height, "current_tip": tip_hash}
            writer.write((json.dumps(response) + "\n").encode('utf-8'))
            await writer.drain()

        elif msg_type == "get_blocks":
            print(msg)
            start_height = msg.get("start_height")
            end_height = msg.get("end_height")
            if start_height is None or end_height is None:
                return

            blocks = []

            for h in range(start_height, end_height + 1):
                found_block = None

                for key in db.keys():
                    if key.startswith(b"block:"):
                        block = json.loads(db[key].decode())

                        if block.get("height") == h:
                            expanded_txs = []
                            for tx_id in block["tx_ids"]:
                                tx_key = f"tx:{tx_id}".encode()
                                if tx_key in db:
                                    expanded_txs.append({
                                        "tx_id": tx_id,
                                        "transaction": json.loads(db[tx_key].decode())
                                    })
                                    #expanded_txs.append({
                                    #    "tx_id": tx_id,
                                    #    "transaction": tx_data
                                    #})
                                else:
                                    continue
                                    #expanded_txs.append({
                                    #    "tx_id": tx_id,
                                    #    "transaction": None
                                    #})

                            cb_key = f"tx:coinbase_{h}".encode()
                            if cb_key in db:
                                expanded_txs.append(json.loads(db[cb_key].decode()))

                            block["full_transactions"] = expanded_txs
                            found_block = block
                            break

                if found_block:
                    blocks.append(found_block)

            response = {"type": "blocks_response", "blocks": blocks}
            writer.write((json.dumps(response) + "\n").encode('utf-8'))
            await writer.drain()

  

    async def randomized_broadcast(self, msg_dict):
        peers = self.dht_peers | self.client_peers 
        if not peers:
            return
        num_peers = max(2, int(len(peers) ** 0.5))
        peers_to_send = random.sample(list(peers), min(len(peers), num_peers))
        payload = (json.dumps(msg_dict) + "\n").encode('utf-8')
        results = await asyncio.gather(
            *[self._send_message(p, payload) for p in peers_to_send],
            return_exceptions=True          
        )
        for peer, result in zip(peers_to_send, results):
            if isinstance(result, Exception):
                logging.warning(f"broadcast {peer} failed: {result}")

    async def _send_message(self, peer, payload):
        # Try direct connection first
        for attempt in range(2):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(peer[0], peer[1], limit=MAX_LINE_BYTES),
                    timeout=5
                )
                writer.write(payload)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                self.failed_peers[peer] = 0
                return
            except Exception as e:
                logging.debug(f"Direct connection attempt {attempt + 1} to {peer} failed: {e}")
                await asyncio.sleep(1)
        
        # Try NAT traversal if available and peer supports it
        if NAT_TRAVERSAL_AVAILABLE and peer in self.peer_info:
            peer_info = self.peer_info[peer]
            if peer_info.get('supports_nat_traversal') and peer_info.get('nat_type') != 'direct':
                logging.info(f"Attempting NAT traversal for peer {peer}")
                
                # Try local network connection if on same network
                if peer_info.get('local_ip') and self._is_same_network(peer_info['local_ip']):
                    try:
                        local_peer = (peer_info['local_ip'], peer_info['local_port'])
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(local_peer[0], local_peer[1], limit=MAX_LINE_BYTES),
                            timeout=3
                        )
                        writer.write(payload)
                        await writer.drain()
                        writer.close()
                        await writer.wait_closed()
                        self.failed_peers[peer] = 0
                        logging.info(f"Local network connection successful to {local_peer}")
                        return
                    except Exception:
                        pass
        
        # All attempts failed
        self.failed_peers[peer] = self.failed_peers.get(peer, 0) + 1
        if peer in self.dht_peers and self.failed_peers[peer] > 3:
            self.dht_peers.remove(peer)
            self.peer_info.pop(peer, None)
            logging.info(f"Removed failed DHT peer {peer}")
    
    def _is_same_network(self, peer_local_ip: str) -> bool:
        """Check if peer is in same local network"""
        try:
            import ipaddress
            import socket
            
            # Get our local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            my_ip = s.getsockname()[0]
            s.close()
            
            my_addr = ipaddress.ip_address(my_ip)
            peer_addr = ipaddress.ip_address(peer_local_ip)
            
            # Check common private networks
            private_networks = [
                ipaddress.ip_network('10.0.0.0/8'),
                ipaddress.ip_network('172.16.0.0/12'),
                ipaddress.ip_network('192.168.0.0/16')
            ]
            
            for network in private_networks:
                if my_addr in network and peer_addr in network:
                    return True
        except Exception:
            pass
        return False

    async def check_partition(self):
        while True:
            alive_peers = sum(1 for peer in self.dht_peers if self.failed_peers.get(peer, 0) < 3)
            if alive_peers < len(self.dht_peers) // 2 and len(self.dht_peers) > 0:
                for peer, fails in list(self.failed_peers.items()):
                    if fails >= 3 and peer in self.dht_peers:
                        try:
                            w = await asyncio.open_connection(peer[0], peer[1])
                            w.write(b"PING\n")
                            await w.drain()
                            w.close()
                            await w.wait_closed()
                            self.failed_peers[peer] = 0
                        except Exception:
                            self.dht_peers.remove(peer)
                            logging.info(f"Removed partitioned DHT peer {peer}")
            await asyncio.sleep(60)

    def add_peer(self, ip: str, port: int, peer_info=None):
        peer = (ip, port)
        if peer not in self.dht_peers:
            self.dht_peers.add(peer)
            
            # Store peer info for NAT traversal
            if peer_info:
                self.peer_info[peer] = peer_info
                
            logging.info(f"Added DHT peer {peer} to validator list")
            if peer not in self.synced_peers:
                self.synced_peers.add(peer)
                asyncio.create_task(push_blocks(ip, port))

    def remove_peer(self, ip: str, port: int):
        peer = (ip, port)
        if peer in self.dht_peers:
            self.dht_peers.remove(peer)
            self.failed_peers.pop(peer, None)
            logging.info(f"Removed DHT peer {peer} from validator list")

    async def stop(self):
        if self.server_task:
            self.server_task.cancel()
        if self.partition_task:
            self.partition_task.cancel()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
