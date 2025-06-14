"""
NAT traversal utilities for qBTC network
Handles UPnP, STUN, and hole punching for P2P connectivity
"""

import asyncio
import logging
import socket
import json
import time
import uuid
from typing import Optional, Tuple, Dict

try:
    import miniupnpc
    UPNP_AVAILABLE = True
except ImportError:
    UPNP_AVAILABLE = False
    
logger = logging.getLogger(__name__)

class NATTraversal:
    """Handles various NAT traversal methods"""
    
    def __init__(self):
        self.upnp = None
        self.mapped_ports = {}
        self.external_ip = None
        
    async def setup_upnp(self, internal_port: int, protocol: str = 'TCP') -> Optional[int]:
        """Try to set up UPnP port mapping"""
        if not UPNP_AVAILABLE:
            logger.warning("miniupnpc not installed, UPnP disabled")
            return None
            
        try:
            self.upnp = miniupnpc.UPnP()
            self.upnp.discoverdelay = 200
            
            # Discover UPnP devices
            devices = await asyncio.to_thread(self.upnp.discover)
            if devices == 0:
                logger.warning("No UPnP devices found")
                return None
                
            # Select IGD
            await asyncio.to_thread(self.upnp.selectigd)
            
            # Get external IP
            self.external_ip = await asyncio.to_thread(self.upnp.externalipaddress)
            logger.info(f"UPnP external IP: {self.external_ip}")
            
            # Try to map the port
            external_port = internal_port
            for attempt in range(10):  # Try 10 different ports
                try:
                    result = await asyncio.to_thread(
                        self.upnp.addportmapping,
                        external_port,
                        protocol,
                        internal_port,
                        self.upnp.lanaddr,
                        'qBTC Node',
                        ''
                    )
                    if result:
                        self.mapped_ports[internal_port] = (external_port, protocol)
                        logger.info(f"UPnP mapping successful: {internal_port} -> {self.external_ip}:{external_port} ({protocol})")
                        return external_port
                except Exception as e:
                    logger.debug(f"Port {external_port} failed: {e}")
                    external_port += 1
                    
            logger.warning("Failed to create UPnP mapping after 10 attempts")
            return None
            
        except Exception as e:
            logger.error(f"UPnP setup failed: {e}")
            return None
    
    async def setup_all_ports(self, dht_port: int, gossip_port: int) -> Dict[str, Optional[int]]:
        """Setup UPnP for all required ports"""
        results = {}
        
        # Map DHT port (UDP)
        results['dht'] = await self.setup_upnp(dht_port, 'UDP')
        
        # Map Gossip port (TCP)
        results['gossip'] = await self.setup_upnp(gossip_port, 'TCP')
        
        return results
            
    async def cleanup_upnp(self):
        """Remove UPnP mappings on shutdown"""
        if self.upnp and self.mapped_ports:
            for internal_port, (external_port, protocol) in self.mapped_ports.items():
                try:
                    await asyncio.to_thread(
                        self.upnp.deleteportmapping,
                        external_port,
                        protocol
                    )
                    logger.info(f"Removed UPnP mapping: {external_port} ({protocol})")
                except Exception as e:
                    logger.error(f"Failed to remove UPnP mapping: {e}")
                    
    def get_external_endpoint(self, internal_port: int) -> Tuple[str, int]:
        """Get the external endpoint for a given internal port"""
        if internal_port in self.mapped_ports:
            external_port, _ = self.mapped_ports[internal_port]
            return (self.external_ip, external_port)
        return None


class SimpleSTUN:
    """Simple STUN client for external address detection"""
    
    STUN_SERVERS = [
        ('stun.l.google.com', 19302),
        ('stun1.l.google.com', 19302),
        ('stun.stunprotocol.org', 3478),
        ('stun.services.mozilla.com', 3478)
    ]
    
    @staticmethod
    async def get_external_address(local_port: int) -> Optional[Tuple[str, int]]:
        """Get external IP and port via STUN"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.bind(('', local_port))
        
        # STUN Binding Request
        stun_request = b'\x00\x01' + b'\x00\x00' + b'\x21\x12\xa4\x42' + b'\x00' * 12
        
        for server_host, server_port in SimpleSTUN.STUN_SERVERS:
            try:
                # Send STUN request
                await asyncio.to_thread(
                    sock.sendto,
                    stun_request,
                    (server_host, server_port)
                )
                
                # Receive response
                data, addr = await asyncio.to_thread(sock.recvfrom, 1024)
                
                # Parse STUN response (simplified)
                if len(data) >= 32 and data[0:2] == b'\x01\x01':
                    # Look for XOR-MAPPED-ADDRESS attribute (0x0020)
                    i = 20
                    while i < len(data) - 4:
                        attr_type = int.from_bytes(data[i:i+2], 'big')
                        attr_len = int.from_bytes(data[i+2:i+4], 'big')
                        
                        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                            # Parse address (simplified for IPv4)
                            xor_port = int.from_bytes(data[i+6:i+8], 'big')
                            xor_ip = data[i+8:i+12]
                            
                            # Unmask with magic cookie
                            port = xor_port ^ 0x2112
                            ip_bytes = bytes(b ^ 0x21 if j == 0 else b ^ 0x12 if j == 1 else b ^ 0xa4 if j == 2 else b ^ 0x42 
                                           for j, b in enumerate(xor_ip))
                            ip = '.'.join(str(b) for b in ip_bytes)
                            
                            sock.close()
                            logger.info(f"STUN discovered external address: {ip}:{port}")
                            return (ip, port)
                            
                        i += 4 + attr_len
                        
            except Exception as e:
                logger.debug(f"STUN server {server_host} failed: {e}")
                continue
                
        sock.close()
        return None


class TCPHolePuncher:
    """TCP hole punching implementation"""
    
    def __init__(self, validator_id: str):
        self.validator_id = validator_id
        self.pending_punches = {}
        
    async def coordinate_hole_punch(self, target_id: str, target_info: dict, 
                                   local_port: int, dht_server) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """Coordinate TCP hole punching with target peer"""
        
        punch_id = str(uuid.uuid4())
        
        # Announce our intention to hole punch
        punch_request = {
            "type": "hole_punch",
            "punch_id": punch_id,
            "initiator_id": self.validator_id,
            "initiator_port": local_port,
            "target_id": target_id,
            "timestamp": time.time()
        }
        
        # Store request in DHT
        await dht_server.set(f"punch_{punch_id}", json.dumps(punch_request))
        
        # Notify target via DHT
        await dht_server.set(f"punch_notify_{target_id}", json.dumps({
            "punch_id": punch_id,
            "initiator_id": self.validator_id
        }))
        
        # Wait a bit for coordination
        await asyncio.sleep(1)
        
        # Attempt simultaneous connect
        target_ip = target_info.get('ip')
        target_port = target_info.get('port')
        
        return await self._simultaneous_connect(target_ip, target_port, local_port)
        
    async def _simultaneous_connect(self, peer_ip: str, peer_port: int, 
                                   local_port: int) -> Optional[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
        """Perform simultaneous TCP connection"""
        
        # Create reusable socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', local_port))
        sock.setblocking(False)
        
        # Multiple rapid connection attempts
        for attempt in range(20):
            try:
                # Non-blocking connect
                result = sock.connect_ex((peer_ip, peer_port))
                
                if result == 0 or result == errno.EISCONN:
                    # Connected! Convert to asyncio
                    reader, writer = await asyncio.open_connection(sock=sock)
                    logger.info(f"Hole punch successful to {peer_ip}:{peer_port}")
                    return reader, writer
                    
            except Exception as e:
                logger.debug(f"Hole punch attempt {attempt} failed: {e}")
                
            await asyncio.sleep(0.1)
            
        sock.close()
        return None


# Global NAT traversal instance
nat_traversal = NATTraversal()