#!/usr/bin/env python3
"""
Enhanced qBTC Network Test with Real cpuminer-opt Block Mining
- Runs Docker Compose with rate limiting disabled for testing
- Creates transactions and verifies propagation across gossip network
- Uses cpuminer-opt Docker container for real block mining
- Verifies blockchain height increases and block propagation across all 3 nodes
- Tests complete block lifecycle: TX → mine (cpuminer) → submit → propagate → verify
- Provides comprehensive network stability and block propagation analysis
"""

import argparse
import base64
import requests
import subprocess
import time
from decimal import Decimal
from typing import List, Dict, Any, Optional
from wallet.wallet import get_or_create_wallet, sign_transaction

class Full100CycleTest:
    def __init__(self, web_nodes: List[str], rpc_nodes: List[str], wallet_file: str = None, wallet_password: str = None):
        self.web_nodes = web_nodes
        self.rpc_nodes = rpc_nodes
        self.primary_web = web_nodes[0]
        self.primary_rpc = rpc_nodes[0]
        self.test_results = []
        self.wallet_file = wallet_file
        self.wallet_password = wallet_password
        
    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with timestamps"""
        emoji_map = {
            "INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARNING": "⚠️",
            "MINING": "⛏️", "NETWORK": "🌐", "WALLET": "💰", "BLOCK": "📦",
            "TEST": "🧪", "CYCLE": "🔄", "STATS": "📊"
        }
        emoji = emoji_map.get(level, "📝")
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {emoji} {message}")

    def rpc_call(self, node_url: str, method: str, params: List[Any] = None, rpc_id: str = "1") -> Optional[Dict[str, Any]]:
        """Make RPC call with error handling"""
        if params is None:
            params = []
        
        payload = {"method": method, "params": params, "id": rpc_id}
        
        try:
            response = requests.post(node_url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.log(f"RPC call failed to {node_url}: {e}", "ERROR")
            return None

    def web_call(self, node_url: str, endpoint: str, method: str = "GET", data: Dict = None) -> Optional[Dict[str, Any]]:
        """Make web API call with error handling"""
        url = f"{node_url}{endpoint}"
        
        try:
            if method == "GET":
                response = requests.get(url, timeout=30)
            elif method == "POST":
                response = requests.post(url, json=data, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            response.raise_for_status()
            
            # Try to parse JSON response
            try:
                return response.json()
            except:
                # If not JSON, log the response text for debugging
                self.log(f"Non-JSON response from {url}: {response.text[:200]}", "WARNING")
                return None
                
        except requests.RequestException as e:
            self.log(f"Web call failed to {url}: {e}", "ERROR")
            # For 400 errors, try to get more details
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    self.log(f"Error details: {error_detail}", "ERROR")
                except:
                    self.log(f"Error response: {e.response.text[:200]}", "ERROR")
            return None

    def wait_for_nodes_ready(self, max_wait: int = 120) -> bool:
        """Wait for all nodes to be healthy with gossip connections"""
        self.log("Waiting for nodes to start and establish connections...", "NETWORK")
        
        start_time = time.time()
        while time.time() - start_time < max_wait:
            all_healthy = True
            nodes_ready = 0
            
            for i, web_url in enumerate(self.web_nodes):
                try:
                    # Health endpoint now returns Prometheus metrics, not JSON
                    # Just check if it responds with 200 OK
                    response = requests.get(f"{web_url}/health", timeout=5)
                    if response.status_code == 200:
                        nodes_ready += 1
                    else:
                        all_healthy = False
                        
                except:
                    all_healthy = False
                    break
            
            if all_healthy and nodes_ready == len(self.web_nodes):
                self.log(f"All {nodes_ready} nodes are healthy and responding", "SUCCESS")
                # Give a bit more time for gossip connections to establish
                time.sleep(5)
                return True
            
            time.sleep(2)
            
        self.log("Timeout waiting for nodes to be ready", "ERROR")
        return False

    def get_blockchain_status(self) -> Dict[str, Dict[str, Any]]:
        """Get blockchain status from all nodes"""
        status = {}
        
        for i, rpc_url in enumerate(self.rpc_nodes):
            try:
                result = self.rpc_call(rpc_url, "getblocktemplate")
                if result and "result" in result:
                    template = result["result"]
                    node_status = {
                        "height": template["height"] - 1,  # Template is for next block
                        "previous_hash": template["previousblockhash"],
                        "transactions": len(template.get("transactions", [])),
                        "template_height": template["height"],
                        "target": template["target"]
                    }
                    status[f"node_{i+1}"] = node_status
                else:
                    status[f"node_{i+1}"] = {"error": "Failed to get template"}
            except Exception as e:
                status[f"node_{i+1}"] = {"error": str(e)}
        
        return status

    def create_and_broadcast_transaction(self, wallet_file: str, receiver: str, amount: Decimal, wallet_password: str = None) -> Optional[str]:
        """Create and broadcast a transaction, return tx_id"""
        try:
            # Load wallet
            wallet = get_or_create_wallet(fname=wallet_file, password=wallet_password)
            sender = wallet["address"]
            
            # Build transaction message
            nonce = str(int(time.time() * 1000))
            message_str = f"{sender}:{receiver}:{amount.normalize()}:{nonce}"
            
            # Sign transaction
            signature_hex = sign_transaction(message_str, wallet["privateKey"])
            
            # Prepare payload
            payload = {
                "request_type": "broadcast_tx",
                "message": base64.b64encode(message_str.encode()).decode(),
                "signature": base64.b64encode(bytes.fromhex(signature_hex)).decode(),
                "pubkey": base64.b64encode(bytes.fromhex(wallet["publicKey"])).decode(),
            }
            
            # Debug: show first transaction details
            if hasattr(self, '_first_tx_logged'):
                pass
            else:
                self._first_tx_logged = True
                self.log(f"First transaction - Sender: {sender[:20]}...", "INFO")
                self.log(f"First transaction - Receiver: {receiver[:20]}...", "INFO")
                self.log(f"First transaction - Amount: {amount}", "INFO")
            
            # Broadcast to primary node
            result = self.web_call(self.primary_web, "/worker", "POST", payload)
            
            if result and "tx_id" in result:
                return result["tx_id"]
            else:
                self.log(f"Transaction broadcast failed: {result}", "ERROR")
                return None
                
        except Exception as e:
            self.log(f"Transaction creation failed: {e}", "ERROR")
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return None

    def check_transaction_propagation(self, expected_count: int, max_wait: int = 10) -> Dict[str, int]:
        """Check transaction propagation across nodes"""
        start_time = time.time()
        best_result = {}
        
        while time.time() - start_time < max_wait:
            tx_counts = {}
            for i, rpc_url in enumerate(self.rpc_nodes):
                try:
                    result = self.rpc_call(rpc_url, "getblocktemplate")
                    if result and "result" in result:
                        template = result["result"]
                        count = len(template.get("transactions", []))
                        tx_counts[f"node_{i+1}"] = count
                    else:
                        tx_counts[f"node_{i+1}"] = -1
                except:
                    tx_counts[f"node_{i+1}"] = -1
            
            best_result = tx_counts
            
            # Check if all nodes have the expected count
            valid_counts = [count for count in tx_counts.values() if count >= 0]
            if len(valid_counts) == len(self.rpc_nodes) and all(count >= expected_count for count in valid_counts):
                break
                
            time.sleep(1)
        
        return best_result

    def mine_with_cpuminer(self, timeout_seconds: int = 120) -> Optional[Dict[str, Any]]:
        """Use cpuminer-opt to mine a block with proper block construction"""
        start_time = time.time()
        
        try:
            # Get initial blockchain state
            initial_status = self.get_blockchain_status()
            initial_height = None
            
            for node_id, status in initial_status.items():
                if "error" not in status:
                    initial_height = status["height"]
                    break
            
            if initial_height is None:
                self.log("Could not determine initial blockchain height", "ERROR")
                return None
            
            self.log(f"Starting cpuminer-opt against {self.primary_rpc} (initial height: {initial_height})", "MINING")
            
            # Run cpuminer-opt to mine exactly one block
            # On macOS, use the docker network instead of host network
            cmd = [
                "docker", "run", "--rm", "--network=qbtc-core_qbtc-network",
                "cpuminer-opt",
                "-a", "sha256d",
                "-o", "http://qbtc-bootstrap:8332/",  # Use container name on docker network
                "-u", "test", "-p", "x",
                "--coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT",  # Use Bitcoin-compatible address
                "-q",  # Quiet mode - less output
            ]
            
            self.log(f"Running cpuminer command: {' '.join(cmd)}", "MINING")
            
            # Start the mining process
            # Don't use wait_for on the Popen itself
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,  # Combine stderr with stdout
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )
            except Exception as e:
                self.log(f"Failed to start cpuminer process: {e}", "ERROR")
                return None
            
            # Monitor for block found or timeout
            mining_start = time.time()
            output_lines = []
            block_found = False
            
            while time.time() - mining_start < timeout_seconds:
                # Check if process is still running
                if process.poll() is not None:
                    # Process ended - get remaining output
                    remaining_output = process.stdout.read()
                    if remaining_output:
                        output_lines.extend(remaining_output.split('\n'))
                    break
                
                # Read output line by line to detect block found
                try:
                    # Non-blocking read with timeout
                    import select
                    if hasattr(select, 'select'):
                        ready, _, _ = select.select([process.stdout], [], [], 0.1)
                        if ready:
                            line = process.stdout.readline()
                            if line:
                                output_lines.append(line.strip())
                                # Log first few lines to see what's happening
                                if len(output_lines) <= 5:
                                    self.log(f"cpuminer output: {line.strip()}", "INFO")
                                # Check for block solved message
                                if "BLOCK SOLVED" in line or "yay!!!" in line.lower():
                                    block_found = True
                                    mining_time = time.time() - mining_start
                                    self.log(f"cpuminer found a block in {mining_time:.1f}s!", "SUCCESS")
                                    
                                    # Wait a moment for submission attempt then terminate
                                    time.sleep(2)
                                    process.terminate()
                                    
                                    # Check if blockchain height increased
                                    time.sleep(1)  # Give network time to process
                                    current_status = self.get_blockchain_status()
                                    current_height = None
                                    
                                    for node_id, status in current_status.items():
                                        if "error" not in status:
                                            current_height = status["height"]
                                            break
                                    
                                    height_increased = current_height is not None and current_height > initial_height
                                    
                                    if height_increased:
                                        self.log(f"Block accepted! Height: {initial_height} → {current_height}", "SUCCESS")
                                    else:
                                        self.log(f"Block found but not accepted (height still {current_height})", "WARNING")
                                    
                                    return {
                                        "height": current_height or initial_height,
                                        "initial_height": initial_height,
                                        "mining_time": mining_time,
                                        "submitted": height_increased,
                                        "block_found": True,
                                        "method": "cpuminer-opt",
                                        "output": '\n'.join(output_lines[-5:])  # Last 5 lines
                                    }
                    else:
                        # Fallback for systems without select
                        time.sleep(0.1)
                except:
                    time.sleep(0.1)
                
                # Also check blockchain height periodically (every 5 seconds)
                if int(time.time() - mining_start) % 5 == 0:
                    current_status = self.get_blockchain_status()
                    current_height = None
                    
                    for node_id, status in current_status.items():
                        if "error" not in status:
                            current_height = status["height"]
                            break
                    
                    if current_height is not None and current_height > initial_height:
                        # Block was mined and accepted (maybe we missed the log message)
                        process.terminate()
                        
                        mining_time = time.time() - mining_start
                        self.log(f"Block accepted! Height: {initial_height} → {current_height} in {mining_time:.1f}s", "SUCCESS")
                        
                        return {
                            "height": current_height,
                            "initial_height": initial_height,
                            "mining_time": mining_time,
                            "submitted": True,
                            "method": "cpuminer-opt",
                            "output": '\n'.join(output_lines[-5:])
                        }
                
                time.sleep(0.5)  # Check twice per second
            
            # Timeout or process ended without success
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            
            # Get final output
            stdout, stderr = process.communicate()
            
            mining_time = time.time() - mining_start
            self.log(f"Mining timeout after {mining_time:.1f}s - no block found", "WARNING")
            
            return {
                "height": initial_height,
                "initial_height": initial_height,
                "mining_time": mining_time,
                "submitted": False,
                "method": "cpuminer-opt",
                "timeout": True,
                "stdout": stdout[-200:] if stdout else "",
                "stderr": stderr[-200:] if stderr else ""
            }
            
        except Exception as e:
            self.log(f"Mining process error: {e}", "ERROR")
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return None

    def verify_blockchain_height_propagation(self, expected_height: int, max_wait: int = 30) -> Dict[str, Any]:
        """Verify that all nodes have consistent blockchain height after block submission"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            status = self.get_blockchain_status()
            heights = []
            all_responsive = True
            
            for node_id, node_status in status.items():
                if "error" in node_status:
                    all_responsive = False
                    break
                height = node_status.get("height", -1)
                heights.append(height)
            
            if all_responsive and len(set(heights)) <= 1 and max(heights) >= expected_height:
                # All nodes are at same height and at least at expected height
                results = {
                    "propagation_success": True,
                    "all_at_expected_height": True,
                    "height_achieved": max(heights),
                    "node_heights": {node: status[node].get("height", -1) for node in status.keys() if "error" not in status[node]},
                    "propagation_time": time.time() - start_time
                }
                return results
            
            time.sleep(1)
        
        # Final check
        final_status = self.get_blockchain_status()
        heights = []
        node_heights = {}
        
        for node_id, node_status in final_status.items():
            if "error" not in node_status:
                height = node_status.get("height", -1)
                heights.append(height)
                node_heights[node_id] = height
            else:
                node_heights[node_id] = -1
                
        return {
            "propagation_success": len(set(heights)) <= 1 and len(heights) == len(self.rpc_nodes),
            "all_at_expected_height": min(heights) >= expected_height if heights else False,
            "height_achieved": max(heights) if heights else -1,
            "node_heights": node_heights,
            "propagation_time": max_wait  # Timeout reached
        }
    
    def get_detailed_blockchain_status(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed blockchain status including block hashes"""
        status = {}
        
        for i, rpc_url in enumerate(self.rpc_nodes):
            try:
                # Get template for height
                template_result = self.rpc_call(rpc_url, "getblocktemplate")
                
                # Try to get the current block hash (if available)
                block_info = {"height": -1, "hash": "unknown", "transactions": 0}
                
                if template_result and "result" in template_result:
                    template = template_result["result"]
                    current_height = template["height"] - 1  # Template is for next block
                    block_info["height"] = current_height
                    block_info["prev_hash"] = template["previousblockhash"] 
                    block_info["transactions"] = len(template.get("transactions", []))
                    block_info["template_height"] = template["height"]
                    block_info["target"] = template["target"]
                
                status[f"node_{i+1}"] = block_info
                
            except Exception as e:
                status[f"node_{i+1}"] = {"error": str(e)}
        
        return status

    def run_single_cycle(self, cycle: int) -> Dict[str, Any]:
        """Run a single test cycle: transaction -> mine -> verify propagation"""
        cycle_results = {
            "cycle": cycle,
            "transaction_success": False,
            "mining_success": False,
            "propagation_success": False,
            "start_time": time.time(),
            "errors": []
        }
        
        try:
            # Step 1: Get initial blockchain status
            initial_status = self.get_blockchain_status()
            initial_height = None
            
            for node_id, status in initial_status.items():
                if "error" not in status:
                    initial_height = status["height"]
                    break
            
            if initial_height is None:
                cycle_results["errors"].append("Could not determine initial height")
                return cycle_results
            
            # Step 2: Create and broadcast transaction
            receiver = f"bqs1cycle{cycle:03d}receiver00000000000000000000"
            amount = Decimal(f"{10 + (cycle % 50)}")  # Vary amounts between 10-59
            
            tx_id = self.create_and_broadcast_transaction(
                self.wallet_file, receiver, amount, self.wallet_password
            )
            
            if tx_id:
                cycle_results["transaction_success"] = True
                cycle_results["tx_id"] = tx_id
                
                # Wait for transaction propagation
                time.sleep(2)
                
                # Check transaction propagation
                tx_counts = self.check_transaction_propagation(1)
                propagated_nodes = sum(1 for count in tx_counts.values() if count > 0)
                cycle_results["tx_propagation_nodes"] = propagated_nodes
                
                # Step 3: Mine block using cpuminer-opt with real block submission
                mining_result = self.mine_with_cpuminer(timeout_seconds=60)
                
                if mining_result:
                    cycle_results["mining_success"] = True
                    cycle_results["mining_result"] = mining_result
                    cycle_results["block_submitted"] = mining_result.get("submitted", False)
                    
                    # Step 4: Verify block propagation across all nodes
                    if mining_result.get("submitted", False):
                        # Block was successfully mined and submitted by cpuminer
                        new_height = mining_result.get("height", initial_height)
                        
                        # Verify propagation across all nodes
                        propagation_results = self.verify_blockchain_height_propagation(new_height, max_wait=10)
                        
                        cycle_results["propagation_success"] = propagation_results["propagation_success"]
                        cycle_results["propagation_details"] = propagation_results
                        cycle_results["height_increased"] = new_height > initial_height
                        cycle_results["new_height"] = new_height
                        cycle_results["propagation_time"] = propagation_results["propagation_time"]
                        
                        if propagation_results["propagation_success"] and cycle_results["height_increased"]:
                            # Block successfully propagated across network
                            self.log(f"Block propagated successfully to all nodes in {propagation_results['propagation_time']:.1f}s", "SUCCESS")
                        else:
                            failed_details = []
                            for node, height in propagation_results["node_heights"].items():
                                if height < new_height:
                                    failed_details.append(f"{node}:{height}")
                            if failed_details:
                                cycle_results["errors"].append(f"Block propagation incomplete: {failed_details}")
                    else:
                        # Mining timed out or failed
                        cycle_results["propagation_success"] = False
                        timeout_msg = "timeout" if mining_result.get("timeout", False) else "failed"
                        cycle_results["errors"].append(f"Mining {timeout_msg} - no block found in 30s")
                        
                        # Still check network responsiveness
                        propagation_results = self.verify_blockchain_height_propagation(initial_height, max_wait=5)
                        cycle_results["propagation_details"] = propagation_results
                else:
                    cycle_results["errors"].append("cpuminer-opt failed to start")
            else:
                cycle_results["errors"].append("Transaction creation failed")
                
        except Exception as e:
            cycle_results["errors"].append(str(e))
        
        cycle_results["duration"] = time.time() - cycle_results["start_time"]
        
        return cycle_results

    def print_progress_report(self, cycles_completed: int, results: List[Dict]):
        """Print progress report every 10 cycles"""
        if cycles_completed % 10 != 0:
            return
            
        successful_txs = sum(1 for r in results if r["transaction_success"])
        successful_mining = sum(1 for r in results if r["mining_success"])
        successful_propagation = sum(1 for r in results if r["propagation_success"])
        successful_block_submission = sum(1 for r in results if r.get("block_submitted", False))
        height_increases = sum(1 for r in results if r.get("height_increased", False))
        
        tx_rate = (successful_txs / cycles_completed) * 100
        mining_rate = (successful_mining / cycles_completed) * 100
        propagation_rate = (successful_propagation / cycles_completed) * 100
        submission_rate = (successful_block_submission / cycles_completed) * 100
        height_rate = (height_increases / cycles_completed) * 100
        
        avg_duration = sum(r.get("duration", 0) for r in results) / len(results)
        
        # Calculate average propagation time for successful propagations
        propagation_times = [r.get("propagation_time", 0) for r in results if r.get("propagation_success", False)]
        avg_propagation_time = sum(propagation_times) / len(propagation_times) if propagation_times else 0
        
        self.log(f"PROGRESS REPORT - Cycle {cycles_completed}/100", "STATS")
        self.log(f"Transaction success: {successful_txs}/{cycles_completed} ({tx_rate:.1f}%)", "INFO")
        self.log(f"Mining success: {successful_mining}/{cycles_completed} ({mining_rate:.1f}%)", "INFO")
        self.log(f"Block submission: {successful_block_submission}/{cycles_completed} ({submission_rate:.1f}%)", "INFO")
        self.log(f"Block propagation: {successful_propagation}/{cycles_completed} ({propagation_rate:.1f}%)", "INFO")
        self.log(f"Height increases: {height_increases}/{cycles_completed} ({height_rate:.1f}%)", "INFO")
        self.log(f"Average cycle time: {avg_duration:.1f}s, propagation: {avg_propagation_time:.1f}s", "INFO")

    def run_100_cycle_test(self, num_cycles=100):
        """Run the complete test with specified number of cycles"""
        self.log(f"🚀 Starting {num_cycles}-Cycle qBTC Network Test with cpuminer-opt", "TEST")
        self.log("=" * 80, "INFO")
        
        # Step 1: Start Docker Compose with rate limiting disabled
        self.log("Checking Docker Compose status...", "NETWORK")
        try:
            # Check if containers are already running
            check_result = subprocess.run(["docker", "compose", "ps", "-q"], 
                                        capture_output=True, text=True)
            if check_result.stdout.strip():
                self.log("Docker Compose already running, using existing containers", "SUCCESS")
            else:
                self.log("Starting Docker Compose 3-node test network...", "NETWORK")
                subprocess.run(["docker", "compose", "down"], 
                             capture_output=True, text=True)
                result = subprocess.run(["docker", "compose", "up", "--build", "-d"], 
                                      check=True, capture_output=True, text=True)
                self.log("Docker Compose started successfully", "SUCCESS")
        except subprocess.CalledProcessError as e:
            self.log(f"Failed to start Docker Compose: {e}", "ERROR")
            self.log(f"Error output: {e.stderr if hasattr(e, 'stderr') else 'No error details'}", "ERROR")
            return
        
        # If no wallet was specified, use the bootstrap node's wallet from Docker
        if self.wallet_file is None or self.wallet_file == "wallet.json":
            self.log("Using bootstrap node's wallet for testing", "WALLET")
            # Wait a bit for containers to create their wallets
            time.sleep(5)
            # Extract wallet from bootstrap container
            try:
                # Copy wallet from container
                subprocess.run(["docker", "cp", "qbtc-bootstrap:/app/bootstrap.json", "./test_wallet.json"], 
                             check=True, capture_output=True)
                self.wallet_file = "./test_wallet.json"
                self.wallet_password = "bootstrappass"  # Known password from docker-compose.yml
                self.log("Extracted bootstrap wallet for testing", "SUCCESS")
            except subprocess.CalledProcessError as e:
                self.log(f"Failed to extract wallet from container: {e}", "ERROR")
                self.log("Make sure Docker containers are running", "INFO")
                return
        else:
            # Using external wallet (e.g., admin wallet)
            self.log(f"Using external wallet: {self.wallet_file}", "WALLET")
        
        # Step 2: Wait for nodes to be ready
        if not self.wait_for_nodes_ready():
            self.log("Nodes failed to start properly", "ERROR")
            return
        
        # Step 3: Mine some initial blocks to generate coins
        self.log("Mining initial blocks to generate coins...", "MINING")
        initial_mining_result = self.mine_with_cpuminer(timeout_seconds=30)
        if initial_mining_result:
            self.log(f"Successfully mined initial block at height {initial_mining_result['height']}", "SUCCESS")
            # Mine a few more blocks to ensure coins are available
            for i in range(5):
                time.sleep(1)
                result = self.mine_with_cpuminer(timeout_seconds=30)
                if result:
                    self.log(f"Mined block {i+2} at height {result['height']}", "SUCCESS")
        else:
            self.log("Failed to mine initial blocks - continuing anyway", "WARNING")
        
        # Step 4: Run test cycles
        self.log(f"Starting {num_cycles} test cycles...", "TEST")
        self.log("Testing full lifecycle: TX creation → cpuminer-opt mining → Block propagation verification", "INFO")
        
        start_time = time.time()
        
        for cycle in range(1, num_cycles + 1):
            # Show cycle start every 10 cycles or for first few
            if cycle <= 5 or cycle % 10 == 0:
                self.log(f"--- CYCLE {cycle} ---", "CYCLE")
            
            result = self.run_single_cycle(cycle)
            self.test_results.append(result)
            
            # Show quick status for early cycles
            if cycle <= 5:
                status = "✅" if result["transaction_success"] else "❌"
                mining = "⛏️✅" if result["mining_success"] else "⛏️❌"
                duration = result.get('duration', 0)
                self.log(f"Cycle {cycle}: TX{status} Mining{mining} ({duration:.1f}s)", "INFO")
            
            # Print progress report every 10 cycles
            self.print_progress_report(cycle, self.test_results)
            
            # Small delay to prevent overwhelming the system
            time.sleep(0.5)
        
        total_time = time.time() - start_time
        
        # Step 4: Generate final comprehensive report
        self.generate_comprehensive_report(total_time, num_cycles)

    def generate_comprehensive_report(self, total_time: float, num_cycles: int):
        """Generate comprehensive test report"""
        self.log("=" * 80, "INFO")
        self.log(f"📊 {num_cycles}-CYCLE COMPREHENSIVE TEST REPORT", "TEST")
        self.log("=" * 80, "INFO")
        
        successful_txs = [r for r in self.test_results if r["transaction_success"]]
        successful_mining = [r for r in self.test_results if r["mining_success"]]
        successful_submission = [r for r in self.test_results if r.get("block_submitted", False)]
        successful_propagation = [r for r in self.test_results if r["propagation_success"]]
        height_increases = [r for r in self.test_results if r.get("height_increased", False)]
        
        # Overall statistics
        total_tests = len(self.test_results)
        tx_rate = (len(successful_txs) / total_tests) * 100
        mining_rate = (len(successful_mining) / total_tests) * 100
        submission_rate = (len(successful_submission) / total_tests) * 100
        propagation_rate = (len(successful_propagation) / total_tests) * 100
        height_rate = (len(height_increases) / total_tests) * 100
        
        self.log(f"Total test cycles completed: {total_tests}", "STATS")
        self.log(f"Total test duration: {total_time/60:.1f} minutes", "STATS")
        self.log(f"Average time per cycle: {total_time/total_tests:.1f}s", "STATS")
        
        self.log("", "INFO")
        self.log("SUCCESS RATES:", "STATS")
        emoji_tx = "✅" if tx_rate > 90 else "⚠️" if tx_rate > 70 else "❌"
        emoji_mining = "✅" if mining_rate > 80 else "⚠️" if mining_rate > 60 else "❌"
        emoji_submission = "✅" if submission_rate > 80 else "⚠️" if submission_rate > 60 else "❌"
        emoji_prop = "✅" if propagation_rate > 90 else "⚠️" if propagation_rate > 70 else "❌"
        emoji_height = "✅" if height_rate > 80 else "⚠️" if height_rate > 60 else "❌"
        
        self.log(f"{emoji_tx} Transaction success: {tx_rate:.1f}% ({len(successful_txs)}/{total_tests})", "STATS")
        self.log(f"{emoji_mining} Mining success: {mining_rate:.1f}% ({len(successful_mining)}/{total_tests})", "STATS")
        self.log(f"{emoji_submission} Block submission: {submission_rate:.1f}% ({len(successful_submission)}/{total_tests})", "STATS")
        self.log(f"{emoji_prop} Block propagation: {propagation_rate:.1f}% ({len(successful_propagation)}/{total_tests})", "STATS")
        self.log(f"{emoji_height} Blockchain height increases: {height_rate:.1f}% ({len(height_increases)}/{total_tests})", "STATS")
        
        # Performance analysis
        if successful_txs:
            durations = [r["duration"] for r in successful_txs]
            avg_duration = sum(durations) / len(durations)
            min_duration = min(durations)
            max_duration = max(durations)
            
            self.log("", "INFO")
            self.log("PERFORMANCE ANALYSIS:", "STATS")
            self.log(f"Average cycle duration: {avg_duration:.1f}s", "INFO")
            self.log(f"Fastest cycle: {min_duration:.1f}s", "INFO")
            self.log(f"Slowest cycle: {max_duration:.1f}s", "INFO")
        
        # Mining analysis
        if successful_mining:
            mining_times = [r["mining_result"].get("mining_time", 0) for r in successful_mining if "mining_result" in r]
            if mining_times:
                avg_mining_time = sum(mining_times) / len(mining_times)
                min_mining_time = min(mining_times)
                max_mining_time = max(mining_times)
                
                self.log("", "INFO")
                self.log("MINING ANALYSIS:", "STATS")
                self.log(f"Average mining time: {avg_mining_time:.1f}s", "INFO")
                self.log(f"Fastest block found: {min_mining_time:.1f}s", "INFO")
                self.log(f"Slowest block found: {max_mining_time:.1f}s", "INFO")
        
        # Error analysis
        all_errors = []
        for result in self.test_results:
            all_errors.extend(result.get("errors", []))
        
        if all_errors:
            error_counts = {}
            for error in all_errors:
                error_counts[error] = error_counts.get(error, 0) + 1
            
            self.log("", "INFO")
            self.log("ERROR ANALYSIS:", "STATS")
            for error, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                self.log(f"  {error}: {count} occurrences", "WARNING")
        
        # Transaction propagation analysis
        tx_propagation_data = [r.get("tx_propagation_nodes", 0) for r in successful_txs]
        if tx_propagation_data:
            avg_propagation = sum(tx_propagation_data) / len(tx_propagation_data)
            self.log("", "INFO")
            self.log("TRANSACTION PROPAGATION ANALYSIS:", "STATS")
            self.log(f"Average nodes receiving transactions: {avg_propagation:.1f}/3", "INFO")
        
        # Block propagation analysis
        if successful_propagation:
            propagation_times = [r.get("propagation_time", 0) for r in successful_propagation]
            avg_block_propagation_time = sum(propagation_times) / len(propagation_times)
            min_block_propagation = min(propagation_times)
            max_block_propagation = max(propagation_times)
            
            self.log("", "INFO")
            self.log("BLOCK PROPAGATION ANALYSIS:", "STATS")
            self.log(f"Average block propagation time: {avg_block_propagation_time:.1f}s", "INFO")
            self.log(f"Fastest block propagation: {min_block_propagation:.1f}s", "INFO")
            self.log(f"Slowest block propagation: {max_block_propagation:.1f}s", "INFO")
            
            # Analyze height increases
            height_data = [r.get("new_height", -1) for r in height_increases if r.get("new_height", -1) > 0]
            if height_data:
                initial_height = min(height_data) - len(height_data) + 1 if height_data else 0
                final_height = max(height_data) if height_data else 0
                height_gained = final_height - initial_height if initial_height > 0 else len(height_data)
                self.log(f"Blockchain height increased by: {height_gained} blocks", "INFO")
        
        # Final blockchain state
        final_status = self.get_blockchain_status()
        self.log("", "INFO")
        self.log("FINAL BLOCKCHAIN STATE:", "BLOCK")
        for node_id, status in final_status.items():
            if "error" not in status:
                self.log(f"  {node_id}: height {status['height']}, {status['transactions']} pending txs", "INFO")
            else:
                self.log(f"  {node_id}: {status['error']}", "ERROR")
        
        # Overall assessment
        self.log("", "INFO")
        self.log("OVERALL ASSESSMENT:", "TEST")
        
        # Enhanced assessment including block propagation
        overall_score = (tx_rate + mining_rate + submission_rate + propagation_rate + height_rate) / 5
        
        if overall_score > 90 and propagation_rate > 85 and height_rate > 80:
            self.log("🎉 EXCELLENT - Network demonstrates exceptional stability with full block propagation", "SUCCESS")
        elif overall_score > 80 and propagation_rate > 70 and height_rate > 65:
            self.log("✅ GOOD - Network shows strong performance with reliable block propagation", "SUCCESS")
        elif overall_score > 65 and propagation_rate > 50 and height_rate > 45:
            self.log("⚠️ ACCEPTABLE - Network functional with some block propagation issues", "WARNING")
        else:
            self.log("❌ NEEDS IMPROVEMENT - Network has significant block propagation problems", "ERROR")
        
        self.log(f"Overall network score: {overall_score:.1f}%", "STATS")
        
        self.log("", "INFO")
        self.log(f"🎯 {num_cycles}-CYCLE TEST COMPLETED!", "TEST")
        self.log("✅ qBTC network has undergone comprehensive testing with real mining", "SUCCESS")
        
        # Clean up test wallet if we extracted it
        if self.wallet_file == "./test_wallet.json":
            try:
                import os
                os.remove("./test_wallet.json")
                self.log("Cleaned up test wallet file", "INFO")
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="qBTC Network Test with Real cpuminer-opt Mining")
    parser.add_argument("--cycles", type=int, default=10, 
                       help="Number of test cycles to run (default: 10)")
    parser.add_argument("--mining-timeout", type=int, default=30,
                       help="Mining timeout per cycle in seconds (default: 30)")
    parser.add_argument("--wallet", type=str, default="wallet.json",
                       help="Path to wallet file (default: wallet.json)")
    parser.add_argument("--password", type=str, default=None,
                       help="Wallet password (will prompt if not provided)")
    parser.add_argument("--use-admin-wallet", action="store_true",
                       help="Use the admin wallet for testing (must specify --wallet path)")
    parser.add_argument("--admin-address", type=str, default=None,
                       help="Override the admin address (also sets ADMIN_ADDRESS env var)")
    
    args = parser.parse_args()
    
    # Set admin address if provided
    if args.admin_address:
        import os
        os.environ["ADMIN_ADDRESS"] = args.admin_address
        print(f"Setting ADMIN_ADDRESS to: {args.admin_address}")
    
    # Get wallet password if not provided
    wallet_password = args.password
    if wallet_password is None and args.wallet != "wallet.json":
        import getpass
        wallet_password = getpass.getpass("Enter wallet password: ")
    
    # Default node configurations
    web_nodes = ["http://localhost:8080", "http://localhost:8081", "http://localhost:8082"]
    rpc_nodes = ["http://localhost:8332", "http://localhost:8333", "http://localhost:8334"]
    
    # Create test instance
    test = Full100CycleTest(web_nodes, rpc_nodes, args.wallet, wallet_password)
    
    # Run test with specified number of cycles
    test.run_100_cycle_test(args.cycles)

if __name__ == "__main__":
    main()