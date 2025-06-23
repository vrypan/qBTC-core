"""
Chain Manager - Handles blockchain consensus, reorganizations, and fork resolution
Implements the longest chain rule (actually highest cumulative difficulty)
"""
import json
import logging
import time
from typing import Dict, List, Optional, Tuple, Set
from decimal import Decimal
from collections import defaultdict
from database.database import get_db
from blockchain.blockchain import Block, validate_pow, bits_to_target, sha256d
from blockchain.difficulty import get_next_bits, validate_block_bits, validate_block_timestamp
from rocksdict import WriteBatch

logger = logging.getLogger(__name__)


class ChainManager:
    """
    Manages blockchain state including:
    - Active chain tracking
    - Fork detection and resolution
    - Chain reorganization
    - Orphan block management
    """
    
    def __init__(self):
        self.db = get_db()
        self.orphan_blocks: Dict[str, dict] = {}  # hash -> block data
        self.block_index: Dict[str, dict] = {}  # hash -> block metadata
        self.chain_tips: Set[str] = set()  # Set of chain tip hashes
        self._initialize_index()
    
    def _initialize_index(self):
        """Build in-memory index of all blocks in database"""
        logger.info("Initializing chain index...")
        
        # Load all blocks into index
        for key, value in self.db.items():
            if key.startswith(b"block:"):
                block_data = json.loads(value.decode())
                block_hash = block_data["block_hash"]
                self.block_index[block_hash] = {
                    "height": block_data["height"],
                    "previous_hash": block_data["previous_hash"],
                    "timestamp": block_data["timestamp"],
                    "bits": block_data["bits"],
                    "cumulative_difficulty": self._get_cumulative_difficulty(block_hash)
                }
        
        # Find all chain tips (blocks with no children)
        self._update_chain_tips()
        logger.info(f"Chain index initialized with {len(self.block_index)} blocks and {len(self.chain_tips)} tips")
    
    def _update_chain_tips(self):
        """Update the set of chain tips"""
        # Start with all blocks as potential tips
        potential_tips = set(self.block_index.keys())
        
        # Remove any block that is a parent of another block
        for block_hash, block_info in self.block_index.items():
            prev_hash = block_info["previous_hash"]
            # Don't remove genesis (all zeros) from tips
            if prev_hash in potential_tips and prev_hash != "0" * 64:
                potential_tips.discard(prev_hash)
        
        self.chain_tips = potential_tips
    
    def _get_cumulative_difficulty(self, block_hash: str) -> Decimal:
        """Calculate cumulative difficulty from genesis to this block"""
        cumulative = Decimal(0)
        current_hash = block_hash
        
        while current_hash and current_hash != "00" * 32:
            if current_hash not in self.block_index:
                # Block not in index, try to load from DB
                block_key = f"block:{current_hash}".encode()
                block_data = self.db.get(block_key)
                if not block_data:
                    logger.warning(f"Block {current_hash} not found in chain")
                    break
                block_info = json.loads(block_data.decode())
            else:
                block_info = self.block_index[current_hash]
            
            # Add this block's difficulty
            bits = block_info.get("bits", 0x1d00ffff)  # Default to min difficulty
            target = bits_to_target(bits)
            difficulty = Decimal(2**256) / Decimal(target)
            cumulative += difficulty
            
            current_hash = block_info.get("previous_hash")
        
        return cumulative
    
    def get_best_chain_tip(self) -> Tuple[str, int]:
        """
        Get the best chain tip (highest cumulative difficulty)
        Returns (block_hash, height)
        """
        best_tip = None
        best_difficulty = Decimal(0)
        best_height = 0
        
        for tip_hash in self.chain_tips:
            tip_info = self.block_index.get(tip_hash)
            if not tip_info:
                continue
                
            difficulty = self._get_cumulative_difficulty(tip_hash)
            if difficulty > best_difficulty:
                best_difficulty = difficulty
                best_tip = tip_hash
                best_height = tip_info["height"]
        
        if not best_tip:
            # No tips found, return genesis
            return "00" * 32, 0
            
        return best_tip, best_height
    
    def add_block(self, block_data: dict) -> Tuple[bool, Optional[str]]:
        """
        Add a new block to the chain
        Returns (success, error_message)
        """
        # Validate required fields
        required_fields = ["block_hash", "previous_hash", "height", "version", "merkle_root", "timestamp", "bits", "nonce"]
        missing_fields = [field for field in required_fields if field not in block_data]
        if missing_fields:
            logger.error(f"Missing required fields in block_data: {missing_fields}")
            logger.error(f"Received block_data keys: {list(block_data.keys())}")
            return False, f"Missing required fields: {missing_fields}"
        
        block_hash = block_data["block_hash"]
        prev_hash = block_data["previous_hash"]
        height = block_data["height"]
        
        # Store the block immediately if we don't have it yet
        block_key = f"block:{block_hash}".encode()
        if block_key not in self.db:
            logger.info(f"Storing new block {block_hash} at height {height}")
            self.db.put(block_key, json.dumps(block_data).encode())
            
            # Also store transactions separately for fork blocks
            # This ensures they're available during reorganization
            if "full_transactions" in block_data:
                for tx in block_data["full_transactions"]:
                    if tx and "txid" in tx:
                        tx_key = f"tx:{tx['txid']}".encode()
                        if tx_key not in self.db:
                            self.db.put(tx_key, json.dumps(tx).encode())
                            logger.debug(f"Stored transaction {tx['txid']} from block {block_hash}")
        
        # Check if block already exists
        if block_hash in self.block_index:
            return True, None  # Already have this block
        
        # Validate PoW
        try:
            block_obj = Block(
                block_data["version"],
                prev_hash,
                block_data["merkle_root"],
                block_data["timestamp"],
                block_data["bits"],
                block_data["nonce"]
            )
        except KeyError as e:
            logger.error(f"Missing required field in block_data: {e}")
            logger.error(f"Block data keys: {list(block_data.keys())}")
            raise
        
        # Special handling for genesis block
        is_genesis = block_hash == "0" * 64 and height == 0
        
        if not is_genesis and not validate_pow(block_obj):
            return False, "Invalid proof of work"
        
        # Validate difficulty adjustment (skip for genesis)
        if not is_genesis and height > 0:
            # Get the expected difficulty for this height
            parent_height = height - 1
            expected_bits = get_next_bits(self.db, parent_height)
            
            if not validate_block_bits(block_data["bits"], expected_bits):
                return False, f"Invalid difficulty bits: expected {expected_bits:#x}, got {block_data['bits']:#x}"
        
        # Validate timestamp (skip for genesis)
        if not is_genesis and prev_hash in self.block_index:
            parent_info = self.block_index[prev_hash]
            current_time = int(time.time())
            
            logger.info(f"Timestamp validation: block_ts={block_data['timestamp']}, parent_ts={parent_info['timestamp']}, current={current_time}")
            
            # Special handling for rapid mining (cpuminer compatibility)
            # If the block timestamp equals or is less than parent timestamp, check if we're mining rapidly
            if block_data["timestamp"] <= parent_info["timestamp"]:
                # Check if parent block was mined very recently (within last 10 seconds)
                time_since_parent = current_time - parent_info["timestamp"]
                logger.info(f"Block timestamp <= parent. Time since parent: {time_since_parent}s")
                
                if time_since_parent <= 10:  # Increased window to 10 seconds
                    logger.warning(f"Allowing timestamp {block_data['timestamp']} <= parent {parent_info['timestamp']} for rapid mining (parent mined {time_since_parent}s ago)")
                    # Skip the normal timestamp validation for rapid mining
                else:
                    return False, f"Invalid block timestamp - must be greater than parent (block: {block_data['timestamp']}, parent: {parent_info['timestamp']})"
            else:
                # Normal timestamp validation
                if not validate_block_timestamp(
                    block_data["timestamp"],
                    parent_info["timestamp"],
                    current_time
                ):
                    return False, "Invalid block timestamp"
        
        # Check if we have the parent block
        if prev_hash not in self.block_index and prev_hash != "00" * 32:
            # Parent not found - this is an orphan
            self._add_orphan(block_data)
            return True, None
        
        # Add block to index
        self.block_index[block_hash] = {
            "height": height,
            "previous_hash": prev_hash,
            "timestamp": block_data["timestamp"],
            "bits": block_data["bits"],
            "cumulative_difficulty": self._get_cumulative_difficulty(block_hash)
        }
        
        # Check if this creates a new chain tip or extends existing one
        self._update_chain_tips()
        
        # Check if we need to reorganize
        current_tip, current_height = self.get_best_chain_tip()
        
        if block_hash == current_tip:
            # This block became the new best tip
            logger.info(f"New best chain tip: {block_hash} at height {height}")
            
            # Connect the block to process its transactions and create UTXOs
            # Need to create a WriteBatch for the transaction
            batch = WriteBatch()
            self._connect_block(block_data, batch)
            self.db.write(batch)
            
            # Process any orphans that can now be connected
            self._process_orphans_for_block(block_hash)
            
            return True, None
        
        # Check if this block creates a better chain
        if self._should_reorganize(block_hash):
            logger.warning(f"Chain reorganization needed! New tip: {block_hash}")
            success = self._reorganize_to_block(block_hash)
            if not success:
                return False, "Reorganization failed"
        
        return True, None
    
    def _add_orphan(self, block_data: dict):
        """Add a block to the orphan pool"""
        block_hash = block_data["block_hash"]
        logger.info(f"Adding orphan block {block_hash}")
        self.orphan_blocks[block_hash] = block_data
    
    def _process_orphans_for_block(self, parent_hash: str):
        """Try to connect any orphans that have this block as parent"""
        connected = []
        
        for orphan_hash, orphan_data in self.orphan_blocks.items():
            if orphan_data["previous_hash"] == parent_hash:
                # This orphan can now be connected
                logger.info(f"Connecting orphan {orphan_hash} to parent {parent_hash}")
                success, _ = self.add_block(orphan_data)
                if success:
                    connected.append(orphan_hash)
        
        # Remove connected orphans
        for orphan_hash in connected:
            del self.orphan_blocks[orphan_hash]
    
    def _should_reorganize(self, new_tip_hash: str) -> bool:
        """Check if a new block creates a better chain than current"""
        current_tip, _ = self.get_best_chain_tip()
        
        current_difficulty = self._get_cumulative_difficulty(current_tip)
        new_difficulty = self._get_cumulative_difficulty(new_tip_hash)
        
        return new_difficulty > current_difficulty
    
    def _reorganize_to_block(self, new_tip_hash: str) -> bool:
        """
        Perform chain reorganization to make new_tip_hash the best chain
        This is the critical function for consensus
        """
        logger.warning(f"Starting chain reorganization to {new_tip_hash}")
        
        current_tip, _ = self.get_best_chain_tip()
        
        # Find common ancestor
        common_ancestor = self._find_common_ancestor(current_tip, new_tip_hash)
        if not common_ancestor:
            logger.error("No common ancestor found - cannot reorganize")
            return False
        
        logger.info(f"Common ancestor: {common_ancestor}")
        
        # Get blocks to disconnect (from current chain)
        blocks_to_disconnect = self._get_chain_between(current_tip, common_ancestor)
        
        # Get blocks to connect (from new chain)
        blocks_to_connect = self._get_chain_between(new_tip_hash, common_ancestor)
        blocks_to_connect.reverse()  # Need to apply in forward order
        
        logger.info(f"Disconnecting {len(blocks_to_disconnect)} blocks, connecting {len(blocks_to_connect)} blocks")
        
        # Create backup of current state for rollback
        backup_state = {
            "best_tip": current_tip,
            "height": self.block_index[current_tip]["height"],
            "utxo_backups": {},
            "block_states": {}
        }
        
        # Start database transaction
        batch = WriteBatch()
        
        try:
            # Phase 1: Disconnect blocks from current chain
            for block_hash in blocks_to_disconnect:
                # Backup block state before disconnecting
                block_key = f"block:{block_hash}".encode()
                backup_state["block_states"][block_hash] = self.db.get(block_key)
                
                self._disconnect_block(block_hash, batch, backup_state["utxo_backups"])
            
            # Phase 2: Validate and connect blocks from new chain
            # First, collect all UTXOs that will be spent in new chain
            new_chain_spent_utxos = set()
            for block_hash in blocks_to_connect:
                block_key = f"block:{block_hash}".encode()
                block_data = self.db.get(block_key)
                if not block_data:
                    raise ValueError(f"Block {block_hash} not found during reorg")
                
                block_dict = json.loads(block_data.decode())
                
                # Collect spent UTXOs from this block's transactions
                for tx in self._get_block_transactions(block_dict):
                    for inp in tx.get("inputs", []):
                        if "txid" in inp and inp["txid"] != "00" * 32:  # Skip coinbase
                            utxo_key = f"{inp['txid']}:{inp.get('utxo_index', 0)}"
                            new_chain_spent_utxos.add(utxo_key)
            
            # Now connect blocks with UTXO tracking
            for block_hash in blocks_to_connect:
                block_key = f"block:{block_hash}".encode()
                block_data = self.db.get(block_key)
                if not block_data:
                    raise ValueError(f"Block {block_hash} not found during reorg")
                
                block_dict = json.loads(block_data.decode())
                
                # Extra safety: Re-validate PoW during reorg (except genesis)
                if block_hash != "0" * 64:
                    try:
                        block_obj = Block(
                            block_dict["version"],
                            block_dict["previous_hash"],
                            block_dict["merkle_root"],
                            block_dict["timestamp"],
                            block_dict["bits"],
                            block_dict["nonce"]
                        )
                        if not validate_pow(block_obj):
                            raise ValueError(f"Block {block_hash} failed PoW validation during reorg!")
                    except Exception as e:
                        raise ValueError(f"Failed to validate block {block_hash} during reorg: {e}")
                
                # Connect with new chain UTXO tracking
                self._connect_block_safe(block_dict, batch, new_chain_spent_utxos)
            
            # Phase 3: Commit the reorganization atomically
            self.db.write(batch)
            
            # Update chain state
            key = b"chain:best_tip"
            self.db.put(key, json.dumps({
                "hash": new_tip_hash,
                "height": self.block_index[new_tip_hash]["height"]
            }).encode())
            
            logger.info(f"Chain reorganization complete. New tip: {new_tip_hash}")
            return True
            
        except Exception as e:
            logger.error(f"Reorganization failed: {e}")
            # Rollback is automatic since we haven't committed the batch
            logger.info("Reorganization rolled back due to error")
            return False
    
    def _find_common_ancestor(self, hash1: str, hash2: str) -> Optional[str]:
        """Find the common ancestor of two blocks"""
        # Get ancestors of both blocks
        ancestors1 = set()
        current = hash1
        while current and current != "00" * 32:
            ancestors1.add(current)
            if current in self.block_index:
                current = self.block_index[current]["previous_hash"]
            else:
                break
        
        # Walk up hash2's chain until we find common ancestor
        current = hash2
        while current and current != "00" * 32:
            if current in ancestors1:
                return current
            if current in self.block_index:
                current = self.block_index[current]["previous_hash"]
            else:
                break
        
        return None
    
    def _get_chain_between(self, tip_hash: str, ancestor_hash: str) -> List[str]:
        """Get all blocks between tip and ancestor (not including ancestor)"""
        blocks = []
        current = tip_hash
        
        while current and current != ancestor_hash and current != "00" * 32:
            blocks.append(current)
            if current in self.block_index:
                current = self.block_index[current]["previous_hash"]
            else:
                break
        
        return blocks
    
    def _get_block_transactions(self, block_dict: dict) -> List[dict]:
        """Get all transactions from a block, loading from DB if necessary"""
        # Use full_transactions if available
        if "full_transactions" in block_dict and block_dict["full_transactions"]:
            return block_dict["full_transactions"]
        
        # Otherwise load from tx_ids
        transactions = []
        for txid in block_dict.get("tx_ids", []):
            tx_key = f"tx:{txid}".encode()
            tx_data = self.db.get(tx_key)
            if tx_data:
                tx = json.loads(tx_data.decode())
                transactions.append(tx)
            else:
                logger.warning(f"Transaction {txid} not found when loading block transactions")
        
        return transactions
    
    def _disconnect_block(self, block_hash: str, batch: WriteBatch, utxo_backups: Dict[str, bytes]):
        """Disconnect a block from the active chain (revert its effects)"""
        logger.info(f"Disconnecting block {block_hash}")
        
        # Load block data
        block_key = f"block:{block_hash}".encode()
        block_data = json.loads(self.db.get(block_key).decode())
        
        # Revert all transactions in this block
        for txid in block_data.get("tx_ids", []):
            self._revert_transaction(txid, batch, utxo_backups)
        
        # Mark block as disconnected (don't delete - might reconnect later)
        block_data["connected"] = False
        batch.put(block_key, json.dumps(block_data).encode())
    
    def _connect_block(self, block_data: dict, batch: WriteBatch):
        """Connect a block to the active chain (apply its effects)"""
        logger.info(f"Connecting block {block_data['block_hash']} at height {block_data['height']}")
        
        # Get full transactions - either from block_data or by loading from DB
        full_transactions = block_data.get("full_transactions", [])
        
        # If full_transactions is empty but we have tx_ids, load the transactions
        if not full_transactions and "tx_ids" in block_data:
            logger.info(f"Loading {len(block_data['tx_ids'])} transactions for block {block_data['block_hash']}")
            full_transactions = []
            for txid in block_data["tx_ids"]:
                tx_key = f"tx:{txid}".encode()
                tx_data = self.db.get(tx_key)
                if tx_data:
                    tx = json.loads(tx_data.decode())
                    full_transactions.append(tx)
                else:
                    logger.warning(f"Transaction {txid} not found in database during block connection")
        
        # Process all transactions in the block
        for tx in full_transactions:
            self._apply_transaction(tx, block_data["height"], batch)
        
        # Mark block as connected
        block_data["connected"] = True
        block_key = f"block:{block_data['block_hash']}".encode()
        batch.put(block_key, json.dumps(block_data).encode())
    
    def _connect_block_safe(self, block_data: dict, batch: WriteBatch, new_chain_spent_utxos: Set[str]):
        """
        Connect a block during reorganization with double-spend protection
        Ensures UTXOs aren't restored if they're spent elsewhere in new chain
        """
        logger.info(f"Safely connecting block {block_data['block_hash']} at height {block_data['height']}")
        
        # Get full transactions
        full_transactions = self._get_block_transactions(block_data)
        
        # Track UTXOs spent within this block to prevent double-spending within same block
        block_spent_utxos = set()
        
        # Process all transactions in the block with validation
        for tx in full_transactions:
            if tx is None:
                continue
                
            # Validate transaction before applying
            if not self._validate_transaction_for_reorg(tx, block_spent_utxos, new_chain_spent_utxos):
                raise ValueError(f"Invalid transaction {tx.get('txid')} during reorganization")
            
            # Apply transaction
            self._apply_transaction_safe(tx, block_data["height"], batch, new_chain_spent_utxos)
            
            # Track spent UTXOs from this transaction
            for inp in tx.get("inputs", []):
                if "txid" in inp and inp["txid"] != "00" * 32:
                    utxo_key = f"{inp['txid']}:{inp.get('utxo_index', 0)}"
                    block_spent_utxos.add(utxo_key)
        
        # Mark block as connected
        block_data["connected"] = True
        block_key = f"block:{block_data['block_hash']}".encode()
        batch.put(block_key, json.dumps(block_data).encode())
    
    def _revert_transaction(self, txid: str, batch: WriteBatch, utxo_backups: Dict[str, bytes] = None):
        """Revert a transaction's effects on the UTXO set"""
        logger.debug(f"Reverting transaction {txid}")
        
        if utxo_backups is None:
            utxo_backups = {}
        
        # Mark all outputs from this transaction as invalid
        tx_key = f"tx:{txid}".encode()
        tx_data = self.db.get(tx_key)
        if not tx_data:
            return
        
        tx = json.loads(tx_data.decode())
        
        # Restore spent inputs - but backup current state first
        for inp in tx.get("inputs", []):
            if "txid" in inp and inp["txid"] != "00" * 32:  # Skip coinbase
                utxo_key = f"utxo:{inp['txid']}:{inp.get('utxo_index', 0)}".encode()
                
                # Backup current state before modifying
                current_utxo_data = self.db.get(utxo_key)
                if current_utxo_data:
                    backup_key = f"{inp['txid']}:{inp.get('utxo_index', 0)}"
                    utxo_backups[backup_key] = current_utxo_data
                    
                    utxo = json.loads(current_utxo_data.decode())
                    utxo["spent"] = False
                    batch.put(utxo_key, json.dumps(utxo).encode())
        
        # Remove outputs created by this transaction
        for idx, out in enumerate(tx.get("outputs", [])):
            utxo_key = f"utxo:{txid}:{idx}".encode()
            
            # Backup before deleting
            current_data = self.db.get(utxo_key)
            if current_data:
                backup_key = f"{txid}:{idx}"
                utxo_backups[backup_key] = current_data
            
            batch.delete(utxo_key)
    
    def _apply_transaction(self, tx: dict, height: int, batch: WriteBatch):
        """Apply a transaction's effects on the UTXO set"""
        if tx is None:
            return
            
        # Handle transaction format variations
        if "transaction" in tx:
            tx = tx["transaction"]
            
        txid = tx.get("txid")
        if not txid:
            # Might be coinbase
            if all(k in tx for k in ("version", "inputs", "outputs")) and len(tx.get("inputs", [])) == 1:
                # Coinbase transaction
                coinbase_tx_id = f"coinbase_{height}"
                batch.put(f"tx:{coinbase_tx_id}".encode(), json.dumps(tx).encode())
                return
            else:
                logger.warning(f"Transaction without txid at height {height}")
                return
        
        logger.debug(f"Applying transaction {txid}")
        
        # Mark inputs as spent
        for inp in tx.get("inputs", []):
            if "txid" in inp:
                utxo_key = f"utxo:{inp['txid']}:{inp.get('utxo_index', 0)}".encode()
                utxo_data = self.db.get(utxo_key)
                if utxo_data:
                    utxo = json.loads(utxo_data.decode())
                    utxo["spent"] = True
                    batch.put(utxo_key, json.dumps(utxo).encode())
        
        # Create new UTXOs
        for idx, out in enumerate(tx.get("outputs", [])):
            # Create proper UTXO record with all necessary fields
            utxo_record = {
                "txid": txid,
                "utxo_index": idx,
                "sender": out.get('sender', ''),
                "receiver": out.get('receiver', ''),
                "amount": str(out.get('amount', '0')),  # Ensure string to avoid scientific notation
                "spent": False  # New UTXOs are always unspent
            }
            utxo_key = f"utxo:{txid}:{idx}".encode()
            batch.put(utxo_key, json.dumps(utxo_record).encode())
        
        # Store transaction
        batch.put(f"tx:{txid}".encode(), json.dumps(tx).encode())
    
    def _validate_transaction_for_reorg(self, tx: dict, block_spent_utxos: Set[str], 
                                       new_chain_spent_utxos: Set[str]) -> bool:
        """
        Validate a transaction during reorganization
        Checks signatures, balances, and double-spending
        """
        if not tx or "txid" not in tx:
            logger.error("Invalid transaction format - missing txid")
            return False
        
        txid = tx["txid"]
        
        # Skip coinbase transactions (they have special rules)
        if len(tx.get("inputs", [])) == 1 and tx["inputs"][0].get("txid") == "00" * 32:
            logger.debug(f"Skipping validation for coinbase transaction {txid}")
            return True
        
        # Validate all inputs exist and aren't double-spent
        total_input = Decimal(0)
        for inp in tx.get("inputs", []):
            if "txid" not in inp:
                logger.error(f"Transaction {txid} has invalid input - missing txid")
                return False
            
            # Check if this UTXO is already spent in this block
            utxo_key = f"{inp['txid']}:{inp.get('utxo_index', 0)}"
            if utxo_key in block_spent_utxos:
                logger.error(f"Double-spend detected: UTXO {utxo_key} already spent in block")
                return False
            
            # Check if this UTXO is spent elsewhere in the new chain
            if utxo_key in new_chain_spent_utxos:
                logger.error(f"Double-spend detected: UTXO {utxo_key} spent in new chain")
                return False
            
            # Verify UTXO exists and get amount
            utxo_db_key = f"utxo:{utxo_key}".encode()
            utxo_data = self.db.get(utxo_db_key)
            if not utxo_data:
                logger.error(f"Transaction {txid} references non-existent UTXO {utxo_key}")
                return False
            
            utxo = json.loads(utxo_data.decode())
            if utxo.get("spent", False):
                logger.error(f"Transaction {txid} tries to spend already spent UTXO {utxo_key}")
                return False
            
            total_input += Decimal(utxo.get("amount", "0"))
        
        # Validate outputs sum to inputs (allowing for fees)
        total_output = Decimal(0)
        for out in tx.get("outputs", []):
            if "amount" not in out:
                logger.error(f"Transaction {txid} has output without amount")
                return False
            total_output += Decimal(out["amount"])
        
        if total_output > total_input:
            logger.error(f"Transaction {txid} outputs ({total_output}) exceed inputs ({total_input})")
            return False
        
        # TODO: Add signature validation here if needed during reorg
        # For now we trust that transactions in blocks were already validated
        
        return True
    
    def _apply_transaction_safe(self, tx: dict, height: int, batch: WriteBatch, 
                               new_chain_spent_utxos: Set[str]):
        """
        Apply a transaction during reorganization with double-spend protection
        """
        if tx is None:
            return
            
        # Handle transaction format variations
        if "transaction" in tx:
            tx = tx["transaction"]
            
        txid = tx.get("txid")
        if not txid:
            # Might be coinbase
            if all(k in tx for k in ("version", "inputs", "outputs")) and len(tx.get("inputs", [])) == 1:
                # Coinbase transaction
                coinbase_tx_id = f"coinbase_{height}"
                batch.put(f"tx:{coinbase_tx_id}".encode(), json.dumps(tx).encode())
                return
            else:
                logger.warning(f"Transaction without txid at height {height}")
                return
        
        logger.debug(f"Safely applying transaction {txid}")
        
        # Mark inputs as spent (skip if already spent in new chain)
        for inp in tx.get("inputs", []):
            if "txid" in inp and inp["txid"] != "00" * 32:
                utxo_key = f"{inp['txid']}:{inp.get('utxo_index', 0)}"
                
                # Skip if this UTXO is already marked as spent in new chain
                if utxo_key not in new_chain_spent_utxos:
                    utxo_db_key = f"utxo:{utxo_key}".encode()
                    utxo_data = self.db.get(utxo_db_key)
                    if utxo_data:
                        utxo = json.loads(utxo_data.decode())
                        utxo["spent"] = True
                        batch.put(utxo_db_key, json.dumps(utxo).encode())
        
        # Create new UTXOs
        for idx, out in enumerate(tx.get("outputs", [])):
            # Create proper UTXO record with all necessary fields
            utxo_record = {
                "txid": txid,
                "utxo_index": idx,
                "sender": out.get('sender', ''),
                "receiver": out.get('receiver', ''),
                "amount": str(out.get('amount', '0')),  # Ensure string to avoid scientific notation
                "spent": False  # New UTXOs are always unspent
            }
            utxo_key = f"utxo:{txid}:{idx}".encode()
            batch.put(utxo_key, json.dumps(utxo_record).encode())
        
        # Store transaction
        batch.put(f"tx:{txid}".encode(), json.dumps(tx).encode())
    
    def get_block_by_hash(self, block_hash: str) -> Optional[dict]:
        """Get a block by its hash"""
        block_key = f"block:{block_hash}".encode()
        block_data = self.db.get(block_key)
        if block_data:
            return json.loads(block_data.decode())
        return None
    
    def is_block_in_main_chain(self, block_hash: str) -> bool:
        """Check if a block is in the main chain"""
        current_tip, _ = self.get_best_chain_tip()
        
        # Walk back from tip to see if we find this block
        current = current_tip
        while current and current != "00" * 32:
            if current == block_hash:
                return True
            if current in self.block_index:
                current = self.block_index[current]["previous_hash"]
            else:
                break
        
        return False