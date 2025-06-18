"""
Event-based WebSocket handlers
"""

import logging
import json
from datetime import datetime
from decimal import Decimal
from typing import Set, Dict

from events.event_bus import Event, EventTypes
from database.database import get_db

logger = logging.getLogger(__name__)


class WebSocketEventHandlers:
    """
    Event handlers for WebSocket notifications
    """
    
    def __init__(self, websocket_manager):
        self.websocket_manager = websocket_manager
        self.wallet_cache: Dict[str, Dict] = {}  # Cache wallet data to detect changes
        logger.info("WebSocketEventHandlers initialized")
    
    async def handle_transaction_confirmed(self, event: Event):
        """Handle confirmed transaction events"""
        try:
            tx_data = event.data
            txid = tx_data.get('txid')
            
            logger.info(f"Processing confirmed transaction: {txid}")
            
            # Update all_transactions subscribers
            await self._broadcast_all_transactions_update()
            
            # Update affected wallets
            affected_wallets = set()
            
            # Add sender and receiver from outputs
            for output in tx_data.get('outputs', []):
                sender = output.get('sender')
                receiver = output.get('receiver')
                if sender:
                    affected_wallets.add(sender)
                if receiver:
                    affected_wallets.add(receiver)
            
            # Update each affected wallet
            for wallet in affected_wallets:
                await self._broadcast_wallet_update(wallet)
                
        except Exception as e:
            logger.error(f"Error handling transaction confirmed: {e}")
    
    async def handle_transaction_pending(self, event: Event):
        """Handle pending transaction events"""
        try:
            tx_data = event.data
            
            # For now, we might not show pending transactions
            # But this could be extended to show pending status
            logger.debug(f"Pending transaction: {tx_data.get('txid')}")
            
        except Exception as e:
            logger.error(f"Error handling pending transaction: {e}")
    
    async def handle_block_added(self, event: Event):
        """Handle new block events"""
        try:
            block_data = event.data
            height = block_data.get('height')
            
            logger.info(f"New block added at height: {height}")
            
            # Update L1 proofs subscribers
            await self._broadcast_l1_proofs_update()
            
        except Exception as e:
            logger.error(f"Error handling block added: {e}")
    
    async def handle_wallet_balance_changed(self, event: Event):
        """Handle wallet balance change events"""
        try:
            wallet_address = event.data.get('wallet_address')
            logger.info(f"Handling wallet balance change event for: {wallet_address}")
            
            if wallet_address:
                await self._broadcast_wallet_update(wallet_address)
            else:
                logger.warning("Wallet balance change event missing wallet_address")
                
        except Exception as e:
            logger.error(f"Error handling wallet balance change: {e}")
    
    async def _broadcast_all_transactions_update(self):
        """Broadcast update to all_transactions subscribers"""
        try:
            db = get_db()
            formatted = []
            
            for key, value in db.items():
                key_text = key.decode("utf-8")
                if not key_text.startswith("utxo:"):
                    continue
                
                try:
                    utxo = json.loads(value.decode("utf-8"))
                    txid = utxo["txid"]
                    sender = utxo["sender"]
                    receiver = utxo["receiver"]
                    amount = Decimal(utxo["amount"])
                    
                    # Skip change outputs (self-to-self)
                    if sender == receiver:
                        continue
                    
                    # For genesis transactions (empty sender), set sender to "GENESIS"
                    if sender == "":
                        sender = "GENESIS"
                    
                    # Get timestamp
                    tx_data_raw = db.get(f"tx:{txid}".encode())
                    if tx_data_raw:
                        tx_data = json.loads(tx_data_raw.decode())
                        ts = tx_data.get("timestamp", 0)
                    else:
                        ts = 0
                    
                    timestamp_iso = datetime.fromtimestamp(ts / 1000).isoformat() if ts else datetime.utcnow().isoformat()
                    
                    formatted.append({
                        "id": txid,
                        "hash": txid,
                        "sender": sender,
                        "receiver": receiver,
                        "amount": f"{amount:.8f} qBTC",
                        "timestamp": timestamp_iso,
                        "status": "confirmed",
                        "_sort_ts": ts
                    })
                    
                except Exception as e:
                    logger.debug(f"Skipping UTXO: {e}")
                    continue
            
            # Sort by timestamp
            formatted.sort(key=lambda x: x["_sort_ts"], reverse=True)
            
            # Remove internal field
            for tx in formatted:
                tx.pop("_sort_ts", None)
            
            update_data = {
                "type": "transaction_update",
                "transactions": formatted,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Broadcasting {len(formatted)} transactions to all_transactions subscribers")
            if formatted:
                logger.info(f"First transaction: {formatted[0]}")
            await self.websocket_manager.broadcast(update_data, "all_transactions")
            
        except Exception as e:
            logger.error(f"Error broadcasting all transactions: {e}")
    
    async def _broadcast_wallet_update(self, wallet_address: str):
        """Broadcast update for specific wallet"""
        try:
            from web.web import get_balance, get_transactions
            
            logger.info(f"Broadcasting wallet update for: {wallet_address}")
            
            balance = get_balance(wallet_address)
            transactions = get_transactions(wallet_address)
            
            logger.info(f"Wallet {wallet_address} - Balance: {balance}, Transactions: {len(transactions)}")
            
            formatted = []
            for tx in transactions:
                tx_type = "send" if tx["direction"] == "sent" else "receive"
                amt_dec = Decimal(tx["amount"])
                amount_fmt = f"{abs(amt_dec):.8f} qBTC"
                address = tx["counterpart"] if tx["counterpart"] else "n/a"
                
                # Check if this is a genesis transaction
                # Genesis transactions have either txid "genesis_tx" or counterpart "bqs1genesis..."
                if tx["txid"] == "genesis_tx" or tx["counterpart"] == "bqs1genesis00000000000000000000000000000000":
                    timestamp_str = "Genesis Block"
                    logger.info(f"Setting Genesis Block timestamp for tx {tx['txid']}")
                else:
                    timestamp_str = datetime.fromtimestamp(tx["timestamp"] / 1000).isoformat() if tx["timestamp"] else "Unknown"
                
                formatted.append({
                    "id": tx["txid"],
                    "type": tx_type,
                    "amount": amount_fmt,
                    "address": address,
                    "timestamp": timestamp_str,
                    "hash": tx["txid"],
                    "status": "confirmed"
                })
            
            update_data = {
                "type": "combined_update",
                "balance": f"{balance:.8f}",
                "transactions": formatted
            }
            
            # Check if data actually changed
            cached = self.wallet_cache.get(wallet_address)
            if cached != update_data:
                self.wallet_cache[wallet_address] = update_data
                await self.websocket_manager.broadcast(
                    update_data,
                    "combined_update",
                    wallet_address
                )
                logger.debug(f"Broadcasted update for wallet: {wallet_address}")
            
        except Exception as e:
            logger.error(f"Error broadcasting wallet update: {e}")
    
    async def _broadcast_l1_proofs_update(self):
        """Broadcast L1 proofs update"""
        try:
            db = get_db()
            proofs = {}
            
            for key, value in db.items():
                if key.startswith(b"block:"):
                    block = json.loads(value.decode())
                    tx_ids = block["tx_ids"]
                    proofs[block["height"]] = {
                        "blockHeight": block["height"],
                        "merkleRoot": block["block_hash"],
                        "bitcoinTxHash": None,
                        "timestamp": datetime.fromtimestamp(block["timestamp"] / 1000).isoformat(),
                        "transactions": [
                            {"id": tx_id, "hash": tx_id, "status": "confirmed"}
                            for tx_id in tx_ids
                        ],
                        "status": "confirmed"
                    }
            
            update_data = {
                "type": "l1proof_update",
                "proofs": list(proofs.values()),
                "timestamp": datetime.now().isoformat()
            }
            
            await self.websocket_manager.broadcast(update_data, "l1_proofs_testnet")
            
        except Exception as e:
            logger.error(f"Error broadcasting L1 proofs: {e}")
    
    def register_handlers(self, event_bus):
        """Register all event handlers"""
        event_bus.subscribe(EventTypes.TRANSACTION_CONFIRMED, self.handle_transaction_confirmed)
        event_bus.subscribe(EventTypes.TRANSACTION_PENDING, self.handle_transaction_pending)
        event_bus.subscribe(EventTypes.BLOCK_ADDED, self.handle_block_added)
        event_bus.subscribe(EventTypes.WALLET_BALANCE_CHANGED, self.handle_wallet_balance_changed)
        logger.info("WebSocket event handlers registered")