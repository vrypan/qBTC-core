#state.py
from collections import deque
import asyncio
# Global state variables for qBTC
ledger = {}                    # Maps wallet addresses to their list of UTXOs
mined_blocks = {}              # Maps block hashes to block metadata (tx_ids, timestamp, etc.)
checkpoint_chain = deque(maxlen=1000)  # Stores ML-DSA-87 signed checkpoints, limited to 1000 entries
validator_keys = {}            # Maps validator IDs to their public keys
known_validators = set()       # Tracks active validator IDs
validator_wallet = None        # Dictionary: {'address', 'privateKey', 'publicKey'} for the current node
transaction_history = deque(maxlen=10000)  # Recent transactions, limited to 10,000 entries
pending_transactions = {}      # Transactions awaiting block inclusion
blockchain = []
state_lock = asyncio.Lock()  
