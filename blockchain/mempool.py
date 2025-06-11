from collections import OrderedDict
from .utils import calculate_tx_hash
from protobuf.blockchain_pb2 import Transaction

class Mempool:
    def __init__(self, limit=1000):
        """
        Initialize the mempool.

        Args:
            limit (int): Maximum number of transactions to store.
        """
        self.limit = limit
        self.tx_map = OrderedDict()

    def add(self, tx: Transaction):
        tx_hash = calculate_tx_hash(tx)
        if tx_hash in self.tx_map:
            return  # Avoid duplicates

        if len(self.tx_map) >= self.limit:
            self.tx_map.popitem(last=False)  # Remove oldest

        self.tx_map[tx_hash] = tx.SerializeToString()

    def get(self, tx_hash: bytes) -> Transaction | None:
        bytes = self.tx_map.get(tx_hash)
        if not bytes:
            return None
        return Transaction.FromString(bytes)

    def remove(self, tx_hash: bytes):
        self.tx_map.pop(tx_hash, None)

    def __len__(self):
        return len(self.tx_map)

    def all(self) -> list[Transaction]:
        return list(self.tx_map.values())

mempool = Mempool(limit=10000)

"""
# example usage from other modules.
from blockchain.mempool import mempool

def handle_new_transaction(tx: Transaction):
    mempool.add(tx)
    print(f"Transaction added. Mempool size: {len(mempool)}")
"""
