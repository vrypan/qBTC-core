import json
from database.database import set_db, get_db
from config.config import ROCKSDB_PATH
from state.state import ledger, blockchain

def setup_database(db_path: str = ROCKSDB_PATH):
    set_db(db_path)
    db = get_db()
    ledger.clear()
    ledger.update({k: json.loads(v.decode()) for k, v in db.items()})
    blockchain.clear()
    blocks = sorted(
        [json.loads(v.decode()) for k, v in db.items() if k.startswith(b"block:")],
        key=lambda x: x["height"]
    )
    blockchain.extend([b["block_hash"] for b in blocks])
    return db
