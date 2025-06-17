import json
import logging
from database.database import set_db, get_db
from config.config import ROCKSDB_PATH
from state.state import ledger, blockchain

logger = logging.getLogger(__name__)

def setup_database(db_path: str = ROCKSDB_PATH):
    logger.info(f"Setting up database at: {db_path}")
    set_db(db_path)
    db = get_db()
    
    ledger.clear()
    blockchain.clear()
    
    # Load all entries into ledger
    entry_count = 0
    block_count = 0
    blocks_data = []
    
    for k, v in db.items():
        entry_count += 1
        ledger[k] = json.loads(v.decode())
        
        if k.startswith(b"block:"):
            block_count += 1
            blocks_data.append(json.loads(v.decode()))
    
    logger.info(f"Loaded {entry_count} entries from database")
    logger.info(f"Found {block_count} blocks")
    
    # Sort blocks by height and populate blockchain list
    blocks = sorted(blocks_data, key=lambda x: x["height"])
    blockchain.extend([b["block_hash"] for b in blocks])
    
    logger.info(f"Blockchain initialized with {len(blockchain)} blocks")
    if blockchain:
        logger.info(f"First block: {blockchain[0]}")
        logger.info(f"Last block: {blockchain[-1]}")
    
    return db
