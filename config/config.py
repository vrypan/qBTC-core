import asyncio
import uuid
import os
from decimal import Decimal 

VALIDATOR_ID = str(uuid.uuid4())[:8]
ROCKSDB_PATH = os.environ.get("ROCKSDB_PATH", "ledger.rocksdb")  
DEFAULT_GOSSIP_PORT = 7002
DHT_PORT = 8001
HEARTBEAT_INTERVAL = 30
VALIDATOR_TIMEOUT = 90
BOOTSTRAP_NODES = [("api.bitcoinqs.org", 8001)]
VALIDATORS_LIST_KEY = "validators_list"
shutdown_event = asyncio.Event()
MAX_CHECKPOINTS = 1000
MAX_TX_HISTORY = 10000
FEE_PERCENTAGE = float(os.environ.get("FEE_PERCENTAGE", "0.001"))
DIFFICULTY_ADJUSTMENT_INTERVAL = int(os.environ.get("DIFFICULTY_ADJUSTMENT_INTERVAL", "10"))
BLOCK_TIME_TARGET = int(os.environ.get("BLOCK_TIME_TARGET", "10"))
GENESIS_ADDRESS = "bqs1genesis00000000000000000000000000000000"
ADMIN_ADDRESS = "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"
