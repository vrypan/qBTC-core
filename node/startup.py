"""
Node startup and shutdown procedures
"""

import os
import asyncio
from log_utils import get_logger
from events.event_bus import event_bus

logger = get_logger(__name__)

async def startup():
    """Initialize node components"""
    logger.info("Starting node initialization")
    
    try:
        # Initialize database
        from database.database import set_db, get_db
        db_path = os.environ.get('ROCKSDB_PATH', './ledger.rocksdb')
        set_db(db_path)
        db = get_db()
        logger.info(f"Database initialized at {db_path}")
        
        # Start event bus if not already started
        if not event_bus.running:
            await event_bus.start()
            logger.info("Event bus started")
        
        # Initialize blockchain components
        # Blockchain initialization happens on-demand through other components
        logger.info("Blockchain components ready")
        
        # Load wallet if specified
        wallet_file = os.environ.get('WALLET_FILE', 'wallet.json')
        wallet_password = os.environ.get('WALLET_PASSWORD', 'password123')
        
        from wallet.wallet import get_or_create_wallet
        wallet = get_or_create_wallet(fname=wallet_file, password=wallet_password)
        logger.info(f"Wallet loaded: {wallet['address']}")
        
        # Store in app state for access
        import sys
        sys.modules['__main__'].wallet = wallet
        
        logger.info("Node startup completed")
        
    except Exception as e:
        logger.error(f"Failed to start node: {str(e)}")
        raise

async def shutdown():
    """Cleanup node components"""
    logger.info("Starting node shutdown")
    
    try:
        # Stop event bus
        if event_bus.running:
            await event_bus.stop()
            logger.info("Event bus stopped")
        
        # Close database connections
        # Database cleanup happens automatically
        
        logger.info("Node shutdown completed")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {str(e)}")
        # Don't raise during shutdown to allow graceful exit