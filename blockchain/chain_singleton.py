"""
Singleton pattern for ChainManager to ensure consistency across the application
"""
from blockchain.chain_manager import ChainManager

_chain_manager_instance = None

def get_chain_manager() -> ChainManager:
    """Get the singleton ChainManager instance"""
    global _chain_manager_instance
    if _chain_manager_instance is None:
        _chain_manager_instance = ChainManager()
    return _chain_manager_instance

def reset_chain_manager():
    """Reset the chain manager (for testing only)"""
    global _chain_manager_instance
    _chain_manager_instance = None