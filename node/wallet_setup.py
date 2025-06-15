import os
import json
import getpass
from wallet.wallet import get_or_create_wallet

def load_wallet(wallet_path: str) -> dict:
    """Load or create a wallet file."""
    try:
        with open(wallet_path, "r") as f:
            wallet_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        wallet_data = {"address": "bqs1DefaultMinerAddressForTesting"}
    return wallet_data

def setup_validator_wallet(wallet_file: str) -> dict:
    """Get validator wallet with password."""
    password = os.getenv("WALLET_PASSWORD")
    if not password:
        password = getpass.getpass("Wallet password: ")
    wallet = get_or_create_wallet(wallet_file, password=password)
    return wallet
