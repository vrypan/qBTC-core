#!/bin/bash
set -e

# Default values if not set
WALLET_FILE="${WALLET_FILE:-wallet.json}"
WALLET_PASSWORD="${WALLET_PASSWORD:-password123}"

echo "🔐 Wallet file: $WALLET_FILE"
echo "🔐 Password: (hidden)"

# Generate or unlock wallet
python3 -c "
import os
from wallet.wallet import get_or_create_wallet
import json

password = os.getenv('WALLET_PASSWORD')

# Force wallet generation or loading
wallet = get_or_create_wallet(filename='/app/${WALLET_FILE}', password=password)

print(f'✅ Wallet ready: Address {wallet[\"address\"]}')
"

# Run main.py with passed arguments
exec python3 main.py "$@"
