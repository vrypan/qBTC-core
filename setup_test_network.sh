#!/bin/bash
# Setup test network with bootstrap wallet receiving genesis funds

echo "🚀 Setting up test network with bootstrap wallet receiving genesis funds..."

# Clean up any existing containers
echo "Cleaning up existing containers..."
docker compose down -v

# Start only bootstrap container to generate wallet
echo "Starting bootstrap container to generate wallet..."
docker compose up -d bootstrap

# Wait for wallet generation
echo "Waiting for bootstrap wallet to be generated..."
sleep 10

# Get bootstrap wallet address and copy the wallet
BOOTSTRAP_ADDRESS=$(docker exec qbtc-bootstrap cat /app/bootstrap.json 2>/dev/null | jq -r .address)

if [ -z "$BOOTSTRAP_ADDRESS" ]; then
    echo "❌ Failed to get bootstrap wallet address"
    exit 1
fi

echo "✅ Bootstrap wallet address: $BOOTSTRAP_ADDRESS"

# Copy the bootstrap wallet to preserve it
echo "Copying bootstrap wallet..."
docker cp qbtc-bootstrap:/app/bootstrap.json ./original_bootstrap.json

# Stop all containers
echo "Stopping containers..."
docker compose down

# Copy the wallet back to ensure it's used on restart
echo "Preserving original bootstrap wallet..."
mkdir -p bootstrap_wallet_backup
cp ./original_bootstrap.json ./bootstrap_wallet_backup/bootstrap.json

# Now start everything with ADMIN_ADDRESS set to bootstrap wallet
echo "Starting network with ADMIN_ADDRESS=$BOOTSTRAP_ADDRESS"
export ADMIN_ADDRESS=$BOOTSTRAP_ADDRESS

# Create a docker-compose override to mount the wallet
cat > docker-compose.override.yml << EOF
version: '3.8'
services:
  bootstrap:
    volumes:
      - ./bootstrap_wallet_backup/bootstrap.json:/app/bootstrap.json
      - bootstrap-data:/app/ledger.rocksdb
      - ./logs:/var/log/qbtc
EOF

docker compose up -d

# Wait for network to stabilize
echo "Waiting for network to start and genesis block to be created..."
sleep 15

# Verify bootstrap wallet has genesis funds
echo "Verifying bootstrap wallet balance..."
BALANCE=$(curl -s http://localhost:8080/balance/$BOOTSTRAP_ADDRESS | jq -r .balance)

if [ "$BALANCE" = "21000000" ]; then
    echo "✅ SUCCESS! Bootstrap wallet has genesis funds: $BALANCE"
    echo ""
    echo "Network is ready for testing!"
    echo "Bootstrap wallet address: $BOOTSTRAP_ADDRESS"
    echo "Bootstrap wallet password: bootstrappass"
    echo ""
    echo "The funded wallet is saved as: ./original_bootstrap.json"
    echo ""
    echo "You can now run:"
    echo "  python full_100_cycle_test.py --wallet original_bootstrap.json --password bootstrappass --cycles 3"
else
    echo "❌ Bootstrap wallet balance is $BALANCE, expected 21000000"
    echo "Something went wrong with genesis block creation"
fi