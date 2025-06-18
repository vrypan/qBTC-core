# qBTC Deployment Guide

This guide covers different deployment scenarios for qBTC nodes with monitoring.

## Quick Start

### Option 1: Interactive Setup (Recommended)
```bash
./scripts/wallet-setup.sh
```
This script will:
- Help you create a new wallet or use an existing one
- Choose between mainnet connection or local bootstrap
- Configure all necessary environment variables
- Optionally start the services

### Option 2: Manual Setup

#### Connect to Mainnet
```bash
# Create wallet (if needed)
./scripts/create-wallet-docker.sh

# Set environment variables
export WALLET_PATH=./wallet.json
export WALLET_PASSWORD=your-password
export GRAFANA_ADMIN_PASSWORD=admin-password

# Start services
docker-compose -f docker-compose.mainnet.yml up -d
```

#### Run Bootstrap Server
```bash
# Use the production setup for bootstrap server
sudo bash monitoring/setup-production.sh
```

## Deployment Options

### 1. Mainnet Node (docker-compose.mainnet.yml)

Connects to the existing qBTC network at api.bitcoinqs.org.

**Features:**
- Connects to mainnet bootstrap at api.bitcoinqs.org:8001
- Local monitoring with Prometheus and Grafana
- Configurable ports via environment variables
- System metrics collection

**Default Ports:**
- API: 8080
- RPC: 8332
- Gossip: 7002
- DHT: 8001
- Grafana: 3000
- Prometheus: 9091

**Environment Variables:**
```bash
# Required
WALLET_PATH=./wallet.json
WALLET_PASSWORD=your-password

# Optional (with defaults)
API_PORT=8080
RPC_PORT=8332
GOSSIP_PORT=7002
DHT_PORT=8001
GRAFANA_PORT=3000
PROMETHEUS_PORT=9091
NODE_EXPORTER_PORT=9100
GRAFANA_ADMIN_PASSWORD=admin
```

### 2. Bootstrap Server (docker-compose.production.yml)

Runs a bootstrap server with public Grafana dashboards.

**Features:**
- SSL/TLS with Let's Encrypt
- Public read-only Grafana dashboards
- Nginx reverse proxy
- Security hardened
- Automatic certificate renewal

**Requirements:**
- Domain name
- Ports 80, 443 open

## Wallet Management

### Create New Wallet

**Option 1: Using Docker (Recommended)**
```bash
./scripts/create-wallet-docker.sh
```

**Option 2: Using Python directly**
```bash
python3 wallet/wallet.py
```

### Use Existing Wallet

Set the `WALLET_PATH` environment variable to your wallet location:
```bash
export WALLET_PATH=/path/to/your/wallet.json
```

## Monitoring Access

### Mainnet Deployment
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9091
- Default login: admin / [your-password]

### Production Bootstrap
- Grafana: https://your-domain.com/grafana/ (public read-only)
- Admin login: admin / [your-password]

## Common Commands

### View Logs
```bash
# Mainnet node
docker-compose -f docker-compose.mainnet.yml logs -f

# Production bootstrap
docker-compose -f docker-compose.production.yml logs -f
```

### Stop Services
```bash
# Mainnet node
docker-compose -f docker-compose.mainnet.yml down

# Production bootstrap
docker-compose -f docker-compose.production.yml down
```

### Update Services
```bash
# Pull latest images
docker-compose -f docker-compose.mainnet.yml pull

# Recreate containers
docker-compose -f docker-compose.mainnet.yml up -d --force-recreate
```

### Backup Data
```bash
# Backup blockchain data
docker run --rm -v qbtc-mainnet-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/qbtc-data-backup.tar.gz -C /data .

# Backup Prometheus data
docker run --rm -v prometheus-mainnet-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/prometheus-backup.tar.gz -C /data .
```

## Troubleshooting

### Connection Issues
```bash
# Check if node is syncing
docker-compose -f docker-compose.mainnet.yml logs qbtc-node | grep -i "sync\|connect"

# Test bootstrap connectivity
curl http://api.bitcoinqs.org:8080/health
```

### Wallet Issues
```bash
# Verify wallet file is readable
docker-compose -f docker-compose.mainnet.yml exec qbtc-node ls -la /data/wallet.json

# Check wallet password in environment
docker-compose -f docker-compose.mainnet.yml exec qbtc-node env | grep WALLET
```

### Resource Usage
```bash
# Check container resources
docker stats

# View system metrics in Grafana
# http://localhost:3000/d/qbtc-overview/
```

## Security Best Practices

1. **Wallet Security**
   - Keep wallet file backed up securely
   - Use strong passwords
   - Don't commit wallet files to git

2. **Network Security**
   - Use firewall rules to limit access
   - Enable SSL for production deployments
   - Regularly update Docker images

3. **Monitoring Security**
   - Change default Grafana admin password
   - Use read-only dashboards for public access
   - Limit Prometheus access to localhost

## Mining Configuration

To mine blocks to your node:
```bash
# For mainnet node
docker run --rm cpuminer-opt \
  -a sha256d \
  -o http://host.docker.internal:8332 \
  -u test -p x \
  --coinbase-addr=your-qbtc-address

# For bootstrap server
docker run --rm cpuminer-opt \
  -a sha256d \
  -o http://your-server:8332 \
  -u test -p x \
  --coinbase-addr=your-qbtc-address
```