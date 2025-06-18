# qBTC Monitoring Setup

This directory contains the monitoring configuration for qBTC nodes using Prometheus and Grafana.

## Architecture

Each qBTC node exposes a `/health` endpoint that provides Prometheus-compatible metrics including:
- Node health status (database, blockchain, network, mempool)
- Blockchain height
- Connected and synced peer counts
- Pending transactions in mempool
- Database response times
- Node uptime

## Docker Compose Configurations

### 1. Test Environment (docker-compose.test.yml / docker-compose.yml)
- 3-node test network (1 bootstrap + 2 validators)
- Prometheus and Grafana included
- No authentication required
- Suitable for development and testing

**Start with:**
```bash
./start_docker.sh
# or
docker compose up --build
```

**Access:**
- Bootstrap: http://localhost:8080
- Validator 1: http://localhost:8081
- Validator 2: http://localhost:8082
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin123)

### 2. Production Bootstrap (docker-compose.bootstrap.yml)
- Single bootstrap node with secure monitoring
- Nginx reverse proxy with SSL/TLS
- Basic authentication for Grafana access
- Rate limiting and security headers

**Requirements:**
- SSL certificates in `monitoring/nginx/ssl/`
- `.htpasswd` file in `monitoring/nginx/`
- Environment variables set

**Start with:**
```bash
./scripts/start-bootstrap.sh
```

**Required Environment Variables:**
```bash
export BOOTSTRAP_WALLET_PASSWORD="your-secure-password"
export GRAFANA_ADMIN_USER="admin"
export GRAFANA_ADMIN_PASSWORD="secure-password"
export ADMIN_ADDRESS="your-admin-address"
export GRAFANA_DOMAIN="monitoring.yourdomain.com"
```

### 3. Mainnet Validator (docker-compose.validator.yml)
- Connects to existing mainnet via api.bitcoinqs.org:8001
- Local monitoring stack
- No external exposure

**Start with:**
```bash
./scripts/start-validator.sh
```

**Required Environment Variables:**
```bash
export VALIDATOR_WALLET_PASSWORD="your-secure-password"
export ADMIN_ADDRESS="your-admin-address"
export VALIDATOR_WALLET_FILE="validator.json"  # optional
```

## Grafana Dashboard

A pre-configured dashboard (`qbtc-overview.json`) is automatically loaded showing:
- Node health status
- Blockchain height over time
- Network peer statistics
- Mempool transaction counts
- Database performance metrics
- Node uptime

## Security Notes

### Production Bootstrap
- Always use SSL/TLS certificates
- Create strong passwords for htpasswd: `htpasswd -c monitoring/nginx/.htpasswd username`
- Regularly update Grafana admin password
- Monitor nginx access logs for suspicious activity

### Validator Nodes
- Keep Grafana access local only
- Use strong wallet passwords
- Monitor resource usage

## Prometheus Metrics

Available metrics include:
- `qbtc_node_info` - Node information
- `qbtc_uptime_seconds` - Node uptime
- `qbtc_blockchain_height` - Current blockchain height
- `qbtc_blockchain_sync_status` - Sync status (1=synced, 0=not synced)
- `qbtc_last_block_time_seconds` - Timestamp of last block
- `qbtc_pending_transactions` - Mempool transaction count
- `qbtc_connected_peers_total` - Total connected peers
- `qbtc_synced_peers` - Number of synced peers
- `qbtc_failed_peers` - Number of failed peers
- `qbtc_database_response_seconds` - Database response time histogram
- `qbtc_health_check_status{component}` - Component health status

## Troubleshooting

### Grafana not showing data
1. Check Prometheus targets at http://localhost:9090/targets
2. Verify nodes are running and `/health` endpoint is accessible
3. Check container logs: `docker compose logs prometheus grafana`

### SSL Certificate Issues
1. Ensure cert.pem and key.pem are in `monitoring/nginx/ssl/`
2. Verify certificate validity and domain match
3. Check nginx logs: `docker compose -f docker-compose.bootstrap.yml logs nginx`

### Authentication Issues
1. Verify .htpasswd file exists and has correct permissions
2. Create new user: `htpasswd monitoring/nginx/.htpasswd newuser`
3. Reset password: `htpasswd monitoring/nginx/.htpasswd existinguser`