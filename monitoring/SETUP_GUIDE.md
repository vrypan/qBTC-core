# qBTC Monitoring Setup Guide

This guide will help you set up Prometheus and Grafana to monitor your qBTC node.

## Quick Start

### 1. Start Prometheus and Grafana

From the monitoring directory, run:
```bash
docker-compose up -d
```

### 2. Access the Services

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000
  - Default login: admin/admin

### 3. Verify Prometheus is Collecting Metrics

1. Go to http://localhost:9090
2. Click on "Status" → "Targets"
3. You should see your qBTC nodes listed and their status should be "UP"

### 4. Import the qBTC Dashboard in Grafana

1. Log into Grafana (http://localhost:3000)
2. Click the "+" icon → "Import"
3. Upload the `qbtc-dashboard.json` file from this directory
4. Select "Prometheus" as the data source
5. Click "Import"

## Available Metrics

Your qBTC node exposes these metrics at `/health`:

### Node Metrics
- `qbtc_node_info` - Basic node information
- `qbtc_uptime_seconds` - How long the node has been running

### Blockchain Metrics
- `qbtc_blockchain_height` - Current blockchain height
- `qbtc_blockchain_sync_status` - Is the node synced? (1=yes, 0=no)
- `qbtc_last_block_time_seconds` - When was the last block created

### Transaction Metrics
- `qbtc_pending_transactions` - Number of transactions in mempool

### Network Metrics
- `qbtc_connected_peers_total` - Total connected peers
- `qbtc_synced_peers` - Number of fully synced peers
- `qbtc_failed_peers` - Number of failed peer connections

### Performance Metrics
- `qbtc_database_response_seconds` - Database query performance
- `qbtc_health_check_status` - Health status by component

## Creating Custom Dashboards

### Example Queries

1. **Node Uptime**:
   ```promql
   qbtc_uptime_seconds / 3600  # Convert to hours
   ```

2. **Blocks Per Minute**:
   ```promql
   rate(qbtc_blockchain_height[5m]) * 60
   ```

3. **Transaction Throughput**:
   ```promql
   rate(qbtc_pending_transactions[1m])
   ```

4. **Peer Health**:
   ```promql
   qbtc_synced_peers / qbtc_connected_peers_total * 100
   ```

### Dashboard Panels to Create

1. **Overview Row**:
   - Current Block Height (Stat)
   - Node Uptime (Stat)
   - Sync Status (Stat with threshold)
   - Connected Peers (Stat)

2. **Blockchain Activity**:
   - Block Height Over Time (Graph)
   - Blocks Per Minute (Graph)
   - Time Since Last Block (Stat)

3. **Network Health**:
   - Connected vs Synced Peers (Graph)
   - Failed Peers Over Time (Graph)
   - Peer Sync Percentage (Gauge)

4. **Performance**:
   - Database Response Time (Graph)
   - Pending Transactions (Graph)
   - Component Health Status (Table)

## Alerting

### Example Alert Rules

Create these in Grafana Alerts:

1. **Node Down Alert**:
   ```promql
   up{job="qbtc-core"} == 0
   ```

2. **Sync Lost Alert**:
   ```promql
   qbtc_blockchain_sync_status == 0
   ```

3. **High Pending Transactions**:
   ```promql
   qbtc_pending_transactions > 1000
   ```

4. **No New Blocks**:
   ```promql
   time() - qbtc_last_block_time_seconds > 600  # No block for 10 minutes
   ```

## Troubleshooting

### Prometheus Can't Reach qBTC Node

If using Docker, make sure to use the correct target address:
- Mac/Windows: `host.docker.internal:8000`
- Linux: `172.17.0.1:8000` or your actual host IP

### No Metrics Showing

1. Check if your qBTC node is running: `curl http://localhost:8000/health`
2. Check Prometheus targets: http://localhost:9090/targets
3. Check Prometheus logs: `docker-compose logs prometheus`

### Grafana Can't Connect to Prometheus

1. Make sure both containers are on the same network
2. In Grafana data source settings, use `http://prometheus:9090` as the URL