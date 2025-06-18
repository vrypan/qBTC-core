# qBTC-core DEV NET

qBTC-core is a modern blockchain implementation inspired by Satoshi Nakamoto's original design for Bitcoin. It stays true to foundational concepts such as:

- **Proof-of-Work (PoW)**
- **UTXO-based accounting**
- **Bitcoin-style block headers**
- **Mining compatibility**
- **Standard RPC methods like getblocktemplate and submitblock**

Built from the ground up in Python to demonstrate a proof-of-concept, qBTC introduces key innovations for the future of Bitcoin:

- **Post-Quantum Security** using the ML-DSA signature scheme
- **Decentralized validator discovery** via a Kademlia DHT
- **Fast, scalable propagation** through an asynchronous gossip network

The cryptographic layer is modular, allowing ML-DSA to be replaced with other post-quantum algorithms as standards evolve.

## 🌐 Key Features

- 🛡 **Post-Quantum Cryptography** (ML-DSA-87 signatures)
- 🔁 **UTXO-Based Ledger** with Merkle root verification
- 🌱 **Validator Discovery** via Kademlia DHT
- 📡 **Gossip Protocol** for fast block propagation
- ⛓️ **Consensus Engine** with chain reorganization support
- 🔄 **Fork Resolution** using cumulative difficulty
- 🧠 **Protobuf-encoded** Transactions and Blocks
- 📊 **Integrated Monitoring** with Prometheus & Grafana
- 🛡️ **Security Suite** with rate limiting, DDoS protection, and attack detection
- 🎯 **Event-Driven Architecture** for real-time updates
- 🚀 Built with **Python, FastAPI, and asyncio**

## 📦 Architecture Overview

```
+-------------------+       +-----------------------+
|   Kademlia DHT    |<----->| Validator Peer Nodes  |
+-------------------+       +-----------------------+
         |                               |
         v                               v
+-------------------+         +----------------------+
| Gossip Network    | <-----> |  GossipNode Class    |
| (async TCP/JSON)  |         +----------------------+
         |                               |
         v                               v
+-------------------+         +----------------------+
| Blockchain Logic  | <-----> | Protobuf Structures  |
| - ChainManager    |         | - Blocks, Txns       |
| - Merkle Root     |         +----------------------+
| - UTXO State      |                 |
| - Fork Resolution |                 v
+-------------------+         +----------------------+
         |                    | Security Middleware  |
         v                    | - Rate Limiting      |
+----------------------+      | - DDoS Protection    |
| Event Bus System     |      | - Attack Detection   |
| - Real-time Updates  |      +----------------------+
+----------------------+                |
         |                              v
         v                    +----------------------+
+----------------------+      | Monitoring Stack     |
| Local DB (RocksDB)   |      | - Prometheus Metrics |
+----------------------+      | - Grafana Dashboards |
                              +----------------------+
```

## 🛠 Getting Started

### 1. Clone the Repository & Install Dependencies

```bash
git clone https://github.com/q-btc/qBTC-core.git
cd qBTC-core
pip install -r requirements.txt
```

Follow the instructions here to install liboqs-python: https://github.com/open-quantum-safe/liboqs-python

For Ubuntu/Debian:
```bash
# Install liboqs
sudo apt-get update && sudo apt-get install -y build-essential cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs
cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON
cmake --build /tmp/liboqs/build --parallel $(nproc)
sudo cmake --install /tmp/liboqs/build
sudo ldconfig

# Install liboqs-python
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python /tmp/liboqs-python
pip install /tmp/liboqs-python
```

### 2. Generate a Wallet

Before starting a node, you must generate a wallet file:

```bash
python3 wallet/wallet.py
```

This will create a `wallet.json` file containing your ML-DSA-87 (post-quantum secure) public/private keypair encrypted with a passphrase.

**Keep it safe** — this is your validator's identity and signing authority.

### 3. Start a Node via CLI

You can start qBTC-core either as a bootstrap server or connect to an existing bootstrap peer.

#### CLI Usage
```
usage: main.py [-h] [--Bootstrap_ip BOOTSTRAP_IP]
               [--Bootstrap_port BOOTSTRAP_PORT] --wallet WALLET [--local]
               validator_port [gossip_port]
```

#### a) Start as a Bootstrap Server
```bash
python main.py 9001 9002 --wallet mywallet.json --local
```
This initializes a validator node and makes it discoverable by others.

#### b) Connect to an Existing Bootstrap Server
```bash
python main.py 9003 9004 --wallet mywallet.json --Bootstrap_ip 192.168.1.10 --Bootstrap_port 9002
```
Replace `192.168.1.10` and `9002` with the IP and port of your chosen bootstrap peer.

#### c) Connect to the Existing qBTC Network
```bash
python3 main.py 8009 8010 --Bootstrap_ip api.bitcoinqs.org --Bootstrap_port 8001 --wallet admin.json
```
Where `8009 8010` are example DHT and gossip ports on your local server.

## 🐳 Docker Development Environment

### Available Docker Configurations

We provide several Docker Compose configurations for different use cases:

1. **docker-compose.test.yml** - 3-node test network with full monitoring stack
2. **docker-compose.bootstrap.yml** - Production bootstrap server with secure public Grafana
3. **docker-compose.validator.yml** - Validator node connecting to mainnet
4. **docker-compose.yml** - Default 3-node test setup

### Option 1: Join the Existing qBTC Network

To run a validator node and connect to the existing qBTC network:

```bash
# Generate a wallet if you don't have one
python3 wallet/wallet.py

# Start the validator node
docker compose -f docker-compose.validator.yml up -d

# View logs
docker compose -f docker-compose.validator.yml logs -f

# Access monitoring dashboard
# Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090
```

### Option 2: Run a Production Bootstrap Server

For running a bootstrap server with secure public monitoring:

```bash
# Configure SSL certificates in monitoring/nginx/ssl/
# Update nginx configuration in monitoring/nginx/nginx-prod.conf

# Start the bootstrap server
docker compose -f docker-compose.bootstrap.yml up -d

# Grafana will be available at https://your-domain.com
```

### Option 3: Local Test Network with Monitoring

For local development and testing with full monitoring:

```bash
# Start the 3-node test network with monitoring
docker compose -f docker-compose.test.yml up -d

# This creates:
# - Bootstrap node: localhost:8080 (API) / localhost:8332 (RPC)
# - Validator 1: localhost:8081 (API) / localhost:8333 (RPC)
# - Validator 2: localhost:8082 (API) / localhost:8334 (RPC)
# - Redis: localhost:6379 (for rate limiting)
# - Prometheus: localhost:9090 (metrics collection)
# - Grafana: localhost:3000 (monitoring dashboards)

# View logs
docker compose -f docker-compose.test.yml logs -f

# Access monitoring
# - Grafana: http://localhost:3000 (admin/admin)
# - View pre-configured qBTC dashboard
# - Monitor node health, block production, network stats

# Stop the network
docker compose -f docker-compose.test.yml down

# Stop and remove all data (fresh start)
docker compose -f docker-compose.test.yml down -v
```

The bootstrap node starts with genesis funds (21M qBTC) at address `bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV`.

You can modify the `docker-compose.yml` file to add more validator nodes if needed.

#### Testing the Local Network

```bash
# Check node status
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:8082/health

# Check balances
curl http://localhost:8080/balance/bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV

# Submit a transaction (you'll need the bootstrap wallet password)
python3 harness.py --node http://localhost:8080 --receiver bqs1NoaFdBFxgaKoUzf4nn3peMwT8P32meFg8 --amount 500 --wallet bootstrap.json

# Mine blocks to include the transaction
docker run --rm --network=qbtc-core_qbtc-network cpuminer-opt \
  -a sha256d \
  -o http://qbtc-bootstrap:8332 \
  -u test -p x \
  --coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT \
  --no-longpoll \
  -t 1
```

## 🧪 Testing Multi-Node

You can simulate multiple validators by launching separate containers or Python processes with unique ports and wallet keys.

## 📜 File Structure

| File/Folder | Description |
|------------|-------------|
| `main.py` | Entry point for validator logic |
| `blockchain/` | Block, transaction, UTXO, Merkle logic |
| `dht/` | Kademlia-based peer discovery |
| `gossip/` | Gossip protocol for block syncing |
| `protobuf.proto` | Message format for blocks and txns |
| `database/` | Local RocksDB storage abstraction |
| `wallet/` | Post-quantum key management (ML-DSA-87) |
| `rpc/` | Bitcoin-compatible RPC (getblocktemplate, submitblock) |
| `web/` | FastAPI REST endpoints & WebSocket handlers |
| `security/` | Rate limiting, DDoS protection, attack detection |
| `monitoring/` | Prometheus & Grafana configurations |
| `models/` | Pydantic validation models |
| `errors/` | Custom exception handling |
| `middleware/` | Security & error handling middleware |
| `events/` | Event bus system for real-time updates |
| `scripts/` | Utility scripts for maintenance |

## 📊 Monitoring

Each qBTC node exposes Prometheus metrics at the `/health` endpoint. The monitoring stack includes:

- **Prometheus**: Collects metrics from all nodes
- **Grafana**: Pre-configured dashboards showing:
  - Node health and uptime
  - Blockchain height and sync status
  - Transaction throughput
  - Mempool size
  - Peer connections
  - Mining statistics
  - Network difficulty

Access monitoring dashboards:
- Grafana: http://localhost:3000 (default: admin/admin)
- Prometheus: http://localhost:9090

## ⛏️ Submitting & Mining Transactions

### Submitting a Transaction to the Mempool

You can broadcast a signed transaction to the mempool using the following command:

```bash
python3 harness.py --node http://localhost:8080 --receiver bqs1Bo4quBsE6f5aitv42X5n1S9kASsphn9At --amount 500 --wallet ~/Desktop/ledger.json
```

This sends 500 qBTC to the specified address using your signed wallet.

### Mining Transactions in the Mempool

To mine blocks (including mempool transactions), use cpuminer-opt connected to any node's RPC endpoint:

```bash
# For external mining (main network)
docker run --rm -it cpuminer-opt \
  -a sha256d \
  -o http://api.bitcoinqs.org:8332 \
  -u someuser -p x \
  --coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT

# For local 3-node test network
docker run --rm --network=qbtc-core_qbtc-network cpuminer-opt \
  -a sha256d \
  -o http://qbtc-bootstrap:8332 \
  -u test -p x \
  --coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT

# For local node (from host)
docker run --rm cpuminer-opt \
  -a sha256d \
  -o http://host.docker.internal:8332 \
  -u test -p x \
  --coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT
```

Example Output:
```
[2025-05-28 11:47:16] 14 of 14 miner threads started using 'sha256d' algorithm
[2025-05-28 11:47:17] CPU temp: curr 0 C max 0, Freq: 0.000/0.000 GHz
[2025-05-28 11:47:17] New Block 1101, Tx 0, Net Diff 1.5259e-05, Ntime 6836f7c5
                      Miner TTF @ 280.00 h/s 3m54s, Net TTF @ 0.00 h/s NA
[2025-05-28 11:47:17] 1 Submitted Diff 8.5386e-05, Block 1101, Ntime c5f73668
[2025-05-28 11:47:17] 1 A1 S0 R0 BLOCK SOLVED 1, 0.497 sec (207ms)
[2025-05-28 11:47:17] New Block 1102, Tx 0, Net Diff 1.5259e-05, Ntime 6836f7c5
                      Miner TTF @ 41.47 Mh/s 0m00s, Net TTF @ 0.00 h/s NA
```

## 🔐 Security Notes

- Transactions use **ML-DSA-87** for post-quantum-safe signing
- Each validator announces itself via DHT and syncs using gossip
- Merkle roots ensure transaction integrity in each block
- **Implemented Security Features:**
  - Rate limiting with Redis backend
  - DDoS protection middleware
  - Attack pattern detection
  - Bot detection system
  - Peer reputation tracking
  - Security event logging
- Future work includes replay protection, TLS, and additional consensus validation

## 📈 Roadmap

- ✅ Merkle Root, Gossip, Kademlia, UTXO
- ✅ Bitcoin-compatible RPC (getblocktemplate, submitblock)
- ✅ Rate limiting & DDoS protection
- ✅ Fork Choice Rule (longest chain by cumulative difficulty)
- ✅ Chain reorganization & orphan block management
- ✅ Difficulty Adjustment Algorithm
- ✅ Integrated monitoring with Prometheus & Grafana
- ✅ Event-driven architecture for real-time updates
- ✅ Security middleware suite
- 🔒 TLS + Peer Authentication
- 🧮 Fee Market & Miner Incentives
- 🧹 UTXO Pruning & State Compression

## 🧠 License

MIT License. See [LICENSE](LICENSE) for more information.

## 🤝 Contributing

PRs and issues welcome! To contribute:

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/foo`)
3. Commit your changes
4. Push to the branch
5. Open a PR

## 🚀 Authors

**Christian Papathanasiou / Quantum Safe Technologies Corp**

---

**⚠️ Disclaimer**: Experimental software. Not audited for production financial use.