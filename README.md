
# qBTC-core DEV NET

**qBTC-core** is a modern blockchain implementation inspired by Satoshi Nakamoto’s original design for Bitcoin. It stays true to foundational concepts such as:

- **Proof-of-Work (PoW)**
- **UTXO-based accounting**
- **Bitcoin-style block headers**
- **Mining compatibility**
- **Standard RPC methods** like `getblocktemplate` and `submitblock`

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
- 🧠 **Protobuf-encoded Transactions and Blocks**
- 🚀 Built with **Python**, **FastAPI**, and **asyncio**

---

## 📦 Architecture Overview

```text
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
| - Merkle Root     |         | - Blocks, Txns       |
| - UTXO State      |         +----------------------+
+-------------------+
         |
         v
+----------------------+
| Local DB (RocksDB)   |
+----------------------+
```

---

## 🛠 Getting Started

### 1. Clone the Repository & Install Dependencies

```bash
git clone https://github.com/bitcoinqs/qBTC-core.git
cd qBTC-core
pip install -r requirements.txt
```

Follow the instructions here to install liboqs-python:
https://github.com/open-quantum-safe/liboqs-python

### 2. Generate a Wallet

Before starting a node, you must generate a wallet file:

```bash
python3 wallet/wallet.py
```

This will create a `wallet.json` file containing your ML-DSA public/private keypair encrypted with a passphrase.

Keep it safe — this is your validator's identity and signing authority.

### 3. Start a Node via CLI

You can start qBTC-core either as a **bootstrap server** or connect to an existing bootstrap peer. Networking (DHT and Gossip) is always enabled and required for node operation.

#### CLI Usage

```bash
usage: main.py [-h] [--bootstrap] [--bootstrap_server BOOTSTRAP_SERVER]
               [--bootstrap_port BOOTSTRAP_PORT] [--dht-port DHT_PORT]
               [--gossip-port GOSSIP_PORT] [--external-ip EXTERNAL_IP]
```

Optional arguments:
- `--bootstrap`: Run as bootstrap server
- `--bootstrap_server`: Bootstrap server host (default: api.bitcoinqs.org)
- `--bootstrap_port`: Bootstrap server port (default: 8001)
- `--dht-port`: DHT port (default: 8001)
- `--gossip-port`: Gossip port (default: 8002)
- `--external-ip`: External IP address for NAT traversal

#### a) Start as a Bootstrap Server

```bash
python3 main.py --bootstrap
```

This initializes a bootstrap node that other nodes can connect to.

#### b) Connect to Default Bootstrap Server (api.bitcoinqs.org)

```bash
python3 main.py
```

This connects to the default bootstrap server at api.bitcoinqs.org:8001.

#### c) Connect to Custom Bootstrap Server

```bash
python3 main.py --bootstrap_server 192.168.1.10 --bootstrap_port 9001
```

Replace `192.168.1.10` and `9001` with your custom bootstrap server details.

#### d) Use Custom Ports

```bash
python3 main.py --dht-port 8009 --gossip-port 8010
```

This starts a node with custom DHT and gossip ports while connecting to the default bootstrap server. 
---

## 🐳 Docker Usage

The project includes several Docker Compose configurations for different deployment scenarios:

### Development/Testing Environment

```bash
# Start a test network with 1 bootstrap node and 2 validators
docker-compose -f docker-compose.yml up -d

# Or use the test configuration
docker-compose -f docker-compose.test.yml up -d
```

### Production Bootstrap Server

```bash
# Start a production bootstrap server
docker-compose -f docker-compose.bootstrap.yml up -d
```

### Production Validator

```bash
# Start a production validator node
docker-compose -f docker-compose.validator.yml up -d
```

All Docker configurations include:
- Automatic wallet generation
- Redis for caching/rate limiting
- Prometheus metrics collection
- Grafana dashboards for monitoring

---

## 🧪 Testing Multi-Node

You can simulate multiple validators by launching separate containers or Python processes with unique ports and wallet keys.

---

## 📜 File Structure

| File/Folder          | Description                             |
|----------------------|-----------------------------------------|
| `main.py`            | Entry point for validator logic         |
| `blockchain/`        | Block, transaction, UTXO, Merkle logic  |
| `dht/`               | Kademlia-based peer discovery           |
| `gossip/`            | Gossip protocol for block syncing       |
| `protobuf.proto`     | Message format for blocks and txns      |
| `database/`          | Local RocksDB-like storage abstraction  |
| `wallet/`            | Post-quantum key management (ML-DSA)    |

---

## ⛏️ Submitting & Mining Transactions

### Submitting a Transaction to the Mempool

You can broadcast a signed transaction to the mempool using the following command:

```bash
python3 harness.py --node http://localhost:8080 --receiver bqs1Bo4quBsE6f5aitv42X5n1S9kASsphn9At --amount 500 --wallet ~/Desktop/ledger.json
```

This sends 500 qBTC to the specified address using your signed wallet.

---

### Mining Transactions in the Mempool

To mine blocks (including mempool transactions), use `cpuminer-opt` connected to any node's RPC endpoint:

```bash
docker run --rm -it cpuminer-opt   -a sha256d   -o http://api.bitcoinqs.org:8332   -u someuser -p x   --coinbase-addr=1BoatSLRHtKNngkdXEeobR76b53LETtpyT
```

#### Example Output:

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

---

## 🔐 Security Notes

- Transactions use **ML-DSA** for post-quantum-safe signing.
- Each validator announces itself via DHT and syncs using gossip.
- Merkle roots ensure transaction integrity in each block.
- Future work includes replay protection, rate limiting, TLS, and full PoW consensus validation.
- Internal/external audits can be found in the audits folder we are working our way through these issues in order of criticality

---

## 📈 Roadmap

- ✅ Merkle Root, Gossip, Kademlia, UTXO
- 🔒 TLS + Peer Authentication
- ⚠️ Fork Choice Rule & Difficulty Enforcement
- 🧮 Fee Market & Miner Incentives
- 🧹 UTXO Pruning & State Compression

---

## 🧠 License

MIT License. See [LICENSE](./LICENSE) for more information.

---

## 🤝 Contributing

PRs and issues welcome! To contribute:

1. Fork the repo  
2. Create your feature branch (`git checkout -b feature/foo`)  
3. Commit your changes  
4. Push to the branch  
5. Open a PR  

---

## 🚀 Authors

- Christian Papathanasiou / Quantum Safe Technologies Corp  
