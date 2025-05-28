# qBTC-core

**qBTC-core** is a modern blockchain implementation inspired by Satoshi Nakamoto’s original design for Bitcoin. It stays true to foundational concepts such as:

- **Proof-of-Work (PoW)**
- **UTXO-based accounting**
- **Bitcoin-style block headers**
- **Mining compatibility**
- **Standard RPC methods** like `getblocktemplate` and `submitblock`

Built from the ground up in Python, qBTC introduces key innovations for the future of Bitcoin:

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


### 1. Clone the Repository

```bash
git clone https://github.com/bitcoinqs/qBTC-core.git
cd qBTC-core
```

### 2. Generate a Wallet

Before starting a node, you must generate a wallet file:

```bash
python3 wallet/wallet.py
```

This will create a `wallet.json` file containing your ML-DSA public/private keypair encrypted with a passphrase.

Keep it safe — this is your validator's identity and signing authority.

### 3. Start a Node via CLI

You can start qBTC-core either as a **bootstrap server** or connect to an existing bootstrap peer.

#### CLI Usage

```bash
usage: main.py [-h] [--Bootstrap_ip BOOTSTRAP_IP]
               [--Bootstrap_port BOOTSTRAP_PORT] --wallet WALLET [--local]
               validator_port [gossip_port]
```

#### a) Start as a Bootstrap Server

```bash
python main.py 9001 9002 --wallet mywallet.json --local
```

This initializes a validator node and makes it discoverable by others. `--local` means this node will act as a bootstrap server.

#### b) Connect to an Existing Bootstrap Server

```bash
python main.py 9003 9004 --wallet mywallet.json --Bootstrap_ip 192.168.1.10 --Bootstrap_port 9002
```

Replace `192.168.1.10` and `9002` with the IP and port of your chosen bootstrap peer.


### 4. Manual Run (Python)

```bash
pip install -r requirements.txt
npm install @noble/post-quantum js-sha3 bs58
python main.py
```

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

## 🔐 Security Notes

- Transactions use **ML-DSA** for post-quantum-safe signing.
- Each validator announces itself via DHT and syncs using gossip.
- Merkle roots ensure transaction integrity in each block.
- Your DHT (UDP) and Gossip ports (TCP) need to be unfiltered on the internet and allow traffic from all.
- Future work includes rate limiting, introduction of protobufs.

---

## 📈 Roadmap

- ✅ Merkle Root, Gossip, Kademlia, UTXO
- 🔒 Protobufs instead of JSON serialization - 
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

