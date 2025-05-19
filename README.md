# qBTC-core

This repository contains a proof-of-concept blockchain implementation written in Python. The project includes modules for networking via gossip and DHT, a simple wallet built using post-quantum signatures, and a RocksDB-backed ledger.

## Components

- **blockchain** – core blockchain data structures and utilities
- **wallet** – wallet generation and transaction signing using ML-DSA-87 via Node.js
- **dht / gossip** – peer discovery and block propagation
- **web / rpc** – simple FastAPI services

The code is experimental and not intended for production use. Review thoroughly before any real-world deployment.

