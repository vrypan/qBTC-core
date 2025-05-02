import argparse

parser = argparse.ArgumentParser(description="Run a validator node with API.")
parser.add_argument("validator_port", type=int, help="Port for DHT server")
parser.add_argument("gossip_port", type=int, nargs="?", default=8081, help="Gossip port")
parser.add_argument("--Bootstrap_ip", type=str, help="Bootstrap node IP")
parser.add_argument("--Bootstrap_port", type=int, help="Bootstrap node port")
parser.add_argument("--wallet", type=str, required=True, help="Path to the wallet file")
parser.add_argument("--local", action="store_true", help="Use 127.0.0.1 instead of external IP")
args = parser.parse_args()
