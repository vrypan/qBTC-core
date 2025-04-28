import struct
from gossip.gossip import sha256d
import hashlib
import base58
import json
# Blockchain state 
TREASURY_ADDRESS = "bqs1GPSETB9KzXeYWHfs2zMGPv5VKhLTPSvhm"
GENESIS_ADDRESS = "bqs1genesis00000000000000000000000000000000"
ADMIN_ADDRESS = "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"
BLOCK_TIME_TARGET = 10  # Target block time in seconds
DIFFICULTY_ADJUSTMENT_INTERVAL = 10  # Blocks before difficulty adjustment


def bits_to_target(bits: int) -> int:
    exponent = bits >> 24
    coefficient = bits & 0xffffff
    return coefficient * (1 << (8 * (exponent - 3)))

def validate_pow(block: "Block") -> bool:
    target = bits_to_target(block.bits)
    return int(block.hash(), 16) < target

class Block:
    def __init__(self, version, prev_block_hash, merkle_root, timestamp, bits, nonce):
        self.version = version
        self.prev_block_hash = prev_block_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce

    def header(self):
        return (
            struct.pack("<L", self.version) +
            bytes.fromhex(self.prev_block_hash)[::-1] +
            bytes.fromhex(self.merkle_root)[::-1] +
            struct.pack("<L", self.timestamp) +
            struct.pack("<L", self.bits) +
            struct.pack("<L", self.nonce)
        )

    def hash(self):
        return sha256d(self.header())[::-1].hex()







def serialize_transaction(tx: dict) -> str:
    tx_data = json.dumps(tx, sort_keys=True)
    return tx_data.encode().hex()

def deserialize_transaction(raw_tx: str) -> dict:
    try:
        tx_bytes = bytes.fromhex(raw_tx)
        tx_json = tx_bytes.decode()
        tx_dict = json.loads(tx_json)
        return tx_dict
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to deserialize transaction: {e}")



def read_varint(raw: bytes, offset: int) -> (int, int):
    i = raw[offset]
    if i < 0xfd:
        return i, 1
    elif i == 0xfd:
        return struct.unpack_from('<H', raw, offset + 1)[0], 3
    elif i == 0xfe:
        return struct.unpack_from('<I', raw, offset + 1)[0], 5
    else:
        return struct.unpack_from('<Q', raw, offset + 1)[0], 9


def parse_tx(raw: bytes, offset: int) -> (dict, int):
    start = offset
    tx = {}
    tx['version'] = struct.unpack_from('<I', raw, offset)[0]
    offset += 4
    vin_cnt, sz = read_varint(raw, offset)
    offset += sz
    inputs = []
    for _ in range(vin_cnt):
        prev_txid = raw[offset:offset+32][::-1].hex()
        offset += 32
        prev_index = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        script_len, sz = read_varint(raw, offset)
        offset += sz
        script_sig = raw[offset:offset+script_len].hex()
        offset += script_len
        sequence = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        inputs.append({
            'prev_txid': prev_txid,
            'prev_index': prev_index,
            'script_sig': script_sig,
            'sequence': sequence
        })
    tx['inputs'] = inputs
    vout_cnt, sz = read_varint(raw, offset)
    offset += sz
    outputs = []
    for _ in range(vout_cnt):
        value = struct.unpack_from('<Q', raw, offset)[0]
        offset += 8
        pk_len, sz = read_varint(raw, offset)
        offset += sz
        script_pubkey = raw[offset:offset+pk_len].hex()
        offset += pk_len
        outputs.append({
            'value': value,
            'script_pubkey': script_pubkey
        })
    tx['outputs'] = outputs
    tx['locktime'] = struct.unpack_from('<I', raw, offset)[0]
    offset += 4
    total_size = offset - start
    return tx, total_size

def scriptpubkey_to_address(script_pubkey_hex):
    if not script_pubkey_hex.startswith("76a914") or not script_pubkey_hex.endswith("88ac"):
        raise ValueError("Not a standard P2PKH scriptPubKey")

    pubkey_hash = script_pubkey_hex[6:-4]  # extract 20-byte pubkey hash
    versioned = b'\x00' + bytes.fromhex(pubkey_hash)
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    address_bytes = versioned + checksum
    return base58.b58encode(address_bytes).decode()