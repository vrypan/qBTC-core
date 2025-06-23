import os
import random
from protobuf.blockchain_pb2 import Transaction, TxInput, TxOutput  # Adjust this import if needed

def random_p2pkh_script_pubkey() -> bytes:
    pubkey_hash = os.urandom(20)
    script_pubkey = (
        b'\x76'              # OP_DUP
        + b'\xa9'            # OP_HASH160
        + b'\x14'            # Push 20 bytes
        + pubkey_hash        # Random pubkey hash
        + b'\x88'            # OP_EQUALVERIFY
        + b'\xac'            # OP_CHECKSIG
    )
    return script_pubkey
def random_p2sh_script_pubkey() -> bytes:
    redeem_script_hash = os.urandom(20)
    script_pubkey = (
        b'\xa9'              # OP_HASH160
        + b'\x14'            # Push 20 bytes
        + redeem_script_hash # Random redeem script hash
        + b'\x87'            # OP_EQUAL
    )
    return script_pubkey

"""
The following are not used, because in qBTC, a tx_output
contains the amount in a separate field, and there is no need
to store the length (protobufs do this)

def random_p2pkh_output(amount_satoshis: int):
    value = struct.pack('<Q', amount_satoshis)  # 8-byte little endian
    script_pubkey = random_p2pkh_script_pubkey()
    script_len = len(script_pubkey).to_bytes(1, 'little')  # VarInt (works if len < 0xfd)
    return value + script_len + script_pubkey
def random_p2sh_output(amount_satoshis: int):
    value = struct.pack('<Q', amount_satoshis)  # 8-byte little endian
    script_pubkey = random_p2sh_script_pubkey()
    script_len = len(script_pubkey).to_bytes(1, 'little')  # VarInt (works if len < 0xfd)
    return value + script_len + script_pubkey
"""

def random_transaction() -> Transaction:
    tx = Transaction()
    tx.version = os.urandom(4)

    num_inputs = random.randint(1, 3)
    num_outputs = random.randint(1, 3)

    for _ in range(num_inputs):
        inp = TxInput()
        inp.txid = os.urandom(32)
        inp.vout = random.randint(0, 10)

        if random.choice([True, False]):
            # P2PKH input
            inp.script_sig = random_p2pkh_script_pubkey()
        else:
            # P2SH input with dummy redeem script
            inp.script_sig = random_p2sh_script_pubkey()

        inp.sequence = random.randint(0, 0xFFFFFFFF)
        tx.inputs.append(inp)

    for _ in range(num_outputs):
        out = TxOutput()
        out.value = random.randint(1, 10_000_000)

        if random.choice([True, False]):
            out.script_pubkey = random_p2pkh_script_pubkey()
        else:
            out.script_pubkey = random_p2sh_script_pubkey()

        tx.outputs.append(out)

    tx.locktime = random.randint(0, 0xFFFFFFFF)
    return tx
