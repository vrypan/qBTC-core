import os
import random
import time
from protobuf.blockchain_pb2 import (
    Transaction, TxInput, TxOutput,
    Block, BlockHeader
)

def random_transaction() -> Transaction:
    """
    Generate a random transaction. Used for testing and simulation purposes.
    """
    tx = Transaction()
    tx.version = os.urandom(4)

    num_inputs = random.randint(1, 3)
    num_outputs = random.randint(1, 3)

    for _ in range(num_inputs):
        inp = TxInput()
        inp.txid = os.urandom(32)
        inp.vout = random.randint(0, 10)
        inp.script_sig = os.urandom(random.randint(20, 100))
        inp.sequence = random.randint(0, 0xFFFFFFFF)
        tx.inputs.append(inp)

    for _ in range(num_outputs):
        out = TxOutput()
        out.value = random.randint(1, 10_000_000)
        out.script_pubkey = os.urandom(random.randint(20, 100))
        tx.outputs.append(out)

    tx.locktime = random.randint(0, 0xFFFFFFFF)
    return tx

def random_block(height: int) -> Block:
    """
    Generate a random block. Used for testing and simulation purposes.
    """
    blk = Block()
    blk.height = height
    blk.size = random.randint(512, 2048)
    blk.hash = os.urandom(32)

    # Create BlockHeader
    header = BlockHeader()
    header.version = 1
    header.previous_hash = os.urandom(32)
    header.merkle_root = os.urandom(32)
    header.timestamp = int(time.time())
    header.difficulty = 0x1d00ffff  # example value
    header.nonce = random.randint(0, 0xFFFFFFFF)
    blk.header.CopyFrom(header)

    # Add random transactions
    blk.transaction_count = random.randint(1, 5)
    for _ in range(blk.transaction_count):
        blk.tx.append(random_transaction())

    return blk
