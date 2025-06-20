import os
import random
import time
from protobuf.blockchain_pb2 import (TxInput, TxOutput,
    Block, BlockHeader
)
from protobuf.rpc_pb2_grpc import NodeServiceStub
from protobuf.request_response_pb2 import Empty
import grpc

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

def get_remote_mempool(host: tuple[str, int]):
    channel = grpc.insecure_channel(f"{host[0]}:{host[1]}")
    grpc.channel_ready_future(channel).result(timeout=10)
    stub = NodeServiceStub(channel)
    for tx in stub.GetMempool(Empty()):
        yield tx
    channel.close()
