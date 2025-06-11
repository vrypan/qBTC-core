from rocksdict import Rdict, Options
import logging
import protobuf.blockchain_pb2 as pb
from blockchain.utils import address_from_script_pubkey, calculate_tx_hash
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

"""
This is a db wrapper. We are not using locking, because all writes are consistent.
For example, when writing a transaction to the database, even if multiple processes
are writing to the same key, the data will be the same (if the hash is the same).

The only exception is set_tip() (two separate processes may write a different tip
hash), but even in this case, the database will eventually be consistent as more blocks
are added to the chain.

Transactions are stored as separate entries, to allow efficient lookups when validatiing
inputs and outputs.

***NO VALIDATION***: This module does not implement any blockchain validation logic.
It expects that transactions and blocks stored have already been validated.

Proper use:
1. Initialize the database once:

from database import init_db
init_db("database.db")

2. In every other case, use db_instance() to access the database instance.
However, accessinng the database instance directly should be rare, since we have
helper functions to read and write specific datatypes (ex. block_set(), block_get(), etc.)

from database import database2 as db
last_block = db.tip_get()
"""

__db: Optional[Rdict] = None
def init_db(path="data.db"):
    """
    Initializes the RocksDict database singleton. Call once at startup.

    Args:
        path (str): The path to the database file.

    Returns:
        Rdict: The initialized database instance.
    """
    global __db
    if __db is None:
        try:
            __db = Rdict(path, options=Options(raw_mode=True))
            logging.info(f"Database initialized at {path}")
        except Exception as e:
            logging.error(f"Failed to initialize RocksDB at {path}: {e}")
            raise
    else:
        logging.info(f"Database already initialized at {__db.path}")
    return __db

def db_instance() -> Rdict:
    """
    Get the database instance after it has been initialized.

    Returns:
        Rdict: The database instance.

    Raises:
        RuntimeError: If init_db() hasn't been called yet.
    """
    if __db is None:
        raise RuntimeError("Database not initialized. Call init_db(path) first.")
    return __db

def utxo_set(txid: bytes, vout: int, output: pb.TxOutput) -> bytes:
    """
    Add a UTXO in the database. The key used is `address:<addr>:<suffix>`
    This makes it easy to find UTXOs for a given address using range scans.

    When generating `suffix`, we trim txid to 8 bytes to save storage.
    In theory, there may be collisions, but it is highly unlikely
    to have the same `<txid[0:8]><vout>` for the same address.

    Args:
        txid (bytes): The hash of the transaction.
        vout (int): The index of the output.
        output (pb.Output): The output to set.

    Returns:
        bytes: The key of the UTXO saved.
    """
    db = db_instance()
    address = address_from_script_pubkey(output.script_pubkey)
    key = b"addr:" + address + b":" + txid[:8] + vout.to_bytes(4, 'big')
    value = pb.Utxo(txid=txid, vout=vout, output=output).SerializeToString()
    db[key] = value
    return key

def utxo_get(address: bytes) -> list[pb.Utxo]:
    """
    Get all UTXOs for a given address.

    Args:
        address (bytes): The address to get UTXOs for.

    Returns:
        list[pb.Utxo]: A list of UTXOs.
    """
    db = db_instance()
    prefix = b"addr:" + address + b":"
    utxos = []

    for key, value in db.items(from_key=prefix):
        if not (isinstance(key, bytes) and key.startswith(prefix)):
            break
        utxo = pb.Utxo()
        utxo.ParseFromString(value)
        utxos.append(utxo)
    return utxos

def utxo_delete(input: pb.TxInput):
    """
    Delete a UTXO based on TxInput, using a tx_lookup(txid) function.

    Args:
        input (pb.TxInput): The input referencing the UTXO to spend.
    """
    db = db_instance()
    txid = input.txid
    vout = input.vout
    tx = tx_get(txid)
    # Disabled this test, while not in prod.
    # if tx is None or vout >= len(tx.outputs):
    #     raise ValueError("Referenced transaction or output not found")
    output = tx.outputs[vout]
    address = address_from_script_pubkey(output.script_pubkey)
    addr_key = b"addr:" + address + b":" + txid[:8] + vout.to_bytes(4, 'big')
    db.delete(addr_key)

def tx_set(tx: pb.Transaction) -> bytes:
    """
    Set a transaction in the database. The key used is `tx:<hash>`

    Args:
        tx (pb.Transaction): The transaction to set.

    Returns:
        bytes: The hash of the transaction.
    """
    db = db_instance()
    hash = calculate_tx_hash(tx)
    db[b"tx:" + hash] = tx.SerializeToString()
    for vin in tx.inputs:
        utxo_delete(vin)
    for vout, output in enumerate(tx.outputs):
        utxo_set(hash, vout, output)
    return hash

def tx_get(hash: bytes) -> pb.Transaction:
    """
    Get a transaction from the database.

    Args:
        hash (bytes): The hash of the transaction.

    Returns:
        pb.Transaction: The transaction.
    """
    db = db_instance()
    tx_bytes = db.get(b"tx:" + hash)
    tx = pb.Transaction()
    if tx_bytes:
        tx.ParseFromString(tx_bytes)
    return tx

def block_set(block: pb.Block):
    """
    Set a block in the database.

    Args:
        block (pb.Block): The block to set.
    """
    db = db_instance()
    db_block = pb.DbBlock()
    db_block.hash = block.hash
    db_block.height = block.height
    db_block.header.CopyFrom(block.header)
    db_block.transaction_count = block.transaction_count
    for tx in block.tx:
        tx_hash = tx_set(tx)
        db_block.txid.append(tx_hash)
    db[b"block:" + block.hash] = db_block.SerializeToString()
    tip_set(db_block)

def block_exists(block_hash: bytes) -> bool:
    """
    Check if a block exists in the database.

    Args:
        block_hash (bytes): The hash of the block.

    Returns:
        bool: True if the block exists, False otherwise.
    """
    db = db_instance()
    return db.get(b"block:" + block_hash) is not None

def block_get(block_hash: bytes) -> pb.Block:
    """
    Get a block from the database.

    Args:
        block_hash (bytes): The hash of the block.

    Returns:
        pb.Block: The block.
    """
    db = db_instance()
    block_bytes = db.get(b"block:" + block_hash)
    db_block = pb.DbBlock()
    block = pb.Block()
    if block_bytes:
        db_block.ParseFromString(block_bytes)
    for tx_hash in db_block.txid:
        tx = tx_get(tx_hash)
        block.tx.append(tx)
    return block

def tip_set(block: pb.DbBlock):
    """
    Set the tip block in the database.

    Args:
        block (pb.DbBlock): The block to set as the tip.
    """
    db = db_instance()
    db[b"chain_tip"] = block.hash

def tip_get() -> pb.Block:
    """
    Get the tip block from the database.

    Returns:
        pb.Block: The tip block.
    """
    db = db_instance()
    block_hash = db.get(b"chain_tip")
    if block_hash:
        return block_get(block_hash)
    return pb.Block()
