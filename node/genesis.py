import time
from gossip.gossip import GENESIS_ADDRESS, ADMIN_ADDRESS
from blockchain.blockchain import serialize_transaction, serialize_block
from blockchain.protobuf_class import Block, Input, Output, TxBody, Transaction
from state.state import blockchain


async def create_genesis_transaction() -> Transaction:
    tx = Transaction()
    tx.txid = "genesis_tx"
    tx.timestamp = 0

    output = tx.outputs.add()
    output.txid = "genesis_tx"
    output.utxo_index = 0
    output.sender = GENESIS_ADDRESS
    output.receiver = ADMIN_ADDRESS
    output.amount = "21000000"
    output.spent = False

    tx.body.msg_str = "genesis"
    tx.body.signature = "genesis_sig"
    tx.body.pubkey = "genesis_key"

    return tx


async def create_genesis_block(db, is_bootstrap: bool, admin_address: str):
    genesis_tx = await create_genesis_transaction()
    genesis_txid = genesis_tx.txid
    genesis_block_hash = "0" * 64
    genesis_utxo_key = f"utxo:{genesis_txid}:0".encode()

    if genesis_utxo_key not in db:
        db.put(genesis_utxo_key, genesis_tx.outputs[0].SerializeToString())
        db.put(b"tx:" + genesis_txid.encode(), genesis_tx.SerializeToString())
        block = Block()
        block.version = 1
        block.previous_hash = ""
        block.block_hash = genesis_block_hash
        block.merkle_root = genesis_txid  # Since only one tx
        block.timestamp = 0
        block.bits = 0
        block.nonce = 0
        block.miner_address = GENESIS_ADDRESS
        block.tx_ids.append(genesis_txid)
        block.full_transactions.append(genesis_tx)
        db.put(b"block:" + genesis_block_hash.encode(), block.SerializeToString())
        blockchain.append(genesis_block_hash)