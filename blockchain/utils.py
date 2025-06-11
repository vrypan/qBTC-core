# This will probably have to be moved to the blockchain folder
from hashlib import sha256
import protobuf.blockchain_pb2 as pb

def address_from_script_pubkey(script_pubkey: bytes, mainnet=True) -> bytes:
    """
    Extracts the address from a script pubkey.

    Args:
        script_pubkey (bytes): The script pubkey to extract the address from.
        mainnet (bool): Whether the address is for the mainnet or testnet.

    Returns:
        bytes: The address.

    Notes:
        Supports P2PKH, P2SH, P2WPKH, and P2WSH addresses.
    """
    if script_pubkey.startswith(b'\x76\xa9\x14') and script_pubkey[-2:] == b'\x88\xac':
        # P2PKH: OP_DUP OP_HASH160 <20-byte> OP_EQUALVERIFY OP_CHECKSIG
        pubkey_hash = script_pubkey[3:23]
        version = b'\x00' if mainnet else b'\x6f'
        return version + pubkey_hash  # 21 bytes

    elif script_pubkey.startswith(b'\xa9\x14') and script_pubkey[-1:] == b'\x87':
        # P2SH: OP_HASH160 <20-byte> OP_EQUAL
        script_hash = script_pubkey[2:22]
        version = b'\x05' if mainnet else b'\xc4'
        return version + script_hash  # 21 bytes

    # Supports post-SegWit scripts, because why not :-)
    elif script_pubkey.startswith(b'\x00\x14'):
        # P2WPKH: 0 <20-byte>
        witness_program = script_pubkey[2:22]
        return b'\x00' + witness_program  # 21 bytes

    elif script_pubkey.startswith(b'\x00\x20'):
        # P2WSH: 0 <32-byte>
        witness_program = script_pubkey[2:34]
        return b'\x00' + witness_program  # 33 bytes

    return b''

def calculate_tx_hash(tx: pb.Transaction) -> bytes:
    """
    Calculate the hash of a transaction.

    Args:
        tx (pb.Transaction): The transaction to hash.

    Returns:
        bytes: The hash of the transaction.

    Notes:
        The transaction is serialized using protobuf's SerializeToString method.
        A lower-level serialization method must be implemented to ensure immunity
        against protobuf serialization changes.
    """
    return sha256(sha256(tx.SerializeToString()).digest()).digest()
