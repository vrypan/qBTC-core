# This will probably have to be moved to the blockchain folder
from hashlib import sha256
import protobuf.blockchain_pb2 as pb

def parse_p2pkh_script_sig(script_sig: bytes):
    """
    Parses a P2PKH scriptSig and extracts:
    - The signature (DER-encoded)
    - The SIGHASH type
    - The public key

    Args:
        script_sig (bytes): The raw scriptSig

    Returns:
        dict: Parsed components
    """
    # First byte: length of the signature (includes sighash type)
    sig_len = script_sig[0]
    signature_with_sighash = script_sig[1:1 + sig_len]

    # Signature is all bytes except the last one (sighash type)
    signature = signature_with_sighash[:-1]
    sighash_type = signature_with_sighash[-1]

    # Next byte: length of the pubkey
    pubkey_len = script_sig[1 + sig_len]
    pubkey = script_sig[1 + sig_len + 1 : 1 + sig_len + 1 + pubkey_len]

    return {
        "signature": signature,
        "sighash_type": sighash_type,
        "pubkey": pubkey
    }

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
        pubkey_hash = script_pubkey[3:-2]
        version = b'\x00'
        return version + pubkey_hash  # 21 bytes

    elif script_pubkey.startswith(b'\xa9\x14') and script_pubkey[-1:] == b'\x87':
        # P2SH: OP_HASH160 <20-byte> OP_EQUAL
        script_hash = script_pubkey[2:-1]
        version = b'\x05'
        return version + script_hash  # 21 bytes
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
