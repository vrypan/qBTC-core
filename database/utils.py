# This will probably have to be moved to the blockchain folder

def extract_address(script_pubkey: bytes, mainnet=True) -> bytes:
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
