import os
import random
import hashlib
from ecdsa import SigningKey, SECP256k1
from protobuf.blockchain_pb2 import Transaction, TxInput, TxOutput  # Adjust this import if needed

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

def hash160(data):
    return ripemd160(sha256(data))

def p2pkh_script_pubkey(pubkey_hash):
    return b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'  # OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

def p2sh_script_pubkey(script_hash):
    return b'\xa9\x14' + script_hash + b'\x87'  # OP_HASH160 <scripthash> OP_EQUAL

def p2pkh_script_sig(signature, pubkey):
    return bytes([len(signature)]) + signature + bytes([len(pubkey)]) + pubkey

def p2sh_script_sig(redeem_script, signature):
    return (
        bytes([len(signature)]) + signature +
        bytes([len(redeem_script)]) + redeem_script
    )

def random_transaction() -> Transaction:
    tx = Transaction()
    tx.version = os.urandom(4)

    num_inputs = random.randint(1, 3)
    num_outputs = random.randint(1, 3)

    for _ in range(num_inputs):
        inp = TxInput()
        inp.txid = os.urandom(32)
        inp.vout = random.randint(0, 10)

        # Create a random signing key and fake signature
        sk = SigningKey.generate(curve=SECP256k1)
        vk = sk.verifying_key
        pubkey = vk.to_string()
        signature = os.urandom(70)  # Fake 70-byte signature

        if random.choice([True, False]):
            # P2PKH input
            inp.script_sig = p2pkh_script_sig(signature, pubkey)
        else:
            # P2SH input with dummy redeem script
            redeem_script = b'\x51'  # OP_1 (just for test)
            inp.script_sig = p2sh_script_sig(redeem_script, signature)

        inp.sequence = random.randint(0, 0xFFFFFFFF)
        tx.inputs.append(inp)

    for _ in range(num_outputs):
        out = TxOutput()
        out.value = random.randint(1, 10_000_000)

        # Generate pubkey and choose script type
        sk = SigningKey.generate(curve=SECP256k1)
        pubkey = sk.verifying_key.to_string()
        pubkey_hash = hash160(pubkey)

        if random.choice([True, False]):
            out.script_pubkey = p2pkh_script_pubkey(pubkey_hash)
        else:
            redeem_script = b'\x51'  # Dummy redeem script
            script_hash = hash160(redeem_script)
            out.script_pubkey = p2sh_script_pubkey(script_hash)

        tx.outputs.append(out)

    tx.locktime = random.randint(0, 0xFFFFFFFF)
    return tx
