#wallet.py

import os
import json
import sys
import getpass
import execjs
import logging

WALLET_FILENAME = "wallet.json"

def load_wallet_file(filename: str = WALLET_FILENAME):
    """Load a wallet from a JSON file if it exists."""
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return None

def save_wallet_file(wallet, filename: str = WALLET_FILENAME):
    """Save a wallet to a JSON file."""
    with open(filename, "w") as f:
        json.dump(wallet, f, indent=2)

def generate_wallet(password: str):
    """Generate a new wallet with ML-DSA-87 keys and encrypt the private key."""
    js_code = """
    const crypto = require('crypto');
    const { ml_dsa87 } = require('@noble/post-quantum/ml-dsa');
    const { randomBytes } = require('@noble/post-quantum/utils');
    const { sha3_256 } = require('js-sha3');
    const bs58Module = require('bs58');
    const bs58 = bs58Module.default || bs58Module;

    function uint8ArrayToHex(array) {
      return Array.from(array).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function deriveQSafeAddress(pubkey) {
      const hashBuffer = sha3_256.arrayBuffer(pubkey);
      const sha3Hash = new Uint8Array(hashBuffer);
      const versionedHash = new Uint8Array(1 + 20);
      versionedHash[0] = 0x00;
      versionedHash.set(sha3Hash.slice(0, 20), 1);
      const checksum = Buffer.from(sha3_256.arrayBuffer(Buffer.from(versionedHash))).slice(0, 4);
      const addressBytes = Buffer.concat([Buffer.from(versionedHash), checksum]);
      return "bqs" + bs58.encode(addressBytes);
    }

    function encryptPrivateKeySync(privateKeyHex, password) {
      const salt = crypto.randomBytes(16);
      const iv = crypto.randomBytes(12);
      const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      let encrypted = cipher.update(privateKeyHex, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      const authTag = cipher.getAuthTag();
      const encryptedBuffer = Buffer.from(encrypted, 'base64');
      const combined = Buffer.concat([encryptedBuffer, authTag]);
      return {
        encryptedPrivateKey: combined.toString('base64'),
        PrivateKeySalt: salt.toString('base64'),
        PrivateKeyIV: iv.toString('base64')
      };
    }

    function generateWalletSync(password) {
      const seed = randomBytes(32);
      const keys = ml_dsa87.keygen(seed);
      const address = deriveQSafeAddress(keys.publicKey);
      const encryptionResult = encryptPrivateKeySync(uint8ArrayToHex(keys.secretKey), password);
      return {
        address: address,
        encryptedPrivateKey: encryptionResult.encryptedPrivateKey,
        PrivateKeySalt: encryptionResult.PrivateKeySalt,
        PrivateKeyIV: encryptionResult.PrivateKeyIV,
        publicKey: uint8ArrayToHex(keys.publicKey)
      };
    }
    module.exports = { generateWalletSync };
    """
    try:
        ctx = execjs.compile(js_code)
        return ctx.call("generateWalletSync", password)
    except Exception as e:
        logging.error(f"Error generating wallet: {e}")
        sys.exit(1)

def unlock_wallet(wallet, password: str):
    """Unlock an existing wallet by decrypting the private key."""
    js_code = """
    const crypto = require('crypto');

    function unlockWalletSync(walletJSON, password) {
      const wallet = JSON.parse(walletJSON);
      if (!wallet.encryptedPrivateKey || !wallet.PrivateKeySalt || !wallet.PrivateKeyIV) {
        throw new Error("Missing wallet fields.");
      }
      const salt = Buffer.from(wallet.PrivateKeySalt, 'base64');
      const iv = Buffer.from(wallet.PrivateKeyIV, 'base64');
      const encryptedData = Buffer.from(wallet.encryptedPrivateKey, 'base64');
      const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
      const tagLength = 16;
      const ciphertext = encryptedData.slice(0, encryptedData.length - tagLength);
      const authTag = encryptedData.slice(encryptedData.length - tagLength);
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv);
      decipher.setAuthTag(authTag);
      let decrypted = decipher.update(ciphertext, undefined, 'utf8');
      decrypted += decipher.final('utf8');
      return {
        privateKey: decrypted,
        publicKey: wallet.publicKey,
        address: wallet.address
      };
    }
    module.exports = { unlockWalletSync };
    """
    try:
        ctx = execjs.compile(js_code)
        wallet_json = json.dumps(wallet)
        return ctx.call("unlockWalletSync", wallet_json, password)
    except Exception as e:
        logging.error(f"Error unlocking wallet: {e}")
        sys.exit(1)

def sign_transaction(message: str, private_key: str) -> str:
    """Sign a message using the wallet's private key."""
    js_code = """
    const { ml_dsa87 } = require('@noble/post-quantum/ml-dsa');

    function signTransaction(message, privkeyHex) {
      const privateKey = Uint8Array.from(privkeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      const messageBytes = new TextEncoder().encode(message);
      const signature = ml_dsa87.sign(privateKey, messageBytes);
      return Array.from(signature).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }
    module.exports = { signTransaction };
    """
    try:
        ctx = execjs.compile(js_code)
        signature = ctx.call("signTransaction", message, private_key)
        logging.debug(f"Signed message '{message}' with signature: {signature[:10]}...")
        return signature
    except Exception as e:
        logging.error(f"Failed to sign transaction: {e}")
        raise RuntimeError(f"Failed to sign transaction: {e}")

def verify_transaction(message: str, signature: str, public_key: str) -> bool:
    """Verify a transaction signature using the public key."""
    js_code = """
    const { ml_dsa87 } = require('@noble/post-quantum/ml-dsa');

    function verifyTransaction(message, signatureHex, pubkeyHex) {
      const publicKey = Uint8Array.from(pubkeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      const signature = Uint8Array.from(signatureHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      const messageBytes = new TextEncoder().encode(message);
      return ml_dsa87.verify(publicKey, messageBytes, signature);
    }
    module.exports = { verifyTransaction };
    """
    try:
        logging.debug(f"Verifying: message='{message}', signature={signature[:10]}..., pubkey={public_key[:10]}...")
        ctx = execjs.compile(js_code)
        result = ctx.call("verifyTransaction", message, signature, public_key)
        if result:
            logging.info(f"Transaction verified successfully for message: {message}")
        else:
            logging.error(f"Verification failed for message: {message}, signature: {signature[:10]}..., pubkey: {public_key[:10]}...")
        return result
    except Exception as e:
        logging.error(f"Error in verify_transaction: {e}")
        raise RuntimeError(f"Failed to verify transaction: {e}")

def get_or_create_wallet(filename: str = WALLET_FILENAME, password: str = None) -> dict:
    """Load an existing wallet or generate a new one."""
    wallet = load_wallet_file(filename)
    if wallet:
        if password is None:
            password = getpass.getpass(f"Enter password to unlock {filename}: ")
        try:
            return unlock_wallet(wallet, password)
        except Exception as e:
            logging.error(f"Failed to unlock wallet: {e}")
            sys.exit(1)
    else:
        if password is None:
            password = getpass.getpass("Enter a new password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                logging.error("Passwords do not match")
                sys.exit(1)
        wallet = generate_wallet(password)
        save_wallet_file(wallet, filename)
        logging.info(f"Wallet generated at {filename}")
        return unlock_wallet(wallet, password)

if __name__ == "__main__":
    wallet = get_or_create_wallet()
    print(f"Unlocked wallet address: {wallet['address']}")
    message = "Sample transaction data"
    signature = sign_transaction(message, wallet['privateKey'])
    print(f"Signature: {signature}")
    is_valid = verify_transaction(message, signature, wallet['publicKey'])
    print(f"Verification: {is_valid}")