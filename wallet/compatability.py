import execjs
import oqs
import json

# JavaScript code using noble's ml-dsa87
js_code = """
const { ml_dsa87 } = require('@noble/post-quantum/ml-dsa');
const { randomBytes } = require('@noble/post-quantum/utils');

function toHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateAndSign(message) {
  const seed = randomBytes(32);
  const { publicKey, secretKey } = ml_dsa87.keygen(seed);
  const msgBytes = new TextEncoder().encode(message);
  const signature = ml_dsa87.sign(secretKey, msgBytes);

  return {
    publicKey: toHex(publicKey),
    signature: toHex(signature),
    message: message
  };
}

module.exports = { generateAndSign };
"""

# Compile and run JS to get keypair and signature
ctx = execjs.compile(js_code)
result = ctx.call("generateAndSign", "hello world")

# Extract from JS result
public_key_hex = result["publicKey"]
signature_hex = result["signature"]
message = result["message"]

# Convert to bytes
public_key_bytes = bytes.fromhex(public_key_hex)
signature_bytes = bytes.fromhex(signature_hex)
message_bytes = message.encode()

# Verify using liboqs
with oqs.Signature("ML-DSA-87") as verifier:
    is_valid = verifier.verify(message_bytes, signature_bytes, public_key_bytes)

# Output result
print("Public Key:", public_key_hex[:64], "...")
print("Signature :", signature_hex[:64], "...")
print("Message   :", message)
print("Signature valid (noble → liboqs)?", is_valid)
