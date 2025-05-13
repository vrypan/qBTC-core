from decimal import Decimal
from rocksdict import Rdict
import sys
from blockchain.protobuf_class import Output  # Assuming this is the compiled protobuf module

ADMIN_ADDRESS = "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"
db_path = sys.argv[1]

db = Rdict(db_path)

sent_transactions = []
received_transactions = []
balance = Decimal("0")

for key, value in db.items():
    key_text = key.decode("utf-8")

    if not key_text.startswith("utxo:"):
        continue

    try:
        utxo = Output()
        utxo.ParseFromString(value)
    except Exception as e:
        print(f"⚠️ Failed to parse key {key_text}: {e}")
        continue

    sender = utxo.sender
    receiver = utxo.receiver
    amount = Decimal(utxo.amount)

    if sender == ADMIN_ADDRESS and receiver != ADMIN_ADDRESS:
        sent_transactions.append((receiver, amount))
        balance -= amount
    elif receiver == ADMIN_ADDRESS:
        received_transactions.append((sender, amount))
        balance += amount

print(f"\n📦 Address: {ADMIN_ADDRESS}")
print(f"💰 Balance: {balance:.8f} qBTC")
print("\n📤 Sent Transactions:")
for rcv, amt in sent_transactions:
    print(f"  → {rcv}: {amt} qBTC")

print("\n📥 Received Transactions:")
for snd, amt in received_transactions:
    print(f"  ← {snd}: {amt} qBTC")