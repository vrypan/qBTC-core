from decimal import Decimal
from rocksdict import Rdict
import json
import sys

ADMIN_ADDRESS = "bqs1HpmbeSd8nhRpq5zX5df91D3Xy8pSUovmV"
db_path = sys.argv[1]

db = Rdict(db_path)

sent_transactions = []
received_transactions = []
balance = Decimal("0")

for key, value in db.items():
    key_text = key.decode('utf-8')

    if not key_text.startswith("utxo:"):
        continue

    utxo = json.loads(value.decode('utf-8'))
    sender = utxo["sender"]
    receiver = utxo["receiver"]
    amount = Decimal(utxo["amount"])

    if sender == ADMIN_ADDRESS and receiver != ADMIN_ADDRESS:
        sent_transactions.append((receiver, amount))
        balance -= amount

    elif receiver == ADMIN_ADDRESS and sender != ADMIN_ADDRESS:
        received_transactions.append((sender, amount))
        balance += amount

# Clearly print results
print("\nSent Transactions:")
for receiver, amt in sent_transactions:
    print(f"Sent {amt} coins to {receiver}")

print("\nReceived Transactions:")
for sender, amt in received_transactions:
    print(f"Received {amt} coins from {sender}")

print(f"\nFinal balance for {ADMIN_ADDRESS}: {balance} coins")
