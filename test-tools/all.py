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
	print(f"{key} :: {value}")
