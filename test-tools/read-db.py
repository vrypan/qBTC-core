from rocksdict import Rdict
import sys


# Load database directory passed as argument
db_path = sys.argv[1]

# Open DB (read_only is True to avoid modifying it)
db = Rdict(db_path)

# Iterate over keys and values
for key, value in db.items():
		print(f"Key: {key}, Value: {value}")
