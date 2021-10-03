"""
Temporary file for developing/testing purposes of EIP712

Is used to better understand the working of EIP712 data signing
and to create expected results of hashing operations
"""
import sys
from eth_account._utils.structured_data.hashing import (
    load_and_validate_structured_message,
    hash_domain,
    hash_message,
)

file = sys.argv[1]
with open(file, "r") as f:
    content = f.read()

message = load_and_validate_structured_message(content)

domain_hash = hash_domain(message)
message_hash = hash_message(message)
print("domain_hash", domain_hash)
print("message_hash", message_hash)
