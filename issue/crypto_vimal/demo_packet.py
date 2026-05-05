# demo_packet.py
"""
Demo script to generate a unified test packet for the dashboard.
This simulates a sender building a packet with all required fields.
"""
import json
import base64
import hashlib
import uuid
from datetime import datetime, timezone

# Simulate device and keys
device_id = "IOMT-DEV-001"
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
nonce = uuid.uuid4().hex

# Simulate encrypted data (normally output of AES/ECC/Hybrid)
encrypted_data = base64.b64encode(b"dummy encrypted payload").decode()
ephemeral_public_key = base64.b64encode(b"dummy eph key").decode()
signature = base64.b64encode(b"dummy signature").decode()

# Build packet (without hash_value first)
packet = {
    "device_id": device_id,
    "timestamp": timestamp,
    "nonce": nonce,
    "encrypted_data": encrypted_data,
    "ephemeral_public_key": ephemeral_public_key,
    "signature": signature
}

# Compute hash_value (canonical JSON, excluding hash_value)
canonical = json.dumps(packet, sort_keys=True, separators=(',', ':')).encode('utf-8')
hash_value = hashlib.sha256(canonical).hexdigest()
packet["hash_value"] = hash_value

# Print packet for dashboard input
def main():
    print(json.dumps(packet, indent=2))

if __name__ == "__main__":
    main()
