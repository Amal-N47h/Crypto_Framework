import json
import time
from hashlib import sha256
from ecdsa import SigningKey, NIST256p
import os

DEVICE_ID = "ECG_01"
DB_FILE = "database.json"

# Generate ECC keys (in real case, already stored in device)
signing_key = SigningKey.generate(curve=NIST256p)
verifying_key = signing_key.verifying_key


# ==============================
# REGISTRATION (store public key)
# ==============================
def register_device():
    public_key_hex = verifying_key.to_string().hex()

    # Load existing database if exists
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            db = json.load(f)
    else:
        db = {"devices": {}}

    # Add/update device
    db["devices"][DEVICE_ID] = {
        "public_key": public_key_hex
    }

    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)

    print("Device registered successfully")


# ==============================
# CREATE AUTH PACKET
# ==============================
def create_auth_packet():
    payload = {
        "device_id": DEVICE_ID,
        "timestamp": int(time.time()),
        "nonce": int(time.time() * 1000) % 1000000
    }

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    payload_hash = sha256(payload_bytes).digest()

    signature = signing_key.sign(payload_hash)

    return {
        "payload": payload,
        "signature": signature.hex()
    }


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    register_device()

    packet = create_auth_packet()

    with open("packet.json", "w") as f:
        json.dump(packet, f, indent=4)

    print("Client: Packet sent")