import json
import time
from hashlib import sha256
from ecdsa import VerifyingKey, NIST256p, BadSignatureError

DB_FILE = "database.json"
used_nonces = set()
ALLOWED_TIME_DRIFT = 30


# ==============================
# LOAD DATABASE
# ==============================
def load_database():
    with open(DB_FILE, "r") as f:
        return json.load(f)


# ==============================
# AUTHENTICATION FUNCTION
# ==============================
def authenticate_device(packet):
    db = load_database()
    registered_devices = db["devices"]

    payload = packet["payload"]
    signature = bytes.fromhex(packet["signature"])

    device_id = payload["device_id"]
    timestamp = payload["timestamp"]
    nonce = payload["nonce"]

    # 1. Check device registration
    if device_id not in registered_devices:
        return "Authentication Failed: Unknown device"

    # 2. Timestamp validation
    current_time = int(time.time())
    if abs(current_time - timestamp) > ALLOWED_TIME_DRIFT:
        return "Authentication Failed: Expired timestamp"

    # 3. Replay protection
    if nonce in used_nonces:
        return "Authentication Failed: Replay detected"

    # 4. Signature verification
    public_key_hex = registered_devices[device_id]["public_key"]
    public_key_bytes = bytes.fromhex(public_key_hex)

    public_key = VerifyingKey.from_string(public_key_bytes, curve=NIST256p)

    payload_bytes = json.dumps(payload, sort_keys=True).encode()
    payload_hash = sha256(payload_bytes).digest()

    try:
        public_key.verify(signature, payload_hash)
    except BadSignatureError:
        return "Authentication Failed: Invalid signature"

    # Store nonce after success
    used_nonces.add(nonce)

    return "Authentication Successful"


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    with open("packet.json", "r") as f:
        packet = json.load(f)

    print(authenticate_device(packet))  # first
    
