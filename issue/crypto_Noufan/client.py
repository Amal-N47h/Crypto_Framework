
import os
import sys
import json
import hmac
import hashlib
from datetime import datetime, timezone, timedelta

# ── Pre-shared HMAC keys (same as gateway — provisioned at device setup) ──────
DEVICE_KEYS = {
    "IOMT-DEV-00423": "a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605",
    "IOMT-DEV-00999": "b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502",
    "IOMT-DEV-001":   "c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601",
    "IOMT-DEV-002":   "d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502",
}

DEVICE_ID   = "IOMT-DEV-001"
PACKET_FILE = "packet.json"


# ==============================
# HMAC TOKEN GENERATION
# ==============================
def make_auth_token(device_id: str, timestamp: str, nonce: str) -> str:
    secret  = bytes.fromhex(DEVICE_KEYS[device_id])
    message = f"{device_id}{timestamp}{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


# ==============================
# BUILD AUTH PACKET
# ==============================
def create_packet(mode="normal"):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce     = os.urandom(16).hex()
    device_id = DEVICE_ID

    if mode == "expired":
        # Timestamp 5 minutes in the past — gateway drift check will catch this
        timestamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    elif mode == "replay":
        # Reuse a fixed nonce — gateway nonce check will catch this
        nonce = "aabbccdd11223344aabbccdd11223344"

    elif mode == "forged":
        # Use a random fake token instead of a real HMAC
        token = os.urandom(32).hex()
        packet = {
            "device_id": device_id,
            "timestamp": timestamp,
            "nonce":     nonce,
            "token":     token,
        }
        return packet

    elif mode == "unregistered":
        # Unknown device ID — gateway registry check will catch this
        device_id = "IOMT-DEV-FAKE"
        token = "deadbeef" * 8
        packet = {
            "device_id": device_id,
            "timestamp": timestamp,
            "nonce":     nonce,
            "token":     token,
        }
        return packet

    token = make_auth_token(device_id, timestamp, nonce)

    return {
        "device_id": device_id,
        "timestamp": timestamp,
        "nonce":     nonce,
        "token":     token,
    }


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

    packet = create_packet(mode)

    with open(PACKET_FILE, "w") as f:
        json.dump(packet, f, indent=4)

    print(f"Client  : Packet created  [mode = {mode}]")
    print(f"          device_id : {packet['device_id']}")
    print(f"          timestamp : {packet['timestamp']}")
    print(f"          nonce     : {packet['nonce'][:16]}...")
    print(f"          token     : {packet['token'][:16]}...")
    print(f"          → written to {PACKET_FILE}")
