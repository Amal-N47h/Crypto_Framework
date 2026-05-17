"""
receiver.py
===========
Receiver side — checks if an incoming packet is genuine or a replay attack.
Author: Sajan Baby P
"""

import uuid
from datetime import datetime, timezone, timedelta

# ── CONFIGURATION ──────────────────────────────────────
# Any packet older than this many seconds is rejected.
MAX_AGE_SECONDS = 60

# A set that remembers every nonce we have seen.
# If the same nonce comes again, it is a replay.
seen_nonces = set()


# ── TIMESTAMP CHECK ────────────────────────────────────
def is_timestamp_valid(timestamp_str):
    # Convert the timestamp string back into a datetime object.
    packet_time = datetime.fromisoformat(timestamp_str)

    # Get the current time in UTC.
    now = datetime.now(timezone.utc)

    # Calculate how old the packet is in seconds.
    age = (now - packet_time).total_seconds()

    # Accept only if age is between 0 and 60 seconds.
    return 0 <= age <= MAX_AGE_SECONDS


# ── NONCE CHECK ────────────────────────────────────────
def is_nonce_fresh(nonce):
    # If we have seen this nonce before, it is a replay.
    if nonce in seen_nonces:
        return False

    # First time seeing this nonce — store it and accept.
    seen_nonces.add(nonce)
    return True


# ── MAIN CHECK ─────────────────────────────────────────
def check_packet(packet):
    # Check 1: Is the timestamp fresh?
    if not is_timestamp_valid(packet["timestamp"]):
        return False, "FAILED — EXPIRED TIMESTAMP"

    # Check 2: Is the nonce new?
    if not is_nonce_fresh(packet["nonce"]):
        return False, "FAILED — DUPLICATE NONCE"

    # Both checks passed.
    return True, "PASSED"


# ── DEMO ───────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  Receiver — Packet Verification")
    print("=" * 50)

    # Build a fresh legitimate packet.
    packet = {
        "device_id": "DEVICE_001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce":     str(uuid.uuid4()),
        "data":      "heart_rate=82"
    }

    print("\nPacket received:")
    print(f"  timestamp : {packet['timestamp']}")
    print(f"  nonce     : {packet['nonce']}")

    result, reason = check_packet(packet)
    print(f"\nResult : {reason}")
