
import os
import json
import hmac
import hashlib
import sqlite3
from datetime import datetime, timezone

# ── Config ─────────────────────────────────────────────────────────────────────
ALLOWED_DRIFT = 60   # seconds — max age of a packet
MAX_FAILURES  = 5    # auto-block after this many consecutive failures
REGISTRY_DB   = "database.db"
PACKET_FILE   = "packet.json"

# ── Pre-shared HMAC keys (must match client.py) ────────────────────────────────
DEVICE_KEYS = {
    "IOMT-DEV-00423": "a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605",
    "IOMT-DEV-00999": "b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502",
    "IOMT-DEV-001":   "c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601",
    "IOMT-DEV-002":   "d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502",
}

# Nonces are persisted in the DB so replay protection works across runs


# ==============================
# DEVICE REGISTRY  (SQLite)
# ==============================
def init_registry():
    """Create registry DB and seed all known devices. Called once at startup."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id       TEXT PRIMARY KEY,
            status          TEXT DEFAULT 'ACTIVE',
            failed_attempts INTEGER DEFAULT 0,
            last_seen       TEXT,
            registered_at   TEXT
        )
    """)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for did in DEVICE_KEYS:
        c.execute("""
            INSERT OR IGNORE INTO devices (device_id, status, registered_at)
            VALUES (?, 'ACTIVE', ?)
        """, (did, now))
    c.execute("""
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()


def _nonce_seen(nonce: str) -> bool:
    """Check if nonce was used before — persists across runs."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("SELECT 1 FROM used_nonces WHERE nonce = ?", (nonce,))
    found = c.fetchone() is not None
    conn.close()
    return found


def _save_nonce(nonce: str):
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO used_nonces (nonce) VALUES (?)", (nonce,))
    conn.commit()
    conn.close()


def get_device(device_id: str):
    """Return device record from registry, or None if not found."""
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def _update_device(device_id: str, success: bool):
    """Update failed attempts counter. Auto-block at MAX_FAILURES."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    if success:
        c.execute("""UPDATE devices
                     SET failed_attempts=0, last_seen=?, status='ACTIVE'
                     WHERE device_id=?""", (now, device_id))
    else:
        c.execute("""UPDATE devices
                     SET failed_attempts=failed_attempts+1, last_seen=?
                     WHERE device_id=?""", (now, device_id))
        c.execute("""UPDATE devices SET status='BLOCKED'
                     WHERE device_id=? AND failed_attempts >= ?""",
                  (device_id, MAX_FAILURES))
    conn.commit()
    conn.close()


# ==============================
# HMAC TOKEN (recompute to verify)
# ==============================
def _generate_token(device_id: str, timestamp: str, nonce: str) -> str:
    secret  = bytes.fromhex(DEVICE_KEYS[device_id])
    message = f"{device_id}{timestamp}{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


# ==============================
# AUTHENTICATION FUNCTION
# ==============================
def authenticate_device(packet: dict) -> str:
    device_id = packet["device_id"]
    timestamp = packet["timestamp"]
    nonce     = packet["nonce"]
    token     = packet["token"]

    # Step 1 — Registry check
    device = get_device(device_id)
    if device is None:
        return "Authentication Failed: Unregistered device"

    # Step 2 — Status check
    if device["status"] == "BLOCKED":
        return f"Authentication Failed: Device blocked after {MAX_FAILURES} failed attempts"
    if device["status"] == "SUSPENDED":
        return "Authentication Failed: Device suspended by operator"

    # Step 3 — Timestamp check
    try:
        pkt_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = abs((datetime.now(timezone.utc) - pkt_time).total_seconds())
        if age > ALLOWED_DRIFT:
            return f"Authentication Failed: Expired timestamp ({age:.0f}s old)"
    except Exception:
        return "Authentication Failed: Invalid timestamp format"

    # Step 4 — Replay check (persisted in DB — works across separate runs)
    if _nonce_seen(nonce):
        return "Authentication Failed: Replay detected (duplicate nonce)"

    # Step 5 — HMAC verification (constant-time compare — prevents timing attacks)
    try:
        expected = _generate_token(device_id, timestamp, nonce)
    except (KeyError, ValueError):
        _update_device(device_id, success=False)
        return "Authentication Failed: No HMAC key for this device"

    if not hmac.compare_digest(expected, token):
        _update_device(device_id, success=False)
        return "Authentication Failed: Invalid token (forged or cloned device)"

    # All checks passed
    _save_nonce(nonce)
    _update_device(device_id, success=True)
    return "Authentication Successful"


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    init_registry()

    with open(PACKET_FILE, "r") as f:
        packet = json.load(f)

    print(f"Server  : Packet received")
    print(f"          device_id : {packet['device_id']}")
    print(f"          timestamp : {packet['timestamp']}")
    print(f"          nonce     : {packet['nonce'][:16]}...")
    print(f"          token     : {packet['token'][:16]}...")
    print()

    result = authenticate_device(packet)
    print(f"Result  : {result}")
