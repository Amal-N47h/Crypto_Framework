"""
auth.py  —  HMAC-SHA256 Device Authentication with Registry
============================================================
Copy this SAME file to both gateway/ and device/ folders.

Device Registry tracks:
  - registered devices with pre-shared HMAC keys
  - device status: ACTIVE | SUSPENDED | BLOCKED
  - failed attempt counter (auto-blocks after 5 failures)
  - last seen timestamp

Unauthorized device attack types detected:
  1. UNREGISTERED  — device_id not in registry
  2. BLOCKED       — auto-blocked after repeated failures
  3. SUSPENDED     — manually suspended by operator
  4. FORGED_TOKEN  — valid device_id but wrong HMAC key
  5. EXPIRED       — timestamp too old (replay)
  6. REPLAY        — nonce seen before
"""

import hmac
import hashlib
import os
import sqlite3
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
ALLOWED_DRIFT   = 60   # seconds
MAX_FAILURES    = 5    # auto-block after this many consecutive failures
REGISTRY_DB     = "device_registry.db"

# ── Pre-shared HMAC keys (provisioned at device setup) ───────────────────────
# Generate a key:  python -c "import os; print(os.urandom(32).hex())"
DEVICE_KEYS = {
    "IOMT-DEV-00423": "a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605",
    "IOMT-DEV-00999": "b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502",
    "IOMT-DEV-001":   "c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601",
    "IOMT-DEV-002":   "d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Device Registry  (SQLite — gateway only)
# ═══════════════════════════════════════════════════════════════════════════

def init_registry():
    """Create registry DB and seed registered devices."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id       TEXT PRIMARY KEY,
            status          TEXT DEFAULT 'ACTIVE',
            failed_attempts INTEGER DEFAULT 0,
            last_seen       TEXT,
            registered_at   TEXT,
            notes           TEXT
        )
    """)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for did in DEVICE_KEYS:
        c.execute("""
            INSERT OR IGNORE INTO devices (device_id, status, registered_at)
            VALUES (?, 'ACTIVE', ?)
        """, (did, now))
    conn.commit()
    conn.close()


def get_device(device_id: str) -> dict | None:
    """Return device record or None if not registered."""
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_devices() -> list:
    """Return all registered devices for the dashboard."""
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY device_id")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def _update_device(device_id: str, success: bool):
    """Update device after auth attempt — increment failures or reset."""
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


def set_device_status(device_id: str, status: str, notes: str = ""):
    """Manually set device status: ACTIVE | SUSPENDED | BLOCKED."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("""UPDATE devices SET status=?, notes=?, failed_attempts=0
                 WHERE device_id=?""", (status, notes, device_id))
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════════════════
#  HMAC Token  (used by both device and gateway)
# ═══════════════════════════════════════════════════════════════════════════

def generate_token(device_id: str, timestamp: str, nonce: str) -> str:
    """Compute HMAC-SHA256 token from device_id + timestamp + nonce."""
    if device_id not in DEVICE_KEYS:
        raise ValueError(f"Unknown device: {device_id}")
    secret  = bytes.fromhex(DEVICE_KEYS[device_id])
    message = f"{device_id}{timestamp}{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def make_auth_token(device_id: str, timestamp: str, nonce: str) -> str:
    """Device calls this to produce its auth token before sending."""
    return generate_token(device_id, timestamp, nonce)


# ═══════════════════════════════════════════════════════════════════════════
#  Verification  (gateway calls this)
# ═══════════════════════════════════════════════════════════════════════════

def verify_device(device_id: str, timestamp: str, nonce: str,
                  token: str, seen_nonces: set) -> tuple:
    """
    Full 5-step device authentication.
    Returns (True, "Authenticated", "OK")
         or (False, "reason", "ATTACK_TYPE")

    Attack types:
      UNREGISTERED  — not in registry at all
      BLOCKED       — auto-blocked after too many failures
      SUSPENDED     — manually suspended
      REPLAYED      — expired timestamp or duplicate nonce
      FORGED_TOKEN  — wrong HMAC key (impersonation attempt)
    """
    # 1. Registry check
    device = get_device(device_id)
    if device is None:
        return False, f"Unregistered device: {device_id}", "UNREGISTERED"

    # 2. Status check
    if device["status"] == "BLOCKED":
        return False, f"Device blocked after {MAX_FAILURES} failed attempts", "BLOCKED"
    if device["status"] == "SUSPENDED":
        return False, f"Device suspended by operator: {device_id}", "SUSPENDED"

    # 3. Timestamp check
    try:
        pkt_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = abs((datetime.now(timezone.utc) - pkt_time).total_seconds())
        if age > ALLOWED_DRIFT:
            return False, f"Expired timestamp ({age:.0f}s old)", "REPLAYED"
    except Exception:
        return False, "Invalid timestamp format", "INVALID_FORMAT"

    # 4. Nonce replay check
    if nonce in seen_nonces:
        return False, "Duplicate nonce — replay attack", "REPLAYED"

    # 5. HMAC token check (constant-time comparison)
    try:
        expected = generate_token(device_id, timestamp, nonce)
    except ValueError:
        _update_device(device_id, success=False)
        return False, f"No HMAC key for: {device_id}", "UNREGISTERED"

    if not hmac.compare_digest(expected, token):
        _update_device(device_id, success=False)
        return False, f"Invalid HMAC token — forged/cloned device: {device_id}", "FORGED_TOKEN"

    # All checks passed
    seen_nonces.add(nonce)
    _update_device(device_id, success=True)
    return True, "Authenticated", "OK"