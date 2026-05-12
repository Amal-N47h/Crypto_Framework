"""
auth.py  —  HMAC-SHA256 Device Authentication
==============================================

On the DEVICE side:
  - Only make_auth_token() is used (to generate tokens before sending)
  - The registry functions (init_registry, get_device, etc.) are only
    called on the GATEWAY side

Returns 3-tuple so crypto_engine.py can map attack types:
  (True,  "Authenticated",   "OK")
  (False, "reason string",   "ATTACK_TYPE")

Attack types returned:
  UNREGISTERED  — device_id not in DEVICE_KEYS
  REPLAYED      — expired timestamp or duplicate nonce
  FORGED_TOKEN  — wrong HMAC key
  BLOCKED       — auto-blocked (gateway only)
  SUSPENDED     — manually suspended (gateway only)
  INVALID_FORMAT — bad timestamp format
"""

import hmac
import hashlib
import os
import sqlite3
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────
ALLOWED_DRIFT = 60    # seconds
MAX_FAILURES  = 5     # auto-block after this many consecutive failures
REGISTRY_DB   = "device_registry.db"

# ── Pre-shared HMAC keys — provisioned at device setup ───────────────────────
# Generate a new key:  python -c "import os; print(os.urandom(32).hex())"
DEVICE_KEYS = {
    "IOMT-DEV-00423": "a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605",
    "IOMT-DEV-00999": "b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502",
    "IOMT-DEV-001":   "c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601",
    "IOMT-DEV-002":   "d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Device Registry  
# ═══════════════════════════════════════════════════════════════════════════

def init_registry():
    """Create registry DB and seed all devices from DEVICE_KEYS."""
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


def get_device(device_id: str):
    """Return device record dict or None if not found."""
    try:
        conn = sqlite3.connect(REGISTRY_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        row = c.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def get_all_devices() -> list:
    """Return all registered devices for the dashboard."""
    try:
        conn = sqlite3.connect(REGISTRY_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM devices ORDER BY device_id")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def _update_device(device_id: str, success: bool):
    """Update failure counter or reset on success. Auto-block at MAX_FAILURES."""
    try:
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
    except Exception:
        pass


def set_device_status(device_id: str, status: str, notes: str = ""):
    """Manually set device status: ACTIVE | SUSPENDED | BLOCKED."""
    try:
        conn = sqlite3.connect(REGISTRY_DB)
        c = conn.cursor()
        c.execute("""UPDATE devices SET status=?, notes=?, failed_attempts=0
                     WHERE device_id=?""", (status, notes, device_id))
        conn.commit()
        conn.close()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  HMAC Token  (used by BOTH device and gateway)
# ═══════════════════════════════════════════════════════════════════════════

def generate_token(device_id: str, timestamp: str, nonce: str) -> str:
    """
    Compute HMAC-SHA256 token.
    message = device_id + timestamp + nonce (concatenated as strings)
    Both device and gateway call this with the same inputs → same output.
    """
    if device_id not in DEVICE_KEYS:
        raise ValueError(f"Unknown device: {device_id}")
    secret  = bytes.fromhex(DEVICE_KEYS[device_id])
    message = f"{device_id}{timestamp}{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def make_auth_token(device_id: str, timestamp: str, nonce: str) -> str:
    """Device calls this to produce its auth token before sending a packet."""
    return generate_token(device_id, timestamp, nonce)


# ═══════════════════════════════════════════════════════════════════════════
#  Device Verification  (called on GATEWAY side)
# ═══════════════════════════════════════════════════════════════════════════

def verify_device(device_id: str, timestamp: str, nonce: str,
                  token: str, seen_nonces: set) -> tuple:
    """
    Full 5-step device authentication.

    Returns:
      (True,  "Authenticated",  "OK")
      (False, "reason string",  "ATTACK_TYPE")

    Attack types:
      UNREGISTERED  — not in registry
      BLOCKED       — auto-blocked after MAX_FAILURES failures
      SUSPENDED     — manually suspended
      REPLAYED      — expired timestamp or duplicate nonce
      FORGED_TOKEN  — valid device_id but wrong HMAC key
      INVALID_FORMAT — bad timestamp
    """
    # 1. Registry check — is this device known at all?
    device = get_device(device_id)
    if device is None:
        # Not in registry DB — but check DEVICE_KEYS as fallback
        if device_id not in DEVICE_KEYS:
            return False, f"Unregistered device: {device_id}", "UNREGISTERED"
        # In DEVICE_KEYS but not in registry DB (registry not initialized yet)
        # Fall through to HMAC check
        device = {"status": "ACTIVE", "failed_attempts": 0}

    # 2. Status check
    if device["status"] == "BLOCKED":
        return False, f"Device blocked after repeated auth failures: {device_id}", "BLOCKED"
    if device["status"] == "SUSPENDED":
        return False, f"Device suspended by operator: {device_id}", "SUSPENDED"

    # 3. Timestamp freshness
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

    # 5. HMAC token verify (constant-time comparison — prevents timing attacks)
    try:
        expected = generate_token(device_id, timestamp, nonce)
    except ValueError:
        _update_device(device_id, success=False)
        return False, f"No HMAC key provisioned for: {device_id}", "UNREGISTERED"

    if not hmac.compare_digest(expected, token):
        _update_device(device_id, success=False)
        return False, f"Invalid HMAC token — forged or cloned device: {device_id}", "FORGED_TOKEN"

    # All checks passed
    seen_nonces.add(nonce)
    _update_device(device_id, success=True)
    return True, "Authenticated", "OK"
