import os
import json
import hmac
import hashlib
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta

# ── Config ─────────────────────────────────────────────────────────────────────
ALLOWED_DRIFT    = 60    # seconds — max age of a packet
MAX_FAILURES     = 5     # auto-block after this many consecutive failures
SESSION_TTL_MINS = 30    # session token valid for 30 minutes
REGISTRY_DB      = "database.db"
PACKET_FILE      = "packet.json"
RESPONSE_FILE    = "response.json"

# ── Pre-shared HMAC keys (must match client.py) ────────────────────────────────
DEVICE_KEYS = {
    "IOMT-DEV-00423": "a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605a3f8c21d9e4b7605",
    "IOMT-DEV-00999": "b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502b7e2d94c1f3a8502",
    "IOMT-DEV-001":   "c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601c9f1e83d2b4a7601",
    "IOMT-DEV-002":   "d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502d2a4b73c1e9f8502",
}

# ── Pre-provisioned public keys (stored at registration time, NOT during auth) ─
# Replace these placeholder PEM strings with real device public keys.
DEVICE_PUBLIC_KEYS = {
    "IOMT-DEV-00423": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDEV00423PLACEHOLDER==\n-----END PUBLIC KEY-----",
    "IOMT-DEV-00999": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDEV00999PLACEHOLDER==\n-----END PUBLIC KEY-----",
    "IOMT-DEV-001":   "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDEV001XXXXPLACEHOLDER==\n-----END PUBLIC KEY-----",
    "IOMT-DEV-002":   "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDEV002XXXXPLACEHOLDER==\n-----END PUBLIC KEY-----",
}


# ==============================
# DEVICE REGISTRY  (SQLite)
# ==============================
def init_registry():
    """Create registry DB and seed all known devices. Called once at startup."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()

    # devices — includes public_key column pre-provisioned at registration
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id       TEXT PRIMARY KEY,
            status          TEXT DEFAULT 'ACTIVE',
            failed_attempts INTEGER DEFAULT 0,
            last_seen       TEXT,
            registered_at   TEXT,
            public_key      TEXT
        )
    """)

    # session_tokens — one active token per device, replaced on each full auth
    c.execute("""
        CREATE TABLE IF NOT EXISTS session_tokens (
            device_id   TEXT PRIMARY KEY,
            token       TEXT NOT NULL,
            issued_at   TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # nonce replay table
    c.execute("""
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce TEXT PRIMARY KEY
        )
    """)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for did in DEVICE_KEYS:
        pubkey = DEVICE_PUBLIC_KEYS.get(did)
        c.execute("""
            INSERT OR IGNORE INTO devices (device_id, status, registered_at, public_key)
            VALUES (?, 'ACTIVE', ?, ?)
        """, (did, now, pubkey))

    conn.commit()
    conn.close()


# ── Nonce helpers ──────────────────────────────────────────────────────────────
def _nonce_seen(nonce: str) -> bool:
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


# ── Device helpers ─────────────────────────────────────────────────────────────
def get_device(device_id: str):
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def _update_device(device_id: str, success: bool):
    """Update failed attempts counter; auto-block at MAX_FAILURES."""
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


# ── Session token helpers ──────────────────────────────────────────────────────
def _create_session_token(device_id: str) -> dict:
    """
    Generate a 256-bit cryptographically secure session token, persist it
    in the DB (upsert — one active token per device), and return the token
    info dict so the gateway can forward it to the device.
    """
    token      = secrets.token_hex(32)
    now        = datetime.now(timezone.utc)
    issued_at  = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_at = (now + timedelta(minutes=SESSION_TTL_MINS)).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("""
        INSERT INTO session_tokens (device_id, token, issued_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(device_id) DO UPDATE SET
            token      = excluded.token,
            issued_at  = excluded.issued_at,
            expires_at = excluded.expires_at
    """, (device_id, token, issued_at, expires_at))
    conn.commit()
    conn.close()

    return {"session_token": token, "expires_at": expires_at}


def _validate_session_token(device_id: str, session_token: str):
    """
    Validate the session token the device attached to its packet.
    Returns None on success, or an error string on failure.
    """
    conn = sqlite3.connect(REGISTRY_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT token, expires_at FROM session_tokens WHERE device_id = ?", (device_id,))
    row = c.fetchone()
    conn.close()

    if row is None:
        return "No active session — please re-authenticate"

    # Constant-time compare to prevent timing attacks
    if not hmac.compare_digest(row["token"], session_token):
        return "Session token invalid"

    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        return f"Session token expired at {row['expires_at']} — please re-authenticate"

    return None  # success


def _revoke_session_token(device_id: str):
    """Remove a device's active session (e.g. after it gets blocked)."""
    conn = sqlite3.connect(REGISTRY_DB)
    c = conn.cursor()
    c.execute("DELETE FROM session_tokens WHERE device_id = ?", (device_id,))
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
# SESSION-BASED FAST PATH
# ==============================
def handle_session_packet(packet: dict) -> dict:
    """
    Fast path for subsequent packets: device sends its session_token instead
    of full HMAC credentials. Only registry + token validation is performed.
    """
    device_id     = packet.get("device_id")
    session_token = packet.get("session_token")

    if not device_id or not session_token:
        return {"status": "error", "message": "Missing device_id or session_token"}

    device = get_device(device_id)
    if device is None:
        return {"status": "error", "message": "Unregistered device"}
    if device["status"] == "BLOCKED":
        _revoke_session_token(device_id)
        return {"status": "error", "message": "Device blocked"}
    if device["status"] == "SUSPENDED":
        return {"status": "error", "message": "Device suspended by operator"}

    err = _validate_session_token(device_id, session_token)
    if err:
        return {"status": "error", "message": err}

    _update_device(device_id, success=True)
    return {"status": "ok", "message": "Session valid — packet accepted"}


# ==============================
# FULL AUTHENTICATION FUNCTION
# ==============================
def authenticate_device(packet: dict) -> dict:
    """
    Full HMAC authentication (first contact or after session expiry).
    On success, issues and returns a session token for the device to reuse.
    """
    device_id = packet["device_id"]
    timestamp = packet["timestamp"]
    nonce     = packet["nonce"]
    token     = packet["token"]

    # Step 1 — Registry check
    device = get_device(device_id)
    if device is None:
        return {"status": "error", "message": "Authentication Failed: Unregistered device"}

    # Step 2 — Status check
    if device["status"] == "BLOCKED":
        return {"status": "error",
                "message": f"Authentication Failed: Device blocked after {MAX_FAILURES} failed attempts"}
    if device["status"] == "SUSPENDED":
        return {"status": "error", "message": "Authentication Failed: Device suspended by operator"}

    # Step 3 — Timestamp check
    try:
        pkt_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = abs((datetime.now(timezone.utc) - pkt_time).total_seconds())
        if age > ALLOWED_DRIFT:
            return {"status": "error",
                    "message": f"Authentication Failed: Expired timestamp ({age:.0f}s old)"}
    except Exception:
        return {"status": "error", "message": "Authentication Failed: Invalid timestamp format"}

    # Step 4 — Replay check
    if _nonce_seen(nonce):
        return {"status": "error", "message": "Authentication Failed: Replay detected (duplicate nonce)"}

    # Step 5 — HMAC verification (constant-time compare)
    try:
        expected = _generate_token(device_id, timestamp, nonce)
    except (KeyError, ValueError):
        _update_device(device_id, success=False)
        return {"status": "error", "message": "Authentication Failed: No HMAC key for this device"}

    if not hmac.compare_digest(expected, token):
        _update_device(device_id, success=False)
        return {"status": "error",
                "message": "Authentication Failed: Invalid token (forged or cloned device)"}

    # All checks passed
    _save_nonce(nonce)
    _update_device(device_id, success=True)
    session_info = _create_session_token(device_id)   # ← issue session token

    return {
        "status":        "ok",
        "message":       "Authentication Successful",
        "session_token": session_info["session_token"],
        "expires_at":    session_info["expires_at"],
    }


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    init_registry()

    with open(PACKET_FILE, "r") as f:
        packet = json.load(f)

    # Route: session fast-path vs full HMAC auth
    if "session_token" in packet:
        print(f"Server  : Session packet received")
        print(f"          device_id     : {packet['device_id']}")
        print(f"          session_token : {packet['session_token'][:16]}...")
        print()
        result = handle_session_packet(packet)
    else:
        print(f"Server  : Auth packet received")
        print(f"          device_id : {packet['device_id']}")
        print(f"          timestamp : {packet['timestamp']}")
        print(f"          nonce     : {packet['nonce'][:16]}...")
        print(f"          token     : {packet['token'][:16]}...")
        print()
        result = authenticate_device(packet)

    print(f"Result  : {result['message']}")
    if result["status"] == "ok" and "session_token" in result:
        print(f"          session_token : {result['session_token'][:16]}...")
        print(f"          expires_at    : {result['expires_at']}")

    with open(RESPONSE_FILE, "w") as f:
        json.dump(result, f, indent=4)
    print(f"\n          → response written to {RESPONSE_FILE}")
