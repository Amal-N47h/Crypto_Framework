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

DEVICE_ID     = "IOMT-DEV-001"
PACKET_FILE   = "packet.json"
RESPONSE_FILE = "response.json"
SESSION_FILE  = "session.json"   # persists the active session token on disk


# ==============================
# SESSION TOKEN PERSISTENCE
# ==============================
def _load_session() -> dict | None:
    """Load saved session token from disk. Returns None if not found or expired."""
    if not os.path.exists(SESSION_FILE):
        return None
    try:
        with open(SESSION_FILE, "r") as f:
            sess = json.load(f)
        expires_at = datetime.fromisoformat(sess["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) >= expires_at:
            print(f"Client  : Cached session token has expired — will re-authenticate")
            os.remove(SESSION_FILE)
            return None
        return sess
    except Exception:
        return None


def save_session(response: dict):
    """Persist the session token returned by the gateway after a successful auth."""
    if response.get("status") == "ok" and "session_token" in response:
        sess = {
            "device_id":    DEVICE_ID,
            "session_token": response["session_token"],
            "expires_at":   response["expires_at"],
        }
        with open(SESSION_FILE, "w") as f:
            json.dump(sess, f, indent=4)
        print(f"Client  : Session token saved to {SESSION_FILE}")


# ==============================
# HMAC TOKEN GENERATION
# ==============================
def make_auth_token(device_id: str, timestamp: str, nonce: str) -> str:
    secret  = bytes.fromhex(DEVICE_KEYS[device_id])
    message = f"{device_id}{timestamp}{nonce}".encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


# ==============================
# BUILD AUTH PACKET  (full HMAC)
# ==============================
def create_auth_packet(mode="normal") -> dict:
    """Build a full HMAC authentication packet (first contact or re-auth)."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce     = os.urandom(16).hex()
    device_id = DEVICE_ID

    if mode == "expired":
        timestamp = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    elif mode == "replay":
        nonce = "aabbccdd11223344aabbccdd11223344"

    elif mode == "forged":
        return {
            "device_id": device_id,
            "timestamp": timestamp,
            "nonce":     nonce,
            "token":     os.urandom(32).hex(),
        }

    elif mode == "unregistered":
        return {
            "device_id": "IOMT-DEV-FAKE",
            "timestamp": timestamp,
            "nonce":     nonce,
            "token":     "deadbeef" * 8,
        }

    token = make_auth_token(device_id, timestamp, nonce)
    return {
        "device_id": device_id,
        "timestamp": timestamp,
        "nonce":     nonce,
        "token":     token,
    }


# ==============================
# BUILD SESSION PACKET  (fast path)
# ==============================
def create_session_packet(session: dict) -> dict:
    """
    Build a lightweight data packet that uses the session token instead of
    full HMAC credentials.  The gateway validates the token and skips re-auth.
    """
    return {
        "device_id":    DEVICE_ID,
        "session_token": session["session_token"],
        # Any real payload fields (sensor readings, etc.) go here:
        # "temperature": 36.7,
        # "heart_rate":  72,
    }


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "auto"

    # ── "auto" mode: use session token if available, else do full auth ─────────
    if mode == "auto":
        session = _load_session()
        if session:
            print(f"Client  : Active session found — using session token  [fast path]")
            packet = create_session_packet(session)
            packet_type = "session"
        else:
            print(f"Client  : No active session — performing full HMAC authentication")
            packet = create_auth_packet("normal")
            packet_type = "auth"

    # ── Explicit modes (for testing) ───────────────────────────────────────────
    elif mode == "session":
        session = _load_session()
        if session is None:
            print("Client  : No valid session found. Run without args (or 'normal') first.")
            sys.exit(1)
        packet = create_session_packet(session)
        packet_type = "session"

    else:
        # normal / expired / replay / forged / unregistered
        packet = create_auth_packet(mode)
        packet_type = "auth"

    # ── Write packet and print summary ─────────────────────────────────────────
    with open(PACKET_FILE, "w") as f:
        json.dump(packet, f, indent=4)

    print(f"Client  : Packet created  [mode = {mode} | type = {packet_type}]")
    print(f"          device_id : {packet['device_id']}")
    if packet_type == "session":
        print(f"          session_token : {packet['session_token'][:16]}...")
    else:
        print(f"          timestamp : {packet['timestamp']}")
        print(f"          nonce     : {packet['nonce'][:16]}...")
        print(f"          token     : {packet['token'][:16]}...")
    print(f"          → written to {PACKET_FILE}")

    # ── Read gateway response (if it exists from a previous server run) ────────
    if os.path.exists(RESPONSE_FILE):
        with open(RESPONSE_FILE, "r") as f:
            response = json.load(f)
        save_session(response)   # persist session token if auth just succeeded
