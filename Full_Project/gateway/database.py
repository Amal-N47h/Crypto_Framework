"""
database.py  —  SQLite + ChaCha20-Poly1305 encryption at rest
=============================================================
UPDATED: Added sessions table for session-based authentication.

Sensitive fields encrypted before writing to disk:
  - patient_id       (PII)
  - decrypted_vitals (plaintext health data)
"""

import os, json, base64, sqlite3
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

DB_PATH = "iomt_web.db"
_KEY_FILE = "db_master.key"

# DB master key — load from env, or from key file, or generate once and save
def _load_or_create_db_key() -> bytes:
    env_key = os.environ.get("IOMT_DB_KEY")
    if env_key:
        return bytes.fromhex(env_key)
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(_KEY_FILE, "wb") as f:
        f.write(key)
    return key

_DB_KEY = _load_or_create_db_key()

# ── ChaCha20-Poly1305 helpers ──────────────────────────────────────────────────

def _encrypt(plaintext: str) -> str:
    chacha = ChaCha20Poly1305(_DB_KEY)
    nonce  = os.urandom(12)
    ct     = chacha.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def _decrypt(blob: str) -> str:
    chacha = ChaCha20Poly1305(_DB_KEY)
    raw    = base64.b64decode(blob)
    return chacha.decrypt(raw[:12], raw[12:], None).decode()

# ── Schema ─────────────────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # ── Schema migration: drop packets table if it has stale columns ──────────
    # Old schema had hash_value TEXT which was removed; the INSERT column list no
    # longer includes it, causing a "20 values for 19 columns" crash on every packet.
    c.execute("PRAGMA table_info(packets)")
    existing_cols = {row[1] for row in c.fetchall()}
    stale_cols = {"hash_value", "hmac_token", "vitals_hash"}
    if existing_cols and (existing_cols & stale_cols):
        print("[DB] Migrating packets table — dropping stale columns from old schema")
        c.execute("DROP TABLE packets")
        conn.commit()

    # Packets table
    c.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id        TEXT,
            device_id        TEXT,
            patient_id       TEXT,
            timestamp        TEXT,
            nonce            TEXT,
            encrypted_data   TEXT,
            signature        TEXT,
            status           TEXT,
            reason           TEXT,
            attack_type      TEXT,
            decrypted_vitals TEXT,
            hmac_ms          REAL,
            hash_ms          REAL,
            ecdsa_ms         REAL,
            kyber_ms         REAL,
            aes_ms           REAL,
            encrypt_ms       REAL,
            total_ms         REAL,
            latency_ms       REAL
        )
    """)

    # Alerts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            packet_id   TEXT,
            device_id   TEXT,
            alert_type  TEXT,
            attack_type TEXT,
            reason      TEXT,
            timestamp   TEXT
        )
    """)

    # Sessions table — NEW for session-based auth
    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_token    TEXT PRIMARY KEY,
            device_id        TEXT,
            ecdsa_public_key TEXT,
            expiry           TEXT,
            created_at       TEXT
        )
    """)

    conn.commit()
    conn.close()

# ── Session management ─────────────────────────────────────────────────────────

def save_session(session_token: str, device_id: str,
                 ecdsa_public_key: str, expiry: str):
    """Store a new session after successful one-time auth."""
    conn = sqlite3.connect(DB_PATH)
    now  = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("""
        INSERT OR REPLACE INTO sessions
          (session_token, device_id, ecdsa_public_key, expiry, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (session_token, device_id, ecdsa_public_key, expiry, now))
    conn.commit()
    conn.close()

def get_session(session_token: str) -> dict | None:
    """Return session record or None if not found."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_token = ?", (session_token,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_session(session_token: str):
    """Revoke a session."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
    conn.commit()
    conn.close()

def get_all_sessions() -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT session_token, device_id, expiry, created_at FROM sessions ORDER BY created_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

# ── Packet storage ─────────────────────────────────────────────────────────────

def save_packet(packet_id, packet, status, reason, vitals, metrics):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO packets
          (packet_id, device_id, patient_id, timestamp, nonce,
           encrypted_data, signature,
           status, reason, attack_type, decrypted_vitals,
           hmac_ms, hash_ms, ecdsa_ms, kyber_ms, aes_ms,
           encrypt_ms, total_ms, latency_ms)
        VALUES (?,?,?,?,?, ?,?,?, ?,?,?,?, ?,?,?,?,?,?,?)
    """, (
        packet_id,
        packet.get("device_id"),
        _encrypt(packet.get("patient_id", "")),
        packet.get("timestamp"),
        packet.get("nonce"),
        packet.get("encrypted_data"),
        packet.get("signature"),
        status, reason,
        metrics.get("attack_type", ""),
        _encrypt(json.dumps(vitals)) if vitals else None,
        metrics.get("hmac_ms"),  metrics.get("hash_ms"),
        metrics.get("ecdsa_ms"), metrics.get("kyber_ms"),
        metrics.get("aes_ms"),   metrics.get("encrypt_ms"),
        metrics.get("total_ms"), metrics.get("latency_ms"),
    ))
    conn.commit()
    conn.close()

def save_alert(packet_id, device_id, alert_type, reason, timestamp, attack_type=""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO alerts
          (packet_id, device_id, alert_type, attack_type, reason, timestamp)
        VALUES (?,?,?,?,?,?)
    """, (packet_id, device_id, alert_type, attack_type, reason, timestamp))
    conn.commit()
    conn.close()

# ── Read helpers ───────────────────────────────────────────────────────────────

def get_all_packets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["patient_id"]       = _decrypt(d["patient_id"]) if d["patient_id"] else ""
            d["decrypted_vitals"] = _decrypt(d["decrypted_vitals"]) if d["decrypted_vitals"] else ""
        except Exception:
            pass
        result.append(d)
    return result

def get_all_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    total   = c.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
    valid   = c.execute("SELECT COUNT(*) FROM packets WHERE status='VALID'").fetchone()[0]
    alerts  = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    return {"total": total, "valid": valid, "alerts": alerts,
            "invalid": total - valid}

def get_metrics():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM packets");                       total       = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM packets WHERE status='VALID'");  valid       = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM alerts");                        alert_count = c.fetchone()[0]
    invalid        = total - valid
    detection_rate = round((alert_count / invalid * 100) if invalid > 0 else 100.0, 1)

    timings = {}
    for f in ["hmac_ms", "hash_ms", "ecdsa_ms", "kyber_ms",
              "aes_ms", "encrypt_ms", "total_ms", "latency_ms"]:
        c.execute(f"SELECT AVG({f}), MIN({f}), MAX({f}) FROM packets WHERE {f}>0")
        row = c.fetchone()
        timings[f] = {
            "avg": round(row[0] or 0, 3),
            "min": round(row[1] or 0, 3),
            "max": round(row[2] or 0, 3),
        }

    c.execute("""SELECT timestamp, total_ms, encrypt_ms, latency_ms, kyber_ms, aes_ms
                 FROM packets WHERE status='VALID' ORDER BY id DESC LIMIT 30""")
    history = [
        {"timestamp": r[0], "total_ms": r[1], "encrypt_ms": r[2],
         "latency_ms": r[3], "kyber_ms": r[4], "aes_ms": r[5]}
        for r in reversed(c.fetchall())
    ]
    conn.close()

    return {
        "total":          total,
        "valid":          valid,
        "invalid":        invalid,
        "alerts":         alert_count,
        "detection_rate": detection_rate,
        "timings":        timings,
        "history":        history,
    }

def clear_all():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM packets")
    conn.execute("DELETE FROM alerts")
    conn.execute("DELETE FROM sessions")
    conn.commit()
    conn.close()