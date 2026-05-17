"""
attack_simulator.py  —  Updated for new packet design
======================================================
Run from the gateway/ folder:  python attack_simulator.py

Changes:
  - hash_value removed from packet (folded into ECDSA internally)
  - vitals_hash removed
  - hmac_token removed from packet (HMAC only at /auth)
  - session_token used instead
  - ECDSA signs SHA-256(packet) internally — no hash field in packet
  - crypto_engine_device_sim removed — uses crypto_engine_device directly

Simulates all attack types:

REPLAY ATTACKS:
  R1. Nonce replay       — exact same packet resent
  R2. Expired timestamp  — old packet replayed

TAMPERING ATTACKS:
  T1. Encrypted data flip  — ciphertext bytes flipped → ECDSA fails
  T2. Signature corruption — signature field corrupted
  T3. Patient ID swap      — patient_id changed → ECDSA fails
  T4. kyber_ct swap        — kyber_ct replaced → ECDSA fails

SESSION ATTACKS:
  S1. Invalid session token  — random/unknown token
  S2. Expired session        — manually expired in DB
  S3. Suspended device       — device suspended mid-session

UNAUTHORIZED DEVICE ATTACKS:
  U1. Unregistered device    — device_id never provisioned
  U2. Brute-force auth       — 5 HMAC failures → auto-blocked
  U3. Spoofed IOMT prefix    — IOMT-FAKE-xxx not in registry
"""

import sys, json, base64, uuid, hashlib, secrets as sec, hmac as _hmac, hashlib as _hs
sys.path.insert(0, ".")

from auth import (init_registry, get_all_devices, set_device_status,
                  DEVICE_KEYS, generate_token, verify_device)
from crypto_engine import (verify_packet, generate_ecdsa_keypair,
                            seen_nonces, get_gateway_kyber_public,
                            load_public_key_from_pem)
from crypto_engine_device import build_packet, set_gateway_kyber_public
from database import (init_db, save_packet, save_alert, get_stats,
                      save_session, get_session)
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

init_db()
init_registry()

# ── Simulator keypair ──────────────────────────────────────────────────────────
dev_priv, dev_pub = generate_ecdsa_keypair()
_pub_pem_b64 = base64.b64encode(
    dev_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
).decode()

set_gateway_kyber_public(get_gateway_kyber_public())

# ── Session setup ──────────────────────────────────────────────────────────────
VITALS         = {"heart_rate": 82, "spo2": 97,
                  "temperature": 36.7, "blood_pressure": "120/80"}
DID            = "IOMT-DEV-00423"
PID            = "PAT-9981"
now            = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
sid            = lambda: str(uuid.uuid4())[:8]

SESSION_SECRET = b"simulator-secret"
SESSION_EXPIRY = (datetime.now(timezone.utc) + timedelta(hours=24)
                  ).strftime("%Y-%m-%dT%H:%M:%SZ")
VALID_TOKEN    = _hmac.new(
    SESSION_SECRET, f"{DID}{SESSION_EXPIRY}".encode(), _hs.sha256
).hexdigest()

save_session(VALID_TOKEN, DID, _pub_pem_b64, SESSION_EXPIRY)

# ── Helper: re-sign after mutating packet fields ───────────────────────────────
def resign(pkt, priv):
    """Recompute internal hash and re-sign after mutating packet fields."""
    copy = {k: v for k, v in pkt.items() if k != "signature"}
    internal = hashlib.sha256(
        json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    pkt["signature"] = base64.b64encode(
        priv.sign(internal.encode(), ec.ECDSA(hashes.SHA256()))
    ).decode()
    return pkt

# ── Helpers ────────────────────────────────────────────────────────────────────
def div(title):
    print(f"\n{'═'*60}\n  {title}\n{'═'*60}")

def run(label, pkt, expected):
    session = get_session(pkt.get("session_token", ""))
    if session:
        try:
            pub = load_public_key_from_pem(session["ecdsa_public_key"])
        except Exception:
            pub = dev_pub
    else:
        pub = None

    r    = verify_packet(pkt, device_public_key=pub)
    ok   = "✓" if r["status"] == expected else "✗ UNEXPECTED"
    icon = "✅" if r["status"] == "VALID" else "🚨"
    print(f"  {icon} {label:<44} → {r['status']} {ok}")
    print(f"     reason: {r['reason']}")
    save_packet(sid(), pkt, r["status"], r["reason"], r["vitals"], r.get("metrics", {}))
    if r["status"] != "VALID":
        save_alert(sid(), pkt.get("device_id", "?"), r["status"],
                   r["reason"], now(), r.get("metrics", {}).get("attack_type", ""))
    return r


# ═══════════════════════════════════════════════════════════════════════════
#  BASELINE
# ═══════════════════════════════════════════════════════════════════════════
div("BASELINE — Valid packet")
base = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
run("valid packet", base, "VALID")


# ═══════════════════════════════════════════════════════════════════════════
#  REPLAY ATTACKS
# ═══════════════════════════════════════════════════════════════════════════
div("REPLAY ATTACK 1 — Nonce replay (same packet resent)")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
verify_packet(p, device_public_key=dev_pub)   # first send — nonce consumed
run("replay same packet", p, "REPLAYED")

div("REPLAY ATTACK 2 — Expired timestamp")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
p["timestamp"] = "2020-01-01T00:00:00Z"
resign(p, dev_priv)                           # re-sign with mutated timestamp
run("expired timestamp", p, "REPLAYED")


# ═══════════════════════════════════════════════════════════════════════════
#  TAMPERING ATTACKS
# ═══════════════════════════════════════════════════════════════════════════
div("TAMPER ATTACK 1 — Encrypted data byte flip")
p   = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
raw = base64.b64decode(p["encrypted_data"])
p["encrypted_data"] = base64.b64encode(
    bytes([raw[0] ^ 0xFF]) + raw[1:]
).decode()
# signature now invalid — ECDSA catches the field change
run("encrypted_data bytes flipped", p, "TAMPERED")

div("TAMPER ATTACK 2 — Signature field corruption")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
p["signature"] = "aa" * 64
run("signature corrupted (ECDSA fails)", p, "TAMPERED")

div("TAMPER ATTACK 3 — Patient ID swap")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
p["patient_id"] = "PAT-EVIL-0000"
# signature now invalid — patient_id is in the signed hash
run("patient_id swapped", p, "TAMPERED")

div("TAMPER ATTACK 4 — kyber_ct swap")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
_, fake_ct = __import__("kyber_py.kyber", fromlist=["Kyber512"]).Kyber512.encaps(
    get_gateway_kyber_public()
)
p["kyber_ct"] = base64.b64encode(fake_ct).decode()
# signature now invalid — kyber_ct is in the signed hash
run("kyber_ct swapped", p, "TAMPERED")


# ═══════════════════════════════════════════════════════════════════════════
#  SESSION ATTACKS
# ═══════════════════════════════════════════════════════════════════════════
div("SESSION ATTACK 1 — Invalid session token")
p = build_packet(DID, PID, VITALS, dev_priv, VALID_TOKEN)
p["session_token"] = "deadbeef" * 8    # unknown token — session lookup fails
resign(p, dev_priv)                    # re-sign so ECDSA doesn't fail first
run("random session token", p, "INVALID_DEVICE")

div("SESSION ATTACK 2 — Expired session")
expired_token = _hmac.new(
    SESSION_SECRET, f"{DID}2020-01-01T00:00:00Z".encode(), _hs.sha256
).hexdigest()
save_session(expired_token, DID, _pub_pem_b64, "2020-01-01T00:00:00Z")
p = build_packet(DID, PID, VITALS, dev_priv, expired_token)
run("expired session token", p, "INVALID_DEVICE")

div("SESSION ATTACK 3 — Suspended device mid-session")
set_device_status("IOMT-DEV-00999", "SUSPENDED", "Reported lost/stolen")
sus_token = _hmac.new(
    SESSION_SECRET, f"IOMT-DEV-00999{SESSION_EXPIRY}".encode(), _hs.sha256
).hexdigest()
save_session(sus_token, "IOMT-DEV-00999", _pub_pem_b64, SESSION_EXPIRY)
p = build_packet("IOMT-DEV-00999", PID, VITALS, dev_priv, sus_token)
run("suspended device mid-session", p, "INVALID_DEVICE")
set_device_status("IOMT-DEV-00999", "ACTIVE", "Restored after test")


# ═══════════════════════════════════════════════════════════════════════════
#  UNAUTHORIZED DEVICE ATTACKS (one-time auth stage)
# ═══════════════════════════════════════════════════════════════════════════
div("UNAUTHORIZED 1 — Unregistered device tries to auth")
auth_nonces = set()
ts    = now()
nonce = sec.token_hex(8)
DEVICE_KEYS["FAKE-999"] = sec.token_hex(32)
tok   = generate_token("FAKE-999", ts, nonce)
del DEVICE_KEYS["FAKE-999"]
ok, reason, atype = verify_device("FAKE-999", ts, nonce, tok, auth_nonces)
print(f"  🚨 unregistered device auth attempt    → {atype} {'✓' if not ok else '✗'}")
print(f"     reason: {reason}")

div("UNAUTHORIZED 2 — Brute-force auth → auto-block")
set_device_status("IOMT-DEV-001", "ACTIVE", "")
print("  Sending 7 auth attempts with wrong HMAC (blocks at attempt 5):\n")
bf_nonces = set()
for i in range(7):
    ts    = now()
    nonce = sec.token_hex(8)
    wrong = "ee" * 32
    ok, reason, atype = verify_device("IOMT-DEV-001", ts, nonce, wrong, bf_nonces)
    icon = "🔐" if "blocked" in reason.lower() else "✗"
    print(f"  Attempt {i+1:2d}: {icon} {atype} — {reason[:55]}")

div("UNAUTHORIZED 3 — Spoofed IOMT prefix")
ts    = now()
nonce = sec.token_hex(8)
DEVICE_KEYS["IOMT-FAKE-99999"] = sec.token_hex(32)
tok = generate_token("IOMT-FAKE-99999", ts, nonce)
del DEVICE_KEYS["IOMT-FAKE-99999"]
ok, reason, atype = verify_device("IOMT-FAKE-99999", ts, nonce, tok, set())
print(f"  🚨 IOMT prefix but not registered      → {atype} {'✓' if not ok else '✗'}")
print(f"     reason: {reason}")


# ═══════════════════════════════════════════════════════════════════════════
#  DEVICE REGISTRY STATUS
# ═══════════════════════════════════════════════════════════════════════════
div("DEVICE REGISTRY STATUS")
print(f"\n  {'DEVICE':<22} {'STATUS':<12} {'FAILURES':<10} NOTES")
print(f"  {'─'*65}")
for d in get_all_devices():
    icon = {"ACTIVE": "🟢", "SUSPENDED": "🟡", "BLOCKED": "🔴"}.get(d["status"], "⚪")
    print(f"  {d['device_id']:<22} {icon} {d['status']:<10} {d['failed_attempts']:<10} {d['notes'] or ''}")


# ═══════════════════════════════════════════════════════════════════════════
#  FINAL STATS
# ═══════════════════════════════════════════════════════════════════════════
s = get_stats()
div("FINAL STATS")
print(f"""
  Total packets : {s['total']}
  Accepted      : {s['valid']}
  Rejected      : {s['invalid']}
  Alerts        : {s['alerts']}

  ┌──────────────────────────────────────────┬──────────────────────────┐
  │ Attack                                   │ Detected by              │
  ├──────────────────────────────────────────┼──────────────────────────┤
  │ R1. Nonce replay                         │ nonce in seen_nonces     │
  │ R2. Expired timestamp                    │ timestamp > 60s          │
  │ T1. Encrypted data flip                  │ ECDSA verify fails       │
  │ T2. Signature corruption                 │ ECDSA verify fails       │
  │ T3. Patient ID swap                      │ ECDSA verify fails       │
  │ T4. kyber_ct swap                        │ ECDSA verify fails       │
  │ S1. Invalid session token                │ session DB lookup        │
  │ S2. Expired session                      │ session expiry check     │
  │ S3. Suspended device mid-session         │ registry status check    │
  │ U1. Unregistered device auth attempt     │ registry lookup          │
  │ U2. Brute-force auth → auto-block        │ failure counter          │
  │ U3. Spoofed IOMT prefix                  │ registry lookup          │
  └──────────────────────────────────────────┴──────────────────────────┘
""")