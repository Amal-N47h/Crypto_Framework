"""
gateway/crypto_engine.py  —  IoMT Gateway Crypto Engine
=========================================================
UPDATED DESIGN:
  - vitals_hash removed
  - hash_value removed — hash folded into ECDSA (not stored in packet)
  - hmac_token removed — session token lookup replaces per-packet HMAC
  - verify_packet() receives device_public_key loaded from DB per device

Verification order:
  1. Format check
  2. Nonce + timestamp replay check
  3. ECDSA verify — recompute internal hash of packet, verify signature
  4. Kyber decaps + AES decrypt
"""

import os, json, base64, hashlib, logging, time
from datetime import datetime, timezone

from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("verifier.log"), logging.StreamHandler()]
)
logger = logging.getLogger("IoMT")

MAX_AGE_SECONDS = 60
seen_nonces     = set()

# ── Gateway Kyber keypair — generated once at startup ─────────────────────────
_gw_kyber_public, _gw_kyber_secret = Kyber512.keygen()


def get_gateway_kyber_public() -> bytes:
    return _gw_kyber_public


# ── Kyber ──────────────────────────────────────────────────────────────────────

def kyber_decaps(ct: bytes) -> bytes:
    return Kyber512.decaps(_gw_kyber_secret, ct)


# ── ECDSA ─────────────────────────────────────────────────────────────────────

def generate_ecdsa_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def load_public_key_from_pem(pem_b64: str):
    """Load device public key stored in DB (base64 PEM)."""
    pem = base64.b64decode(pem_b64)
    return serialization.load_pem_public_key(pem)


def ecdsa_verify(data: bytes, sig_b64: str, pub) -> bool:
    try:
        pub.verify(base64.b64decode(sig_b64), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def aes_decrypt(enc: dict, key: bytes) -> bytes:
    dec = Cipher(
        algorithms.AES(key),
        modes.GCM(base64.b64decode(enc["iv"]), base64.b64decode(enc["tag"]))
    ).decryptor()
    return dec.update(base64.b64decode(enc["ciphertext"])) + dec.finalize()


# ── Verify packet ─────────────────────────────────────────────────────────────

def verify_packet(packet: dict, device_public_key=None) -> dict:
    """
    Verification order:
      1. Format check
      2. Nonce + timestamp replay check
      3. ECDSA verify — recompute internal SHA-256 of packet (excl. signature),
                        verify signature against it
      4. Kyber decaps + AES decrypt

    Session token lookup and device status check happen in app.py
    before calling here. device_public_key is loaded from DB and passed in.
    """
    t0      = time.perf_counter()
    metrics = {
        "hmac_ms":   0,
        "hash_ms":   0,
        "ecdsa_ms":  0,
        "kyber_ms":  0,
        "aes_ms":    0,
        "total_ms":  0,
        "latency_ms": 0,
        "attack_type": "",
        "encrypt_ms": packet.get("encrypt_ms", 0),
    }

    def done(status, reason, vitals=None):
        metrics["total_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        return {"status": status, "reason": reason,
                "vitals": vitals, "metrics": metrics}

    # ── Step 1 — Format check ────────────────────────────────────────────────
    required = ["session_token", "device_id", "timestamp", "nonce",
                "signature", "kyber_ct", "encrypted_data"]
    for f in required:
        if f not in packet:
            return done("INVALID_FORMAT", f"Missing field: {f}")

    device_id = packet["device_id"]

    # Latency measurement
    try:
        pkt_time = datetime.fromisoformat(packet["timestamp"].replace("Z", "+00:00"))
        metrics["latency_ms"] = round(
            abs((datetime.now(timezone.utc) - pkt_time).total_seconds() * 1000), 2)
    except Exception:
        pass

    # ── Step 2 — Nonce + timestamp replay check ──────────────────────────────
    t = time.perf_counter()
    try:
        pkt_time = datetime.fromisoformat(packet["timestamp"].replace("Z", "+00:00"))
        age = abs((datetime.now(timezone.utc) - pkt_time).total_seconds())
        if age > MAX_AGE_SECONDS:
            metrics["hmac_ms"]     = round((time.perf_counter() - t) * 1000, 3)
            metrics["attack_type"] = "REPLAYED"
            logger.warning(f"REPLAYED [EXPIRED] {device_id} — {age:.0f}s old")
            return done("REPLAYED", f"Expired timestamp ({age:.0f}s old)")
    except Exception:
        return done("INVALID_FORMAT", "Invalid timestamp format")

    if packet["nonce"] in seen_nonces:
        metrics["hmac_ms"]     = round((time.perf_counter() - t) * 1000, 3)
        metrics["attack_type"] = "REPLAYED"
        logger.warning(f"REPLAYED [NONCE] {device_id}")
        return done("REPLAYED", "Duplicate nonce — replay attack")

    metrics["hmac_ms"] = round((time.perf_counter() - t) * 1000, 3)

    # ── Step 3 — ECDSA verify ────────────────────────────────────────────────
    # Recompute the same internal hash the device computed:
    #   SHA-256 of packet excluding the signature field
    # This catches any field tampering (patient_id, kyber_ct, encrypted_data, etc.)
    if device_public_key:
        t = time.perf_counter()

        packet_copy   = {k: v for k, v in packet.items()
                         if k not in ("signature", "encrypt_ms")}
        internal_hash = hashlib.sha256(
            json.dumps(packet_copy, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        sig_ok = ecdsa_verify(
            internal_hash.encode(),
            packet["signature"],
            device_public_key         # ← correct variable name
        )
        metrics["ecdsa_ms"] = round((time.perf_counter() - t) * 1000, 3)

        if not sig_ok:
            metrics["attack_type"] = "TAMPERED"
            logger.error(f"TAMPERED [ECDSA] {device_id}")
            return done("TAMPERED", "Invalid ECDSA signature — packet tampered or forged")

    # ── Step 4 — Kyber decaps ────────────────────────────────────────────────
    try:
        t  = time.perf_counter()
        ss = kyber_decaps(base64.b64decode(packet["kyber_ct"]))
        metrics["kyber_ms"] = round((time.perf_counter() - t) * 1000, 3)
    except Exception as e:
        return done("DECRYPTION_ERROR", f"Kyber decaps failed: {e}")

    # ── Step 5 — AES-256-GCM decrypt ────────────────────────────────────────
    try:
        t           = time.perf_counter()
        enc         = json.loads(base64.b64decode(packet["encrypted_data"]).decode())
        vitals_json = aes_decrypt(enc, ss)
        vitals      = json.loads(vitals_json.decode())
        metrics["aes_ms"] = round((time.perf_counter() - t) * 1000, 3)
    except Exception as e:
        return done("DECRYPTION_ERROR", f"AES decrypt failed: {e}")

    seen_nonces.add(packet["nonce"])
    result = done("VALID", "All checks passed", vitals)
    logger.info(f"VALID {device_id} nonce={packet['nonce']} "
                f"ecdsa={metrics['ecdsa_ms']}ms kyber={metrics['kyber_ms']}ms "
                f"aes={metrics['aes_ms']}ms total={metrics['total_ms']}ms")
    return result