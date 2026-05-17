"""
crypto_engine_device.py  —  Device-side crypto (PC 1)
======================================================
UPDATED DESIGN:
  - Device generates its own ECDSA keypair (private key never leaves device)
  - Kyber public key received from gateway via POST /auth (authenticated channel)
  - vitals_hash removed — ECDSA signs internal hash of final packet
  - hash_value removed — hash folded into ECDSA operation, not stored in packet
  - No hmac_token per packet — session token used instead

Packet build order:
  1. Kyber encaps + AES encrypt vitals
  2. Assemble final packet (encrypted_data, no plaintext vitals)
  3. Compute SHA-256 of final packet internally
  4. ECDSA sign the hash
  5. Attach signature
  6. Send
"""

import os, json, base64, hashlib, secrets, logging, time
from datetime import datetime, timezone

from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("IoMT-Device")

seen_nonces      = set()
_gw_kyber_public = None


def set_gateway_kyber_public(pub: bytes):
    global _gw_kyber_public
    _gw_kyber_public = pub


# ── ECDSA keypair — generated locally, private key never leaves device ─────────

def generate_ecdsa_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def get_ecdsa_public_key_pem(pub) -> str:
    """Export public key as base64 PEM to send to gateway during auth."""
    pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(pem).decode()


# ── Kyber ──────────────────────────────────────────────────────────────────────

def kyber_encaps():
    if _gw_kyber_public is None:
        raise RuntimeError("Gateway Kyber public key not set. Run /auth first.")
    ss, ct = Kyber512.encaps(_gw_kyber_public)
    return ss, ct


# ── AES-256-GCM ───────────────────────────────────────────────────────────────

def aes_encrypt(pt: bytes, key: bytes) -> dict:
    iv  = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return {
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "tag":        base64.b64encode(enc.tag).decode(),
    }


# ── ECDSA ─────────────────────────────────────────────────────────────────────

def ecdsa_sign(data: bytes, priv) -> str:
    return base64.b64encode(
        priv.sign(data, ec.ECDSA(hashes.SHA256()))
    ).decode()


# ── Build packet ──────────────────────────────────────────────────────────────

def build_packet(device_id: str, patient_id: str, vitals: dict,
                 device_private_key, session_token: str) -> dict:
    """
    Packet build order:
      1. Kyber encaps + AES encrypt vitals
      2. Assemble final packet with encrypted_data (no plaintext vitals)
      3. Compute SHA-256 of final packet internally (not stored in packet)
      4. ECDSA sign the internal hash
      5. Attach signature and return
    """
    t0          = time.perf_counter()
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce       = secrets.token_hex(8)
    vitals_json = json.dumps(vitals, sort_keys=True).encode()

    # Step 1 — Kyber encaps + AES encrypt vitals
    ss, kyber_ct = kyber_encaps()
    enc          = aes_encrypt(vitals_json, ss)

    # Step 2 — assemble final packet (encrypted_data, no plaintext vitals)
    packet = {
        "session_token":  session_token,
        "device_id":      device_id,
        "patient_id":     patient_id,
        "timestamp":      timestamp,
        "nonce":          nonce,
        "kyber_ct":       base64.b64encode(kyber_ct).decode(),
        "encrypted_data": base64.b64encode(json.dumps(enc).encode()).decode(),
    }

    # Step 3 — compute SHA-256 of the final packet (internal, not stored)
    internal_hash = hashlib.sha256(
        json.dumps(packet, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    # Step 4 — ECDSA sign the hash
    # Step 5 — attach signature
    packet["signature"]  = ecdsa_sign(internal_hash.encode(), device_private_key)
    packet["encrypt_ms"] = round((time.perf_counter() - t0) * 1000, 3)

    return packet