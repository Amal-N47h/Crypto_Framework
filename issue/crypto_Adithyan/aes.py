"""
aes_module.py
=============
AES-256-GCM Encryption & Decryption Module
Project : Lightweight Cryptographic Framework for IoMT Networks

Payload structure (what gets encrypted)
----------------------------------------
{
    "device_id":   "IOMT-DEV-00423",
    "patient_id":  "PAT-9981",
    "timestamp":   "2026-05-04T13:56:35Z",
    "nonce":       "c6b50c52d0cfb14a",        <- device-level nonce (from IoMT device)
    "vitals": {
        "heart_rate":     82,
        "spo2":           97,
        "temperature":    36.7,
        "blood_pressure": "120/80"
    },
    "hash_value":  "dc0de086..."               <- SHA-256 of vitals, verified on decrypt
}

The entire payload above (data + hash_value) is encrypted together as one bundle.
On decryption, hash_value is re-verified against the vitals to catch any tampering.
"""

import os
import base64
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────
KEY_SIZE_BYTES   = 32   # AES-256
NONCE_SIZE_BYTES = 12   # 96-bit GCM nonce


# ─────────────────────────────────────────────
#  KEY MANAGEMENT
# ─────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """
    Generate a cryptographically secure 256-bit AES key.
    In production this key comes from the ECC key exchange phase.
    """
    return os.urandom(KEY_SIZE_BYTES)

def key_to_base64(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode()

def key_from_base64(b64: str) -> bytes:
    return base64.urlsafe_b64decode(b64.encode())


# ─────────────────────────────────────────────
#  HASHING
# ─────────────────────────────────────────────

def compute_hash(vitals: dict) -> str:
    """
    Compute SHA-256 hash of the vitals block.

    The vitals dict is sorted before hashing so key order
    never affects the digest — consistent across devices.

    Returns hex digest string (same format as hash_value in the payload).
    """
    vitals_str = json.dumps(vitals, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(vitals_str.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────
#  PAYLOAD BUILDER
# ─────────────────────────────────────────────

def build_payload(device_id: str, patient_id: str, vitals: dict) -> dict:
    """
    Construct a fully-formed IoMT payload ready for encryption.

    Automatically fills:
        - timestamp  : current UTC time
        - nonce      : 8-byte random hex string (device-level, distinct from GCM nonce)
        - hash_value : SHA-256 of the vitals block

    Parameters
    ----------
    device_id  : str  – e.g. "IOMT-DEV-00423"
    patient_id : str  – e.g. "PAT-9981"
    vitals     : dict – { heart_rate, spo2, temperature, blood_pressure }

    Returns
    -------
    dict – complete payload matching the project schema
    """
    from datetime import datetime, timezone
    return {
        "device_id":  device_id,
        "patient_id": patient_id,
        "timestamp":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce":      os.urandom(8).hex(),          # device-level nonce
        "vitals":     vitals,
        "hash_value": compute_hash(vitals),
    }


# ─────────────────────────────────────────────
#  ENCRYPTION
# ─────────────────────────────────────────────

def aes_encrypt(payload: dict, key: bytes) -> dict:
    """
    Encrypt a complete IoMT payload using AES-256-GCM.

    The entire payload dict (including hash_value) is serialised to
    JSON and encrypted as one bundle. A fresh 12-byte GCM nonce is
    generated per message.

    Parameters
    ----------
    payload : dict  – Output of build_payload() or a manually constructed dict.
    key     : bytes – 32-byte AES-256 key.

    Returns
    -------
    dict:
        'ciphertext' : Base64-encoded AES-GCM output (payload + 16-byte auth tag)
        'gcm_nonce'  : Base64-encoded 12-byte GCM nonce
        'hash_value' : plaintext hash — passed to ECDSA signing module

    Raises
    ------
    ValueError  if key length != 32 bytes.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes. Got {len(key)}.")

    plaintext  = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    gcm_nonce  = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(key).encrypt(gcm_nonce, plaintext, None)

    return {
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
        "gcm_nonce":  base64.urlsafe_b64encode(gcm_nonce).decode(),
        "hash_value": payload["hash_value"],   # exposed for ECDSA signer
    }


# ─────────────────────────────────────────────
#  DECRYPTION
# ─────────────────────────────────────────────

def aes_decrypt(encrypted: dict, key: bytes) -> dict:
    """
    Decrypt an AES-256-GCM packet and verify the vitals hash.

    Verification steps
    ------------------
    1. AES-GCM decryption — GCM auth tag checked automatically.
       Raises InvalidTag if the ciphertext was modified in transit.
    2. Re-compute SHA-256 of the decrypted vitals block.
    3. Compare against hash_value inside the decrypted payload.
       Mismatch raises ValueError — catches any corruption that
       occurred before encryption or inside the payload fields.

    Parameters
    ----------
    encrypted : dict  – Output of aes_encrypt().
    key       : bytes – The same 32-byte AES-256 key.

    Returns
    -------
    dict – the original IoMT payload with an added 'hash_verified' flag.

    Raises
    ------
    cryptography.exceptions.InvalidTag – GCM tag mismatch (ciphertext tampered).
    ValueError                         – hash_value mismatch after decryption.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes. Got {len(key)}.")

    gcm_nonce  = base64.urlsafe_b64decode(encrypted["gcm_nonce"])
    ciphertext = base64.urlsafe_b64decode(encrypted["ciphertext"])

    # Step 1 — AES-GCM decrypt
    plaintext = AESGCM(key).decrypt(gcm_nonce, ciphertext, None)
    payload   = json.loads(plaintext.decode("utf-8"))

    # Step 2 — re-hash vitals
    recomputed = compute_hash(payload["vitals"])

    # Step 3 — verify
    if recomputed != payload["hash_value"]:
        raise ValueError(
            f"Hash mismatch — data may be corrupted.\n"
            f"  Stored   : {payload['hash_value']}\n"
            f"  Computed : {recomputed}"
        )

    payload["hash_verified"] = True
    return payload


# ─────────────────────────────────────────────
#  SERIALIZATION  (for MQTT transmission)
# ─────────────────────────────────────────────

def to_json(data: dict) -> str:
    """Serialize an encrypted packet to a JSON string for MQTT."""
    return json.dumps(data)

def from_json(json_str: str) -> dict:
    """Deserialize a received MQTT JSON string back to a dict."""
    return json.loads(json_str)


# ─────────────────────────────────────────────
#  DEMO
# ─────────────────────────────────────────────

def _demo():
    SEP = "=" * 62

    print(SEP)
    print("  AES-256-GCM Demo  —  IoMT Cryptographic Framework")
    print(SEP)

    # ── Build payload ────────────────────────────────────────────
    vitals = {
        "heart_rate":     82,
        "spo2":           97,
        "temperature":    36.7,
        "blood_pressure": "120/80",
    }
    payload = build_payload("IOMT-DEV-00423", "PAT-9981", vitals)

    print("\n[DEVICE]  Payload to encrypt:")
    print(json.dumps(payload, indent=2))

    # ── Generate key ─────────────────────────────────────────────
    key = generate_aes_key()
    print(f"\n[DEVICE]  AES-256 key  : {key_to_base64(key)}")

    # ── Encrypt ──────────────────────────────────────────────────
    encrypted = aes_encrypt(payload, key)
    print(f"\n[DEVICE]  GCM nonce   : {encrypted['gcm_nonce']}")
    print(f"[DEVICE]  Ciphertext  : {encrypted['ciphertext'][:64]}...")
    print(f"[DEVICE]  Hash (->ECDSA signer): {encrypted['hash_value'][:32]}...")

    # ── MQTT ─────────────────────────────────────────────────────
    packet = to_json(encrypted)
    print(f"\n[MQTT]    Transmitting {len(packet)} bytes...")

    # ── Decrypt & verify ─────────────────────────────────────────
    result = aes_decrypt(from_json(packet), key)
    print(f"\n[GATEWAY] Decrypted payload:")
    print(json.dumps({k: v for k, v in result.items() if k != "hash_verified"}, indent=2))
    print(f"\n[GATEWAY] Hash verified : {result['hash_verified']}  OK")
    print(f"[OK]  Round-trip successful.\n")

    # ── Tamper simulation ────────────────────────────────────────
    print("-" * 62)
    print("[ATTACK]  Flipping a byte in the ciphertext...")
    tampered = dict(encrypted)
    raw = bytearray(base64.urlsafe_b64decode(tampered["ciphertext"]))
    raw[len(raw) // 2] ^= 0xFF
    tampered["ciphertext"] = base64.urlsafe_b64encode(bytes(raw)).decode()

    try:
        aes_decrypt(tampered, key)
        print("[FAIL]  Tamper not detected!")
    except Exception as e:
        print(f"[OK]  Tamper detected  ->  {type(e).__name__}")
        print("      Packet rejected by gateway.\n")


if __name__ == "__main__":
    _demo()
