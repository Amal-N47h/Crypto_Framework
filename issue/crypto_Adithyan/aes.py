"""
aes_module.py
=============
AES-256-GCM Encryption & Decryption Module
Project : Lightweight Cryptographic Framework for IoMT Networks

Responsibility
--------------
Receive a fully-formed IoMT payload (with hash_value already included),
encrypt it, and decrypt it. Nothing more.

Expected payload format
-----------------------
{
    "device_id":   "IOMT-DEV-00423",
    "patient_id":  "PAT-9981",
    "timestamp":   "2026-05-04T13:56:35Z",
    "nonce":       "c6b50c52d0cfb14a",
    "vitals": {
        "heart_rate":     82,
        "spo2":           97,
        "temperature":    36.7,
        "blood_pressure": "120/80"
    },
    "hash_value":  "dc0de086513660b3db958cf7889eaf2bfd7ea9acf710bf2e05250046f0d29cc1"
}
"""

import os
import base64
import json
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
#  ENCRYPTION
# ─────────────────────────────────────────────

def aes_encrypt(payload: dict, key: bytes) -> dict:
    """
    Encrypt a complete IoMT payload using AES-256-GCM.

    The payload is taken as-is (hash_value already present) and
    encrypted as a single JSON bundle. A fresh 12-byte GCM nonce
    is generated for every message.

    Parameters
    ----------
    payload : dict  – The full IoMT payload including hash_value.
    key     : bytes – 32-byte AES-256 key (from ECC key exchange).

    Returns
    -------
    dict:
        'ciphertext' : Base64-encoded ciphertext + 16-byte GCM auth tag
        'gcm_nonce'  : Base64-encoded 12-byte GCM nonce

    Raises
    ------
    ValueError if key is not exactly 32 bytes.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes. Got {len(key)}.")

    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    gcm_nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(key).encrypt(gcm_nonce, plaintext, None)

    return {
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
        "gcm_nonce":  base64.urlsafe_b64encode(gcm_nonce).decode(),
    }


# ─────────────────────────────────────────────
#  DECRYPTION
# ─────────────────────────────────────────────

def aes_decrypt(encrypted: dict, key: bytes) -> dict:
    """
    Decrypt an AES-256-GCM packet and return the original payload.

    The GCM authentication tag is verified automatically during
    decryption — if the ciphertext was tampered with in transit,
    an InvalidTag exception is raised and the data is rejected.

    Parameters
    ----------
    encrypted : dict  – Output of aes_encrypt() containing
                        'ciphertext' and 'gcm_nonce'.
    key       : bytes – The same 32-byte AES-256 key.

    Returns
    -------
    dict – the original IoMT payload.

    Raises
    ------
    cryptography.exceptions.InvalidTag – ciphertext was tampered with.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes. Got {len(key)}.")

    gcm_nonce  = base64.urlsafe_b64decode(encrypted["gcm_nonce"])
    ciphertext = base64.urlsafe_b64decode(encrypted["ciphertext"])

    plaintext = AESGCM(key).decrypt(gcm_nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


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

    # Payload received from the device (hash already included)
    payload = {
        "device_id":  "IOMT-DEV-00423",
        "patient_id": "PAT-9981",
        "timestamp":  "2026-05-04T13:56:35Z",
        "nonce":      "c6b50c52d0cfb14a",
        "vitals": {
            "heart_rate":     82,
            "spo2":           97,
            "temperature":    36.7,
            "blood_pressure": "120/80",
        },
        "hash_value": "dc0de086513660b3db958cf7889eaf2bfd7ea9acf710bf2e05250046f0d29cc1",
    }

    print("\n[IN]      Received payload:")
    print(json.dumps(payload, indent=2))

    # Key (from ECC key exchange in production)
    key = generate_aes_key()
    print(f"\n[KEY]     AES-256 : {key_to_base64(key)}")

    # Encrypt
    encrypted = aes_encrypt(payload, key)
    print(f"\n[ENCRYPT] GCM nonce  : {encrypted['gcm_nonce']}")
    print(f"[ENCRYPT] Ciphertext : {encrypted['ciphertext'][:64]}...")

    # Transmit over MQTT
    packet = to_json(encrypted)
    print(f"\n[MQTT]    Transmitting {len(packet)} bytes...")

    # Decrypt
    result = aes_decrypt(from_json(packet), key)
    print(f"\n[DECRYPT] Recovered payload:")
    print(json.dumps(result, indent=2))

    assert result == payload
    print("\n[OK]  Round-trip successful.\n")

    # Tamper simulation
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
        print("      Packet rejected.\n")


if __name__ == "__main__":
    _demo()
