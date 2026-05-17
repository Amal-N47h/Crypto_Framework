"""
crypto_engine_device_sim.py
============================
Thin shim so attack_simulator.py can call build_packet()
without importing the full device Flask app.

Place in gateway/ folder alongside attack_simulator.py.
"""

import os, json, base64, hashlib, secrets, time
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timezone

_gw_kyber_public = None

def set_gateway_kyber_public(pub: bytes):
    global _gw_kyber_public
    _gw_kyber_public = pub

def compute_hash(packet: dict) -> str:
    copy = {k: v for k, v in packet.items()
            if k not in ("hash_value", "signature")}
    return hashlib.sha256(
        json.dumps(copy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def aes_encrypt(pt: bytes, key: bytes) -> dict:
    iv  = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ct  = enc.update(pt) + enc.finalize()
    return {"iv":  base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
            "tag": base64.b64encode(enc.tag).decode()}

def build_packet(device_id: str, patient_id: str, vitals: dict,
                 device_private_key, session_token: str) -> dict:
    """
    Build packet using the new order:
      1. assemble with plaintext vitals
      2. hash whole packet
      3. ECDSA sign hash_value
      4. Kyber + AES encrypt vitals
      5. replace vitals with encrypted_data
    """
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce       = secrets.token_hex(8)
    vitals_json = json.dumps(vitals, sort_keys=True).encode()

    t0 = time.perf_counter()

    # Step 1 — assemble with plaintext vitals
    packet = {
        "session_token": session_token,
        "device_id":     device_id,
        "patient_id":    patient_id,
        "timestamp":     timestamp,
        "nonce":         nonce,
        "vitals":        vitals,
    }

    # Step 2 — hash whole packet (covers plaintext vitals)
    hash_value = compute_hash(packet)

    # Step 3 — ECDSA sign hash_value
    signature = base64.b64encode(
        device_private_key.sign(hash_value.encode(), ec.ECDSA(hashes.SHA256()))
    ).decode()

    # Step 4 — Kyber + AES encrypt vitals
    ss, kyber_ct = Kyber512.encaps(_gw_kyber_public)
    enc          = aes_encrypt(vitals_json, ss)

    encrypt_ms = round((time.perf_counter() - t0) * 1000, 3)

    # Step 5 — replace plaintext vitals with encrypted fields
    del packet["vitals"]
    packet["kyber_ct"]       = base64.b64encode(kyber_ct).decode()
    packet["encrypted_data"] = base64.b64encode(json.dumps(enc).encode()).decode()
    packet["hash_value"]     = hash_value
    packet["signature"]      = signature
    packet["encrypt_ms"]     = encrypt_ms

    return packet
