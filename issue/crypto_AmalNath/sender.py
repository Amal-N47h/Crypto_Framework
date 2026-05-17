"""
sender.py — Device Side (Hybrid Encryption)
============================================
1. Kyber512 encaps → shared secret (ss) + kyber_ct
2. AES-256-GCM    → encrypt vitals using ss
3. Save packet    → packet.json (simulates sending to gateway)

Run:
  python sender.py
"""

import os, json, base64
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hybrid_encrypt(plaintext: bytes, kyber_pub: bytes) -> dict:
    # Step 1 — Kyber512 encaps: produces shared secret + ciphertext
    ss, kyber_ct = Kyber512.encaps(kyber_pub)

    # Step 2 — AES-256-GCM encrypt using shared secret
    iv  = os.urandom(12)
    enc = Cipher(algorithms.AES(ss), modes.GCM(iv)).encryptor()
    ct  = enc.update(plaintext) + enc.finalize()

    return {
        "kyber_ct":   base64.b64encode(kyber_ct).decode(),
        "iv":         base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "tag":        base64.b64encode(enc.tag).decode(),
    }


if __name__ == "__main__":
    # Load gateway's Kyber public key
    with open("kyber_public.key", "rb") as f:
        kyber_pub = f.read()
    print("[✓] Loaded gateway Kyber public key")

    # IoMT vitals to send
    vitals    = {"heart_rate": 78, "spo2": 98, "temperature": 36.7, "bp": "120/80"}
    plaintext = json.dumps(vitals).encode()
    print(f"[SENDER] Plaintext vitals : {vitals}")

    # Encrypt
    packet = hybrid_encrypt(plaintext, kyber_pub)
    print(f"[SENDER] kyber_ct size    : {len(base64.b64decode(packet['kyber_ct']))} bytes")
    print(f"[SENDER] ciphertext       : {packet['ciphertext'][:40]}...")

    # Save packet (simulates transmitting to gateway)
    with open("packet.json", "w") as f:
        json.dump(packet, f)
    print("[✓] Encrypted packet saved to packet.json")
