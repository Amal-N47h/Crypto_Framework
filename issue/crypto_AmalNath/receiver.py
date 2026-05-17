"""
receiver.py — Gateway Side (Hybrid Decryption)
===============================================
Run this FIRST to generate Kyber keypair → kyber_public.key + kyber_secret.key
Then run sender.py, then run this again to decrypt.

Steps:
  1. python receiver.py        ← generates keys
  2. python sender.py          ← encrypts and saves packet.json
  3. python receiver.py        ← decrypts packet.json

"""

import json, base64, os
from kyber_py.kyber import Kyber512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_kyber_keypair():
    pub, sec = Kyber512.keygen()
    with open("kyber_public.key", "wb") as f:
        f.write(pub)
    with open("kyber_secret.key", "wb") as f:
        f.write(sec)
    print("[✓] Kyber keypair generated")
    print("    → kyber_public.key (share with device/sender)")
    print("    → kyber_secret.key (keep secret)")


def hybrid_decrypt(packet: dict, kyber_sec: bytes) -> bytes:
    # Step 1 — Kyber512 decaps: recover shared secret from kyber_ct
    ss = Kyber512.decaps(kyber_sec, base64.b64decode(packet["kyber_ct"]))

    # Step 2 — AES-256-GCM decrypt using recovered shared secret
    dec = Cipher(
        algorithms.AES(ss),
        modes.GCM(
            base64.b64decode(packet["iv"]),
            base64.b64decode(packet["tag"])
        )
    ).decryptor()

    return dec.update(base64.b64decode(packet["ciphertext"])) + dec.finalize()


if __name__ == "__main__":
    # Generate keys if not present
    if not os.path.exists("kyber_secret.key"):
        generate_kyber_keypair()
        print("\nNow run sender.py, then run this again to decrypt.\n")
        exit()

    # Load secret key
    with open("kyber_secret.key", "rb") as f:
        kyber_sec = f.read()
    print("[✓] Loaded Kyber secret key")

    # Load packet from sender
    if not os.path.exists("packet.json"):
        print("[!] packet.json not found. Run sender.py first.")
        exit()

    with open("packet.json") as f:
        packet = json.load(f)
    print("[✓] Loaded packet.json")

    # Decrypt
    plaintext = hybrid_decrypt(packet, kyber_sec)
    vitals    = json.loads(plaintext.decode())
    print(f"\n[RECEIVER] Decrypted vitals : {vitals}")
    print("\n[✓] Hybrid decryption successful")
