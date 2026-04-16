# [Week 1] Adithyan B – AES Encryption

**Module:** AES Encryption | **Role:** Packet Format Coordinator

**Goal (Apr 13–19):** Set up the environment and get basic AES-128/256 encrypt/decrypt working on sample patient data.

## Tasks

1. Install Python 3.10+ and `pycryptodome`. Create folder `crypto_framework/aes/` with `aes_module.py` and `test_aes.py`.
2. Implement `aes_encrypt(plaintext, key)` for AES-128 (16-byte key) and AES-256 (32-byte key). Use CBC or GCM mode. Return Base64-encoded ciphertext.
3. Implement `aes_decrypt(ciphertext_b64, key)` and confirm the round-trip matches the original.
4. Test on a sample JSON patient record (`patient_id`, `heart_rate`, `spo2`, `temperature`). Encrypt, decrypt, assert equality.
5. Document the `encrypted_data` field format at the top of `aes_module.py`: encoding (Base64), key sizes, and how the IV is stored alongside the ciphertext.

## Deliverables
- [ ] `aes_encrypt` / `aes_decrypt` working for AES-128 and AES-256
- [ ] Round-trip test passing on patient JSON
- [ ] `encrypted_data` format documented
- [ ] Code pushed to your branch
