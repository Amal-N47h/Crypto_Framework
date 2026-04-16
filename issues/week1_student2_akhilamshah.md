# [Week 1] Akhilamshah B – AES Mode Comparison

**Module:** AES Mode Comparison | **Role:** Data Flow Coordinator

**Goal (Apr 13–19):** Implement both AES-CBC and AES-GCM modes and run them on the same test data so you have working code to compare in Week 2.

## Tasks

1. Install Python 3.10+ and `pycryptodome`. Create folder `crypto_framework/aes_modes/` with `aes_cbc.py`, `aes_gcm.py`, and `test_modes.py`.
2. Implement `encrypt_cbc` / `decrypt_cbc` in `aes_cbc.py`. Use PKCS7 padding and prepend the IV to the ciphertext before Base64 encoding.
3. Implement `encrypt_gcm` / `decrypt_gcm` in `aes_gcm.py`. Prepend nonce + auth tag before ciphertext, then Base64-encode.
4. In `test_modes.py`, run encrypt → decrypt for both modes using the same patient JSON (`patient_id`, `heart_rate`, `spo2`, `temperature`). Assert all round-trips succeed.
5. Review Student 1's `encrypted_data` field format and make sure your Base64 encoding style matches.

## Deliverables
- [ ] `aes_cbc.py` with working encrypt/decrypt
- [ ] `aes_gcm.py` with working encrypt/decrypt
- [ ] Both modes tested on patient data with passing assertions
- [ ] Code pushed to your branch
