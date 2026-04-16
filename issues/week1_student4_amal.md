# [Week 1] Amal Nath V S – Hybrid Encryption

**Module:** Hybrid Encryption | **Role:** Integrity/Auth Integrator

**Goal (Apr 13–19):** Design the hybrid encryption flow that combines AES data encryption with ECC key exchange, and define the shared packet structure.

## Tasks

1. Install Python 3.10+, `pycryptodome`, and `cryptography`. Create folder `crypto_framework/hybrid/` with `hybrid_encrypt.py` and `test_hybrid.py`.
2. Read and understand the outputs of Students 1, 2, and 3. Document the hybrid pipeline as a comment block at the top of `hybrid_encrypt.py`:
   - Sender generates ephemeral ECC key pair → derives AES key via ECDH → encrypts data with AES → sends ephemeral public key + encrypted data.
   - Receiver uses own private key + sender's ephemeral public key → derives same AES key → decrypts.
3. Write function stubs `hybrid_encrypt(plaintext, receiver_public_key) -> dict` and `hybrid_decrypt(packet, receiver_private_key) -> bytes` with clear docstrings. Stubs can raise `NotImplementedError` for now.
4. Define `build_packet(encrypted_data, ephemeral_public_key) -> dict` returning a dict with all planned fields listed (include commented-out fields for `hash_value`, `hmac_value`, `signature`, `device_id`, `timestamp`, `nonce` to be filled by later students).
5. Write a skeleton test in `test_hybrid.py` that will be completed in Week 2.

## Deliverables
- [ ] Pipeline flow documented as a comment block
- [ ] `hybrid_encrypt` / `hybrid_decrypt` stubs with docstrings
- [ ] `build_packet` helper with all planned packet fields listed
- [ ] Code pushed to your branch
