# [Week 1] Alwin T Varghese – ECC Key Exchange

**Module:** ECC Key Exchange | **Role:** Encryption Chain Integrator

**Goal (Apr 13–19):** Generate ECC key pairs and demonstrate a working ECDH key exchange where both sides derive the same shared secret.

## Tasks

1. Install Python 3.10+ and `cryptography`. Create folder `crypto_framework/ecc/` with `ecc_keygen.py`, `ecc_exchange.py`, and `test_ecc.py`.
2. In `ecc_keygen.py`, implement `generate_ecc_keypair()` using the NIST P-256 curve. Add helpers to serialize/deserialize keys as PEM bytes.
3. In `ecc_exchange.py`, implement `derive_shared_secret(private_key, peer_public_key)` using ECDH. Apply HKDF-SHA256 to produce a 32-byte AES key from the raw shared secret.
4. In `test_ecc.py`, simulate sender and receiver: each generates a key pair, both call `derive_shared_secret` with the other's public key, and assert the two results are identical.
5. Review Student 1's AES key format so your 32-byte output matches what is expected as the AES-256 key input.

## Deliverables
- [ ] `generate_ecc_keypair()` returning serializable P-256 key pairs
- [ ] `derive_shared_secret()` producing a 32-byte key via ECDH + HKDF
- [ ] Test confirming sender and receiver derive the same secret
- [ ] Code pushed to your branch
