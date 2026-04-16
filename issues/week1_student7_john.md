# [Week 1] John Varghese – ECDSA Signature

**Module:** ECDSA Signature | **Role:** MQTT Receiver

**Goal (Apr 13–19):** Generate an ECDSA key pair, sign a test message, and verify the signature — including failure cases.

## Tasks

1. Install Python 3.10+ and `cryptography`. Create folder `crypto_framework/signature/` with `ecdsa_module.py` and `test_ecdsa.py`.
2. Implement `generate_signing_keypair()` using NIST P-256. Add PEM serialization helpers for both private and public keys.
3. Implement `sign_data(data: bytes, private_key) -> bytes` that returns a DER-encoded ECDSA signature using SHA-256.
4. Implement `verify_signature(data: bytes, signature: bytes, public_key) -> bool` that returns `True` on a valid signature and `False` on `InvalidSignature`.
5. Write a `fields_to_sign(packet: dict) -> bytes` helper serialising the packet fields to sign — coordinate with Student 5 to use the same canonical format.
6. In `test_ecdsa.py`, test: valid signature passes, wrong public key fails, tampered data fails.

## Deliverables
- [ ] `generate_signing_keypair()` working with P-256
- [ ] `sign_data` and `verify_signature` implemented
- [ ] `fields_to_sign` helper documented
- [ ] Tests: valid passes, wrong key fails, tampered data fails
- [ ] Code pushed to your branch
