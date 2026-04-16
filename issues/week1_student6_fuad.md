# [Week 1] Fuad Haris – HMAC Protection

**Module:** HMAC Protection | **Role:** MQTT Sender

**Goal (Apr 13–19):** Implement HMAC-SHA256 generation and verification using a shared secret key, running on dummy packet data.

## Tasks

1. Create folder `crypto_framework/hmac_module/` with `hmac_module.py` and `test_hmac.py`. No extra libraries needed — use Python's built-in `hmac` and `hashlib`.
2. Implement `compute_hmac(data: bytes, secret_key: bytes) -> str` that returns the HMAC-SHA256 hex digest. This becomes the `hmac_value` field in the packet.
3. Implement `verify_hmac(data: bytes, secret_key: bytes, expected_hmac: str) -> bool` using `hmac.compare_digest`.
4. Write a `fields_to_mac(packet: dict) -> bytes` helper consistent with Student 5's `fields_to_hash` — both should serialise the same packet fields the same way.
5. In `test_hmac.py`, test with a dummy packet: correct key passes, wrong key fails, tampered data fails.
6. Start a short notes file (`hmac_vs_hash_notes.md`) listing initial observations on how HMAC differs from a plain hash (Week 2 will expand this into a full comparison).

## Deliverables
- [ ] `compute_hmac` and `verify_hmac` implemented
- [ ] `fields_to_mac` helper aligned with Student 5's field selection
- [ ] Tests passing: correct key passes, wrong key fails, tampered data fails
- [ ] Initial `hmac_vs_hash_notes.md` created
- [ ] Code pushed to your branch
