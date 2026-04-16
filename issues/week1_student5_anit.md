# [Week 1] Anit Benny – SHA-256 Integrity

**Module:** SHA-256 Integrity | **Role:** Packet Builder

**Goal (Apr 13–19):** Implement SHA-256 hash generation and verification, and confirm it correctly detects tampering on a dummy packet.

## Tasks

1. Create folder `crypto_framework/integrity/` with `sha256_module.py` and `test_sha256.py`. No extra libraries needed — use Python's built-in `hashlib`.
2. Implement `compute_hash(data: bytes) -> str` that returns the SHA-256 hex digest. This will become the `hash_value` field in the packet.
3. Implement `verify_hash(data: bytes, expected_hash: str) -> bool` using `hmac.compare_digest` for timing-safe comparison.
4. Write a `fields_to_hash(packet: dict) -> bytes` helper that serialises the fields to be integrity-protected into canonical JSON bytes (sorted keys, no whitespace). Coordinate with Student 4 on which fields to include.
5. In `test_sha256.py`, build a dummy packet, compute its hash, assert it verifies correctly, then tamper with `encrypted_data` and assert verification fails.

## Deliverables
- [ ] `compute_hash` and `verify_hash` implemented
- [ ] `fields_to_hash` helper with documented field selection
- [ ] Tests passing: intact packet verifies, tampered packet fails
- [ ] Code pushed to your branch
