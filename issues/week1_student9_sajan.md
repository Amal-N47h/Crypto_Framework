# [Week 1] Sajan Baby P – Replay Protection

**Module:** Replay Protection | **Role:** Attack Injection Tester

**Goal (Apr 13–19):** Implement timestamp validation and nonce tracking so expired and replayed packets can be detected.

## Tasks

1. Create folder `crypto_framework/replay_protection/` with `replay_module.py` and `test_replay.py`. No extra libraries needed — use Python's `datetime` and `uuid`.
2. Implement `generate_timestamp() -> str` returning the current UTC time in ISO 8601 format, and `is_timestamp_valid(timestamp_str) -> bool` that returns `False` if the packet is older than 60 seconds (configurable constant).
3. Implement `generate_nonce() -> str` using `uuid.uuid4()`, and `is_nonce_fresh(nonce) -> bool` that returns `False` if the nonce has been seen before (use an in-memory set). Include a `reset_nonce_store()` helper for testing.
4. Implement `check_replay_protection(packet: dict) -> tuple[bool, str]` combining both checks, returning `(True, "OK")` or `(False, reason)` where reason is `"EXPIRED_TIMESTAMP"` or `"DUPLICATE_NONCE"`.
5. In `test_replay.py`, test: fresh packet passes, same packet replayed fails with `DUPLICATE_NONCE`, packet with old timestamp fails with `EXPIRED_TIMESTAMP`.

## Deliverables
- [ ] Timestamp generation and validation implemented
- [ ] Nonce generation and dedup tracking implemented
- [ ] `check_replay_protection` combining both checks
- [ ] All three test scenarios passing
- [ ] Code pushed to your branch
