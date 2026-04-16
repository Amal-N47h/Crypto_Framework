# [Week 1] Noufan TN – Device Authentication

**Module:** Device Authentication | **Role:** Verification Pipeline Coordinator

**Goal (Apr 13–19):** Build a trusted device registry with basic check logic, and document the full receiver verification order for the team.

## Tasks

1. Create folder `crypto_framework/auth/` with `device_auth.py` and `test_device_auth.py`. No extra libraries needed.
2. Define a `TRUSTED_DEVICES` dict mapping `device_id` to device metadata (name, location, active status). Add at least 3 entries including one inactive device.
3. Implement `register_device(device_id, name, location)`, `deactivate_device(device_id)`, and `is_trusted_device(device_id) -> bool` (returns `True` only if the device exists and is active).
4. In `test_device_auth.py`, test: known active device passes, unknown device fails, deactivated device fails, newly registered device passes then fails after deactivation.
5. Create `verification_order.md` in your folder documenting the exact 7-step order the receiver must follow: (1) device auth → (2) timestamp → (3) nonce → (4) ECDSA signature → (5) SHA-256 hash → (6) HMAC → (7) AES decryption. Share this file with the whole team — Students 9 and 10 depend on it.

## Deliverables
- [ ] `TRUSTED_DEVICES` registry with register/deactivate/check functions
- [ ] All authentication tests passing
- [ ] `verification_order.md` written and pushed
- [ ] Code pushed to your branch
