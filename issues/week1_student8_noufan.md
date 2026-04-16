---
title: "[Week 1] Noufan TN – Device Authentication: Build Trusted Device Registry & Check Logic"
assignee: ""
labels: ["Week 1", "authentication", "device"]
---

## Assigned To
**Noufan TN** — Student 8

## Module
**Device Authentication** | Integration Role: *Verification Pipeline Coordinator*

## Week 1 Goal (Apr 13–19)
> Create a trusted device registry and implement the basic device ID check logic that will form the first step of the full verification pipeline.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment.
- No extra libraries needed beyond the standard library.
- Create your module folder:
  ```
  crypto_framework/
  └── auth/
      ├── device_auth.py
      └── test_device_auth.py
  ```

### 2. Build the Trusted Device Registry
In `device_auth.py`, implement a simple registry (for now a Python dict or JSON file):
```python
# Trusted device registry: maps device_id → device metadata
TRUSTED_DEVICES = {
    "DEV-001": {"name": "Heart Monitor A", "location": "ICU", "active": True},
    "DEV-002": {"name": "Temp Sensor B",   "location": "Ward 3", "active": True},
    "DEV-999": {"name": "Old Device",      "location": "Storage", "active": False},
}
```
Design it so new devices can be registered:
```python
def register_device(device_id: str, name: str, location: str) -> None:
    """Registers a new trusted device."""

def deactivate_device(device_id: str) -> None:
    """Marks a device as inactive (e.g., decommissioned or compromised)."""
```

### 3. Implement the Device Authentication Check
```python
def is_trusted_device(device_id: str) -> bool:
    """
    Returns True if device_id is in the registry AND is marked active.
    Returns False for unknown or deactivated devices.
    """
    device = TRUSTED_DEVICES.get(device_id)
    return device is not None and device.get("active", False)
```

### 4. Define the Full Verification Order (Documentation)
Your most important Week 1 task is to **document the exact sequence** of checks that the receiver must perform. Create `verification_order.md` inside your folder:

```markdown
# Receiver Verification Pipeline Order

When a packet arrives, checks must be performed in this exact order:

1. **Device Authentication** (this module, Student 8)
   - Reject packet immediately if device_id is not in trusted registry.

2. **Timestamp Check** (Student 9 - Sajan)
   - Reject if timestamp is older than the allowed window (e.g., 60 seconds).

3. **Nonce Check** (Student 9 - Sajan)
   - Reject if nonce has been seen before (replay attack).

4. **ECDSA Signature Verification** (Student 7 - John)
   - Reject if signature does not match packet fields.

5. **SHA-256 Hash Verification** (Student 5 - Anit)
   - Reject if hash_value does not match re-computed hash.

6. **HMAC Verification** (Student 6 - Fuad)
   - Reject if hmac_value does not match.

7. **AES Decryption** (Students 1–4)
   - Decrypt encrypted_data to recover patient payload.

Fail fast: stop at the first failed check and log the failure reason.
```

### 5. Test the Device Authentication
In `test_device_auth.py`:
```python
# Known active device
assert is_trusted_device("DEV-001") == True

# Unknown device
assert is_trusted_device("DEV-999-UNKNOWN") == False

# Deactivated device
assert is_trusted_device("DEV-999") == False

# Register a new device and check it
register_device("DEV-003", "BP Monitor C", "OPD")
assert is_trusted_device("DEV-003") == True

# Deactivate it and check again
deactivate_device("DEV-003")
assert is_trusted_device("DEV-003") == False

print("All device authentication tests passed.")
```

---

## Deliverables by End of Week 1
- [ ] `TRUSTED_DEVICES` registry with at least 3 entries.
- [ ] `register_device`, `deactivate_device`, and `is_trusted_device` implemented.
- [ ] `verification_order.md` documenting the 7-step receiver pipeline order.
- [ ] All tests passing.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 5–7** — review their modules to understand what checks come before/after yours in the pipeline.

## Notes
The `verification_order.md` file you create this week is a **shared team document** — share it with all students so everyone understands where their module fits in the full pipeline. This is the most critical coordination output of Week 1. Student 10 (Vimal) will implement the full pipeline based on your ordering.
