---
title: "[Week 1] Fuad Haris – HMAC Protection: Create HMAC with Secret Key"
assignee: ""
labels: ["Week 1", "HMAC", "authentication"]
---

## Assigned To
**Fuad Haris** — Student 6

## Module
**HMAC Protection** | Integration Role: *MQTT Sender*

## Week 1 Goal (Apr 13–19)
> Implement HMAC-SHA256 generation and verification using a shared secret key, and have it running on dummy packet data.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment.
- No external libraries needed — Python's built-in `hmac` and `hashlib` modules are sufficient.
- Create your module folder:
  ```
  crypto_framework/
  └── hmac_module/
      ├── hmac_module.py
      └── test_hmac.py
  ```

### 2. Implement HMAC Generation
In `hmac_module.py`:
```python
import hmac, hashlib, json

def compute_hmac(data: bytes, secret_key: bytes) -> str:
    """
    Computes HMAC-SHA256 over `data` using `secret_key`.
    Returns the hex digest string — this becomes 'hmac_value' in the packet.
    """
    return hmac.new(secret_key, data, hashlib.sha256).hexdigest()
```

### 3. Implement HMAC Verification
```python
def verify_hmac(data: bytes, secret_key: bytes, expected_hmac: str) -> bool:
    """
    Returns True if the computed HMAC matches expected_hmac.
    Uses hmac.compare_digest to prevent timing attacks.
    """
    computed = compute_hmac(data, secret_key)
    return hmac.compare_digest(computed, expected_hmac)
```

### 4. Define What Gets MAC'd
HMAC should cover the same canonical data that Student 5 hashes, plus confirm with Student 5 that you use the same `fields_to_hash` helper (or a compatible one):
```python
def fields_to_mac(packet: dict) -> bytes:
    """
    Returns canonical JSON bytes of the fields to be MAC'd.
    Must be consistent with Student 5's fields_to_hash.
    """
    fields = {
        "encrypted_data": packet["encrypted_data"],
        "device_id":      packet.get("device_id", ""),
        "timestamp":      packet.get("timestamp", ""),
        "nonce":          packet.get("nonce", ""),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
```

### 5. Test HMAC on a Dummy Packet
In `test_hmac.py`:
```python
secret_key = b"iomt-shared-secret-2025"

dummy_packet = {
    "encrypted_data": "U2FtcGxlQmFzZTY0Q2lwaGVydGV4dA==",
    "device_id": "DEV-001",
    "timestamp": "2025-04-15T10:00:00Z",
    "nonce": "abc123xyz",
}

data_bytes = fields_to_mac(dummy_packet)
h = compute_hmac(data_bytes, secret_key)
print("HMAC:", h)

# Valid key → should pass
assert verify_hmac(data_bytes, secret_key, h) == True

# Wrong key → should fail
assert verify_hmac(data_bytes, b"wrong-key", h) == False

# Tampered data → should fail
tampered = dummy_packet.copy()
tampered["encrypted_data"] = "TAMPERED"
assert verify_hmac(fields_to_mac(tampered), secret_key, h) == False

print("All HMAC tests passed.")
```

### 6. Note the Differences Between HMAC and Plain Hash (for Week 2 Report)
Start a short notes file (`hmac_vs_hash_notes.md`) capturing your initial observations:
- Does HMAC require a secret key? Does SHA-256 hash?
- Can an attacker forge an HMAC without knowing the key?
- What attack does HMAC defend against that a plain hash does not?

You will expand this into a full comparison report in Week 2.

---

## Deliverables by End of Week 1
- [ ] `compute_hmac` and `verify_hmac` implemented.
- [ ] `fields_to_mac` helper aligned with Student 5's field selection.
- [ ] Tests passing: correct key passes, wrong key fails, tampered data fails.
- [ ] Initial `hmac_vs_hash_notes.md` notes file created.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 1–5** — your module is downstream of all encryption work. Coordinate with Student 5 on field selection and packet structure.

## Notes
The secret key used for HMAC in IoMT would normally be pre-provisioned on the device (similar to a device certificate). For this project, you can use a hardcoded shared key for testing, but document that in a real deployment this must be stored securely (e.g., in a hardware security module or secure element).
