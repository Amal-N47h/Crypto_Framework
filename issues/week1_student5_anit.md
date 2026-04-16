---
title: "[Week 1] Anit Benny – SHA-256 Integrity: Hash Generation on Dummy Packet"
assignee: ""
labels: ["Week 1", "SHA-256", "integrity"]
---

## Assigned To
**Anit Benny** — Student 5

## Module
**SHA-256 Integrity** | Integration Role: *Packet Builder*

## Week 1 Goal (Apr 13–19)
> Implement SHA-256 hash generation and verification, and verify it correctly detects a tampered vs. intact dummy packet.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment.
- No external libraries needed — Python's built-in `hashlib` covers SHA-256.
- Create your module folder:
  ```
  crypto_framework/
  └── integrity/
      ├── sha256_module.py
      └── test_sha256.py
  ```

### 2. Implement SHA-256 Hash Generation
In `sha256_module.py`:
```python
import hashlib, json

def compute_hash(data: bytes) -> str:
    """
    Returns the SHA-256 hash of `data` as a lowercase hex string.
    This will become the 'hash_value' field in the packet.
    """
    return hashlib.sha256(data).hexdigest()
```

### 3. Implement Hash Verification
```python
def verify_hash(data: bytes, expected_hash: str) -> bool:
    """
    Returns True if SHA-256(data) == expected_hash, False otherwise.
    Use hmac.compare_digest for timing-safe comparison.
    """
    import hmac as _hmac
    return _hmac.compare_digest(compute_hash(data), expected_hash)
```

### 4. Define What Gets Hashed
Decide and document which fields of the packet are included in the hash input.
Recommended approach — hash the canonical JSON of the core data fields:
```python
def fields_to_hash(packet: dict) -> bytes:
    """
    Extracts the fields that must be integrity-protected and returns
    their canonical JSON bytes (sorted keys, no whitespace).
    """
    fields = {
        "encrypted_data": packet["encrypted_data"],
        "device_id":      packet.get("device_id", ""),
        "timestamp":      packet.get("timestamp", ""),
        "nonce":          packet.get("nonce", ""),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
```
Document your decision so Student 8 (verifier) knows what to re-hash at the receiver.

### 5. Build a Dummy Packet and Test
In `test_sha256.py`:
```python
# Dummy packet (replace encrypted_data with real output in Week 2)
dummy_packet = {
    "encrypted_data": "U2FtcGxlQmFzZTY0Q2lwaGVydGV4dA==",
    "device_id": "DEV-001",
    "timestamp": "2025-04-15T10:00:00Z",
    "nonce": "abc123xyz",
}

# Compute hash
data_bytes = fields_to_hash(dummy_packet)
h = compute_hash(data_bytes)
print("Hash:", h)

# Verify intact packet
assert verify_hash(data_bytes, h) == True, "Intact packet must verify"

# Tamper with encrypted_data and verify detection
tampered = dummy_packet.copy()
tampered["encrypted_data"] = "TAMPERED_VALUE"
assert verify_hash(fields_to_hash(tampered), h) == False, "Tampered packet must fail"

print("All integrity tests passed.")
```

---

## Deliverables by End of Week 1
- [ ] `compute_hash` and `verify_hash` implemented.
- [ ] `fields_to_hash` helper with documented field selection.
- [ ] Tests passing: intact packet verifies, tampered packet fails.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 1–4** — your module operates on the packet structure. Coordinate with Student 4 (Amal) on the agreed packet field names.

## Notes
The `hash_value` field you produce will be added to the shared packet by you in Week 2 (your Packet Builder role). This week just make sure your hashing logic is solid. Student 10 (final verifier) will call your `verify_hash` function at the end of the pipeline.
