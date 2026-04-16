---
title: "[Week 1] Amal Nath V S – Hybrid Encryption: Draft Hybrid Flow & Helper Functions"
assignee: ""
labels: ["Week 1", "hybrid-encryption", "integration"]
---

## Assigned To
**Amal Nath V S** — Student 4

## Module
**Hybrid Encryption** | Integration Role: *Integrity/Auth Integrator*

## Week 1 Goal (Apr 13–19)
> Design and draft the hybrid encryption flow that combines AES data encryption (Student 1) with ECC-secured key exchange (Student 3), and write stub/helper functions to be filled in Week 2.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment and install:
  ```bash
  pip install pycryptodome cryptography
  ```
- Create your module folder:
  ```
  crypto_framework/
  └── hybrid/
      ├── hybrid_encrypt.py
      └── test_hybrid.py
  ```

### 2. Understand the Full Pipeline (Research Task)
Before writing code, read and understand the outputs of Students 1, 2, and 3:
- **Student 1**: AES encrypt/decrypt functions and `encrypted_data` Base64 format.
- **Student 2**: AES mode comparison (CBC vs GCM) — note the recommended mode.
- **Student 3**: ECC key pair generation and ECDH shared-secret derivation.

Document your understanding as a comment block at the top of `hybrid_encrypt.py`:
```
# Hybrid Encryption Pipeline:
# 1. Receiver generates ECC key pair and shares public key.
# 2. Sender generates ephemeral ECC key pair.
# 3. Sender derives shared AES key via ECDH + HKDF (Student 3).
# 4. Sender encrypts patient data with AES using that key (Student 1/2).
# 5. Sender transmits: ECC ephemeral public key + encrypted_data.
# 6. Receiver derives same AES key, then decrypts.
```

### 3. Draft the Sender-Side Helper Functions
In `hybrid_encrypt.py`, write these function stubs with clear docstrings:
```python
def hybrid_encrypt(plaintext: bytes, receiver_public_key) -> dict:
    """
    Returns a dict:
    {
        "ephemeral_public_key": "<PEM string>",
        "encrypted_data": "<Base64 ciphertext>"
    }
    Step 1: Generate ephemeral ECC key pair (Student 3).
    Step 2: Derive AES key via ECDH (Student 3).
    Step 3: Encrypt plaintext with AES (Student 1/2).
    """

def hybrid_decrypt(packet: dict, receiver_private_key) -> bytes:
    """
    Recovers plaintext from the dict produced by hybrid_encrypt.
    Step 1: Read ephemeral_public_key from packet.
    Step 2: Derive same AES key via ECDH (Student 3).
    Step 3: Decrypt encrypted_data with AES (Student 1/2).
    """
```
- It is OK for these to be stubs (raise `NotImplementedError`) at the end of Week 1.
- The goal is to have the **interface and data structure defined** so downstream students (hash, HMAC, signature) know what fields to expect in the packet.

### 4. Define the Shared Packet Structure (Partial)
Define a helper that builds the packet dict that will grow over subsequent weeks:
```python
def build_packet(encrypted_data: str, ephemeral_public_key: str) -> dict:
    return {
        "ephemeral_public_key": ephemeral_public_key,
        "encrypted_data": encrypted_data,
        # Fields to be added later:
        # "hash_value": ...       (Student 5)
        # "hmac_value": ...       (Student 6)
        # "signature": ...        (Student 7)
        # "device_id": ...        (Student 8)
        # "timestamp": ...        (Student 9)
        # "nonce": ...            (Student 9)
    }
```

### 5. Write a Skeleton Test
In `test_hybrid.py`, write a test that will pass once the stubs are filled in Week 2:
```python
import json

sample_data = json.dumps({"patient_id": "P001", "heart_rate": 72}).encode()

# TODO Week 2: generate receiver key pair, call hybrid_encrypt/decrypt, assert match
```

---

## Deliverables by End of Week 1
- [ ] Pipeline flow documented as a comment block in `hybrid_encrypt.py`.
- [ ] `hybrid_encrypt` and `hybrid_decrypt` function stubs with clear docstrings.
- [ ] `build_packet` helper with all planned fields commented in.
- [ ] Skeleton test file ready for Week 2 implementation.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 1, 2, 3** — coordinate to understand their APIs before finalising your function signatures.

## Notes
Your packet structure definition (`build_packet`) is the most important output this week. Students 5–10 all add fields to this same packet, so getting the structure documented early avoids conflicts later. Discuss with the team and agree on field names.
