---
title: "[Week 1] Akhilamshah B – AES Mode Comparison: Implement CBC & GCM with Test Data"
assignee: ""
labels: ["Week 1", "AES", "comparison"]
---

## Assigned To
**Akhilamshah B** — Student 2

## Module
**AES Mode Comparison** | Integration Role: *Data Flow Coordinator*

## Week 1 Goal (Apr 13–19)
> Implement two AES modes (CBC and GCM) and run them against the same test data so you have working code to compare in Week 2.

---

## Detailed Tasks

### 1. Environment Setup
- Clone the repository and set up a Python 3.10+ virtual environment.
- Install required library:
  ```bash
  pip install pycryptodome
  ```
- Create your module folder:
  ```
  crypto_framework/
  └── aes_modes/
      ├── aes_cbc.py
      ├── aes_gcm.py
      └── test_modes.py
  ```

### 2. Implement AES-CBC Mode
In `aes_cbc.py`, implement:
```python
def encrypt_cbc(plaintext: bytes, key: bytes) -> str:
    """Returns Base64-encoded IV + ciphertext"""

def decrypt_cbc(ciphertext_b64: str, key: bytes) -> bytes:
    """Recovers original plaintext"""
```
- Use PKCS7 padding.
- Prepend the 16-byte IV to the ciphertext before Base64 encoding.

### 3. Implement AES-GCM Mode
In `aes_gcm.py`, implement:
```python
def encrypt_gcm(plaintext: bytes, key: bytes) -> str:
    """Returns Base64-encoded nonce + tag + ciphertext"""

def decrypt_gcm(ciphertext_b64: str, key: bytes) -> bytes:
    """Recovers original plaintext; raises ValueError on auth failure"""
```
- Use a random 16-byte nonce.
- Prepend nonce + auth tag (16 bytes) before ciphertext, then Base64-encode.

### 4. Use the Same Test Data for Both Modes
In `test_modes.py`, use the same patient JSON used by Student 1:
```python
import json

patient_data = {
    "patient_id": "P001",
    "heart_rate": 72,
    "spo2": 98,
    "temperature": 36.6
}
plaintext = json.dumps(patient_data).encode("utf-8")
key_128 = b"0123456789abcdef"   # 16 bytes
key_256 = b"0123456789abcdef0123456789abcdef"  # 32 bytes
```
- Run encrypt → decrypt for both modes with both key sizes.
- Assert round-trips succeed.
- Print the Base64 ciphertext length for each so you can compare overhead.

### 5. Coordinate with Student 1
- Review Student 1's `encrypted_data` field format documentation.
- Confirm your implementations output the same Base64/encoding style.
- Note any differences and raise them in the team chat.

---

## Deliverables by End of Week 1
- [ ] `aes_cbc.py` with working `encrypt_cbc` / `decrypt_cbc`.
- [ ] `aes_gcm.py` with working `encrypt_gcm` / `decrypt_gcm`.
- [ ] `test_modes.py` running both modes successfully on patient data.
- [ ] Brief notes on what you plan to compare in Week 2 (security, performance, overhead).
- [ ] Code pushed to your branch.

---

## Dependencies
- **Student 1 (Adithyan)** — coordinate on the `encrypted_data` field format and test data structure.

## Notes
In Week 2 you will benchmark both modes and write a formal comparison. For now focus on correct implementation. GCM provides built-in authentication (no separate HMAC needed) — keep this in mind as you read ahead about Student 6's HMAC work.
