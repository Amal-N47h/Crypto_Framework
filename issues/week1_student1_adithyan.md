---
title: "[Week 1] Adithyan B – AES Encryption: Environment Setup & Basic Encrypt/Decrypt"
assignee: ""
labels: ["Week 1", "AES", "encryption"]
---

## Assigned To
**Adithyan B** — Student 1

## Module
**AES Encryption** | Integration Role: *Packet Format Coordinator*

## Week 1 Goal (Apr 13–19)
> Set up the development environment and get basic AES-128/256 encrypt/decrypt working on sample patient data.

---

## Detailed Tasks

### 1. Environment Setup
- Install Python 3.10+ and create a virtual environment for the project.
- Install the cryptography library:
  ```bash
  pip install pycryptodome
  ```
- Create your module folder:
  ```
  crypto_framework/
  └── aes/
      ├── aes_module.py
      └── test_aes.py
  ```

### 2. Implement AES-128 Encryption
- Write a function `aes_encrypt(plaintext: bytes, key: bytes) -> str` using AES-128 (16-byte key).
- Use CBC or GCM mode for now (Student 2 will compare both in Week 2 and confirm the final choice).
- Return the ciphertext encoded as a **Base64** string so it can be embedded in JSON.

### 3. Implement AES-256 Encryption
- Repeat the same function with a 32-byte key for AES-256.
- Keep both variants callable side-by-side for comparison.

### 4. Implement Decryption
- Write a matching `aes_decrypt(ciphertext_b64: str, key: bytes) -> bytes` function.
- Verify that `aes_decrypt(aes_encrypt(data, key), key) == data` is always `True`.

### 5. Test on Sample Patient Data
Use this sample in `test_aes.py`:
```python
import json

patient_data = {
    "patient_id": "P001",
    "heart_rate": 72,
    "spo2": 98,
    "temperature": 36.6
}

plaintext = json.dumps(patient_data).encode("utf-8")
```
- Encrypt the JSON bytes, print the Base64 ciphertext, decrypt it, and assert it matches the original.

### 6. Define the `encrypted_data` Field Format
Document (in a comment block at the top of `aes_module.py`) the exact format other students must follow:

| Field | Value |
|---|---|
| Encoding | Base64 |
| Key sizes | 128-bit (16 bytes) or 256-bit (32 bytes) |
| IV/Nonce storage | Prepend IV (16 bytes) to ciphertext before Base64 encoding |
| Character set | UTF-8 safe (Base64 output only) |

---

## Deliverables by End of Week 1
- [ ] `aes_encrypt` and `aes_decrypt` functions implemented for both AES-128 and AES-256.
- [ ] Successful round-trip test on sample JSON patient data (encrypt → decrypt → verify).
- [ ] `encrypted_data` field format documented in the module file.
- [ ] Code pushed to your branch in the repository.

---

## Dependencies
**None** — you are the foundation module. Every other student depends on the output format you define here.

## Who Depends on You
- Student 2 (Akhilamshah) will run mode comparisons using your module.
- Student 3 (Alwin) will use your AES key format in ECC key exchange.
- All downstream students build on your `encrypted_data` field format.
