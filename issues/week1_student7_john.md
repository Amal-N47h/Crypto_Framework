---
title: "[Week 1] John Varghese – ECDSA Signature: Generate Key Pair & Sign Data"
assignee: ""
labels: ["Week 1", "ECDSA", "signature"]
---

## Assigned To
**John Varghese** — Student 7

## Module
**ECDSA Signature** | Integration Role: *MQTT Receiver*

## Week 1 Goal (Apr 13–19)
> Generate an ECDSA key pair and successfully sign a test message, then verify the signature.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment and install:
  ```bash
  pip install cryptography
  ```
- Create your module folder:
  ```
  crypto_framework/
  └── signature/
      ├── ecdsa_module.py
      └── test_ecdsa.py
  ```

### 2. Generate an ECDSA Key Pair
In `ecdsa_module.py`:
```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_signing_keypair():
    """
    Generates an ECDSA key pair using NIST P-256.
    Returns (private_key, public_key).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key
```

Also add PEM serialization helpers:
```python
def private_key_to_pem(private_key) -> bytes: ...
def public_key_to_pem(public_key) -> bytes: ...
def pem_to_public_key(pem: bytes): ...
```

### 3. Implement Signing
```python
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives import hashes

def sign_data(data: bytes, private_key) -> bytes:
    """
    Signs `data` with the ECDSA private key using SHA-256.
    Returns the DER-encoded signature bytes.
    """
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
```

### 4. Implement Verification
```python
from cryptography.exceptions import InvalidSignature

def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """
    Returns True if signature is valid for data under public_key.
    Returns False if the signature is invalid.
    """
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
```

### 5. Define What Gets Signed
ECDSA should sign the most critical fields of the packet to prove sender authenticity.
Coordinate with Student 5 on the `fields_to_hash` helper — you can sign the same canonical bytes:
```python
import json

def fields_to_sign(packet: dict) -> bytes:
    """
    Returns canonical JSON bytes of fields that must be signed.
    """
    fields = {
        "encrypted_data": packet["encrypted_data"],
        "device_id":      packet.get("device_id", ""),
        "timestamp":      packet.get("timestamp", ""),
        "nonce":          packet.get("nonce", ""),
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
```

### 6. Test: Sign, Verify, and Test Failure Cases
In `test_ecdsa.py`:
```python
import base64, json

private_key, public_key = generate_signing_keypair()

dummy_packet = {
    "encrypted_data": "U2FtcGxlQmFzZTY0Q2lwaGVydGV4dA==",
    "device_id": "DEV-001",
    "timestamp": "2025-04-15T10:00:00Z",
    "nonce": "abc123xyz",
}

data_to_sign = fields_to_sign(dummy_packet)
sig = sign_data(data_to_sign, private_key)
sig_b64 = base64.b64encode(sig).decode()
print("Signature (Base64):", sig_b64)

# Valid signature
assert verify_signature(data_to_sign, sig, public_key) == True

# Wrong key → should fail
_, wrong_public_key = generate_signing_keypair()
assert verify_signature(data_to_sign, sig, wrong_public_key) == False

# Tampered data → should fail
tampered_data = fields_to_sign({**dummy_packet, "encrypted_data": "TAMPERED"})
assert verify_signature(tampered_data, sig, public_key) == False

print("All ECDSA tests passed.")
```

---

## Deliverables by End of Week 1
- [ ] `generate_signing_keypair()` working, returning P-256 key pairs.
- [ ] `sign_data()` and `verify_signature()` implemented.
- [ ] `fields_to_sign()` helper documented.
- [ ] Tests: valid signature passes, wrong key fails, tampered data fails.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 1–6** — coordinate with Student 4 on the packet structure and with Student 5 on canonical byte representation.

## Notes
Your `signature` field in the packet will be stored as Base64. In Week 2 you will wire this into the full packet and add receiver-side logic to capture the MQTT packet and route it to verification. Keep the `sign_data` / `verify_signature` API clean so Student 8 (device authentication) and Student 10 (final verifier) can call it easily.
