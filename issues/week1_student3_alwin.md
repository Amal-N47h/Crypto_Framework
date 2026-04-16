---
title: "[Week 1] Alwin T Varghese – ECC Key Exchange: Generate ECC Key Pairs & Sample Exchange"
assignee: ""
labels: ["Week 1", "ECC", "key-exchange"]
---

## Assigned To
**Alwin T Varghese** — Student 3

## Module
**ECC Key Exchange** | Integration Role: *Encryption Chain Integrator*

## Week 1 Goal (Apr 13–19)
> Generate ECC public/private key pairs and demonstrate a basic key exchange so the sender and receiver can arrive at the same shared secret.

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
  └── ecc/
      ├── ecc_keygen.py
      ├── ecc_exchange.py
      └── test_ecc.py
  ```

### 2. ECC Key Pair Generation
In `ecc_keygen.py`, implement:
```python
def generate_ecc_keypair():
    """
    Returns (private_key, public_key) using NIST P-256 curve.
    Keys should be serializable to PEM format.
    """
```
- Use the **NIST P-256** (secp256r1) curve — it is well-supported and appropriate for IoMT.
- Add helper functions to serialize keys to PEM bytes and deserialize them back:
  ```python
  def private_key_to_pem(private_key) -> bytes
  def public_key_to_pem(public_key) -> bytes
  def pem_to_public_key(pem: bytes)
  ```

### 3. Simulate a Key Exchange (ECDH)
In `ecc_exchange.py`, implement:
```python
def derive_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Performs ECDH key agreement and returns a 32-byte shared secret
    derived via HKDF-SHA256.
    """
```
- Use **ECDH** (Elliptic Curve Diffie-Hellman) for the exchange.
- Apply **HKDF** (with SHA-256) to the raw shared secret to produce a proper 32-byte AES key.

### 4. Test the Full Exchange in `test_ecc.py`
Simulate sender (device) and receiver (gateway):
```python
# Device side
device_private, device_public = generate_ecc_keypair()

# Gateway side
gateway_private, gateway_public = generate_ecc_keypair()

# Both derive the same shared secret
secret_device   = derive_shared_secret(device_private, gateway_public)
secret_gateway  = derive_shared_secret(gateway_private, device_public)

assert secret_device == secret_gateway, "Shared secrets must match!"
print("ECC key exchange successful. Shared AES key:", secret_device.hex())
```

### 5. Read Ahead on AES Integration
- Review Student 1's `encrypted_data` format documentation.
- In Week 2 you will use the 32-byte shared secret as the AES-256 key for encryption.
- Note any questions about the AES interface and raise them early.

---

## Deliverables by End of Week 1
- [ ] `generate_ecc_keypair()` working and returning serializable P-256 key pairs.
- [ ] `derive_shared_secret()` using ECDH + HKDF to produce a 32-byte key.
- [ ] `test_ecc.py` proving `secret_device == secret_gateway`.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Student 1 (Adithyan)** — review AES key format so your shared secret output matches the expected AES key input.
- **Student 2 (Akhilamshah)** — after Week 2 mode comparison, you'll use the recommended AES mode together with your shared secret.

## Notes
The shared secret you produce becomes the AES session key. The security of the whole encryption pipeline depends on this step being correct. Make sure the HKDF step uses a fixed `info` label (e.g., `b"iomt-aes-key"`) so both sides derive identical keys.
