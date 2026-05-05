# AES-CBC vs AES-GCM Evaluation for IoMT

## Objective
To evaluate AES-CBC and AES-GCM encryption modes based on security, performance, overhead, and suitability for IoMT (Internet of Medical Things).

---

## Overview

### AES-CBC (Cipher Block Chaining)
- Encrypts data block by block
- Requires padding
- Provides only confidentiality
- Needs additional mechanisms (like HMAC) for integrity

### AES-GCM (Galois/Counter Mode)
- Uses counter-based encryption
- No padding required
- Provides confidentiality + integrity + authentication
- Includes an authentication tag for verification

---

## Evaluation

### 1. Security
- AES-CBC:
  - Ensures confidentiality only
  - Vulnerable to padding attacks
  - Requires extra protection for integrity

- AES-GCM:
  - Ensures confidentiality, integrity, and authentication
  - Detects tampering automatically
  - More secure for sensitive data

**Result:** AES-GCM is more secure

---

### 2. Performance
- AES-CBC:
  - Slower due to sequential processing
  - Higher latency

- AES-GCM:
  - Faster due to parallel processing
  - Lower latency

**Result:** AES-GCM performs better

---

### 3. Overhead
- AES-CBC:
  - Requires padding
  - Needs additional integrity mechanisms (HMAC)
  - Higher implementation complexity

- AES-GCM:
  - No padding required
  - Built-in authentication
  - Simpler implementation

**Result:** AES-GCM has lower overhead

---

### 4. Suitability for IoMT
IoMT devices require:
- Low power consumption
- Fast processing
- Strong security

- AES-CBC:
  - Less efficient for real-time systems
  - Requires extra computation

- AES-GCM:
  - Efficient and lightweight
  - Suitable for real-time secure communication

**Result:** AES-GCM is better suited for IoMT

---

## Conclusion

AES-GCM is the better encryption mode compared to AES-CBC because it:
- Provides combined encryption and authentication
- Offers better performance and efficiency
- Reduces implementation complexity
- Ensures strong protection for sensitive medical data

---

## Final Recommendation

AES-GCM should be used for IoMT systems such as:
- Wearable health devices
- Remote patient monitoring systems
- Smart medical sensors

**Final Statement:**  
AES-GCM is the optimal encryption mode for IoMT environments due to its superior security, efficiency, and performance.
