# Unified Packet Format for IoMT Crypto Framework

This document defines the unified JSON packet format expected by the verification dashboard and pipeline.

## Packet Structure

```
{
  "device_id": "IOMT-DEV-001",
  "timestamp": "2026-05-05T12:34:56Z",
  "nonce": "randomstring",
  "encrypted_data": "<base64 string>",
  "ephemeral_public_key": "<PEM or base64>",
  "hash_value": "<sha256 hash>",
  "hmac_value": "<hmac, optional>",
  "signature": "<ecdsa signature>",
  "packet_id": "<uuid, optional>"
}
```

- `device_id`: Unique device identifier (must start with IOMT)
- `timestamp`: ISO8601 UTC timestamp
- `nonce`: Unique random string for replay protection
- `encrypted_data`: AES/ECC/Hybrid encrypted payload (base64)
- `ephemeral_public_key`: Sender's ephemeral ECC public key (base64 or PEM)
- `hash_value`: SHA-256 hash of the canonical packet (excluding hash_value)
- `hmac_value`: HMAC for integrity (optional)
- `signature`: ECDSA signature of the packet (base64)
- `packet_id`: Unique packet identifier (assigned by dashboard, optional)

## Notes
- All fields are required unless marked optional.
- The dashboard and verifier will expect this format for all incoming packets.
- Update this document if the format changes.
