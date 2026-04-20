"""
sha256_module.py
----------------
SHA-256 Integrity Module for Secure IoMT Packet Transmission.

Responsibilities:
  - compute_hash  : Generate a SHA-256 hex digest from raw bytes.
  - verify_hash   : Timing-safe comparison of a computed hash vs an expected hash.
  - fields_to_hash: Serialise selected packet fields into canonical JSON bytes
                    ready for hashing.

Author : Anit Benny
Module : SHA-256 Integrity (Project 5 — Week 1)
Libraries: hashlib, hmac, json  (all built-in — no third-party dependencies)
"""

import hashlib
import hmac
import json


# ---------------------------------------------------------------------------
# Fields that will be integrity-protected in the final shared packet.
# Agreed with Student 4 (Packet Builder): hash covers the payload-critical
# fields — anything that must NOT be modified in transit.
# Signature and hmac_value are excluded because they are computed separately
# and added after the hash is generated.
# ---------------------------------------------------------------------------
FIELDS_TO_PROTECT = [
    "device_id",
    "timestamp",
    "nonce",
    "encrypted_data",
    "encrypted_key",
]


def compute_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of the given bytes.

    Parameters
    ----------
    data : bytes
        The raw bytes to hash (typically the output of fields_to_hash()).

    Returns
    -------
    str
        A 64-character lowercase hexadecimal digest string.
        This value becomes the `hash_value` field in the packet.

    Example
    -------
    >>> compute_hash(b"hello")
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    return hashlib.sha256(data).hexdigest()


def verify_hash(data: bytes, expected_hash: str) -> bool:
    """
    Verify the SHA-256 hash of `data` against `expected_hash`.

    Uses hmac.compare_digest() instead of a plain == comparison to prevent
    timing attacks — an attacker cannot infer how many characters matched
    by measuring how long the comparison took.

    Parameters
    ----------
    data          : bytes  — The packet bytes to re-hash.
    expected_hash : str    — The hash_value field received with the packet.

    Returns
    -------
    bool
        True  → data is intact (hashes match).
        False → data has been tampered with (hashes differ).
    """
    actual_hash = compute_hash(data)
    # hmac.compare_digest requires both arguments to be the same type.
    return hmac.compare_digest(actual_hash, expected_hash)


def fields_to_hash(packet: dict) -> bytes:
    """
    Serialise the integrity-protected fields of a packet into canonical
    JSON bytes suitable for hashing.

    Canonical rules (ensures identical bytes on sender and receiver):
      1. Only the fields listed in FIELDS_TO_PROTECT are included.
      2. Keys are sorted alphabetically.
      3. No extra whitespace (separators=(',', ':')).
      4. Encoded to UTF-8 bytes.

    Parameters
    ----------
    packet : dict
        The full packet dictionary (may contain extra fields like
        hash_value, hmac_value, signature — these are intentionally skipped).

    Returns
    -------
    bytes
        The deterministic byte string to feed into compute_hash().

    Raises
    ------
    KeyError
        If a required field from FIELDS_TO_PROTECT is missing in `packet`.
    """
    # Extract only the fields that must be integrity-protected.
    protected = {field: packet[field] for field in FIELDS_TO_PROTECT}

    # Serialise: sorted keys + no whitespace = canonical form
    canonical_json = json.dumps(protected, sort_keys=True, separators=(",", ":"))

    return canonical_json.encode("utf-8")
