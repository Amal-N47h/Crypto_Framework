"""
test_sha256.py
--------------
Test suite for the SHA-256 Integrity Module.

Tests:
  1. Hash generation         — compute_hash() produces a valid 64-char hex string.
  2. Intact packet           — verify_hash() returns True for an unmodified packet.
  3. Tamper detection        — verify_hash() returns False after modifying encrypted_data.
  4. Canonical serialisation — fields_to_hash() is deterministic (same input → same bytes).
  5. Field exclusion         — hash_value / hmac_value / signature are NOT part of the hash.

Author : Anit Benny
Module : SHA-256 Integrity (Project 5 — Week 1)
"""

import sys
import os

# Allow running the test directly from any working directory.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from crypto_framework.integrity.sha256_module import (
    compute_hash,
    verify_hash,
    fields_to_hash,
    FIELDS_TO_PROTECT,
)


# ---------------------------------------------------------------------------
# Dummy packet — mirrors the agreed common packet structure.
# encrypted_data and encrypted_key would normally come from Students 1–3;
# we use placeholder base64-like strings for Week 1 testing.
# ---------------------------------------------------------------------------
DUMMY_PACKET = {
    "device_id":      "IoMT-SENSOR-001",
    "timestamp":      "2026-04-20T10:30:00Z",
    "nonce":          "a3f8c21d9e74b056",
    "encrypted_data": "U2FsdGVkX1+ABC123encryptedPayloadXYZ==",
    "encrypted_key":  "encryptedAESkey+base64==",
    # These fields are added AFTER hashing — intentionally excluded from hash input.
    "hash_value":     "",   # will be filled in
    "hmac_value":     "",   # added by Student 2
    "signature":      "",   # added by Student 3
}


# ──────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────

def run_test(name: str, result: bool) -> None:
    """Print a formatted PASS / FAIL line and raise on failure."""
    status = "PASS" if result else "FAIL"
    symbol = "✓" if result else "✗"
    print(f"  [{status}] {symbol}  {name}")
    if not result:
        raise AssertionError(f"Test failed: {name}")


# ──────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────

def test_hash_format():
    """compute_hash() must return a 64-character lowercase hex string."""
    sample_data = b"test_data_for_format_check"
    digest = compute_hash(sample_data)
    run_test(
        "Hash is a 64-character hex string",
        len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
    )


def test_intact_packet():
    """
    Scenario: Sender computes hash, receiver re-computes and verifies.
    Expected : verify_hash() → True  (no tampering occurred).
    """
    packet = dict(DUMMY_PACKET)  # work on a copy

    # Step 1 — Sender side: serialise protected fields and compute hash.
    protected_bytes = fields_to_hash(packet)
    packet["hash_value"] = compute_hash(protected_bytes)

    print(f"\n  Generated hash_value : {packet['hash_value']}")

    # Step 2 — Receiver side: re-serialise and verify.
    received_bytes = fields_to_hash(packet)
    result = verify_hash(received_bytes, packet["hash_value"])

    run_test("Intact packet verifies correctly (True)", result is True)


def test_tampered_packet():
    """
    Scenario: Attacker modifies encrypted_data after hash was computed.
    Expected : verify_hash() → False  (tampering detected).
    """
    packet = dict(DUMMY_PACKET)

    # Sender computes and embeds hash.
    packet["hash_value"] = compute_hash(fields_to_hash(packet))

    # ── TAMPER ──────────────────────────────────────────────────────────
    original_data = packet["encrypted_data"]
    packet["encrypted_data"] = "TAMPERED_MALICIOUS_PAYLOAD_9999!!"
    print(f"\n  Original encrypted_data : {original_data}")
    print(f"  Tampered encrypted_data : {packet['encrypted_data']}")
    # ────────────────────────────────────────────────────────────────────

    # Receiver re-computes hash on the (now tampered) data.
    received_bytes = fields_to_hash(packet)
    result = verify_hash(received_bytes, packet["hash_value"])

    run_test("Tampered packet detected correctly (False)", result is False)


def test_canonical_serialisation():
    """
    fields_to_hash() must be deterministic: calling it twice on the same
    packet must return identical bytes (order-independent).
    """
    packet = dict(DUMMY_PACKET)
    bytes_1 = fields_to_hash(packet)
    bytes_2 = fields_to_hash(packet)
    run_test("Canonical serialisation is deterministic", bytes_1 == bytes_2)


def test_excluded_fields_do_not_affect_hash():
    """
    Changing hash_value / hmac_value / signature must NOT change the hash
    input, because those fields are excluded from FIELDS_TO_PROTECT.
    """
    packet_a = dict(DUMMY_PACKET)
    packet_b = dict(DUMMY_PACKET)

    # Mutate fields that should be excluded.
    packet_b["hash_value"]  = "some_previously_computed_hash"
    packet_b["hmac_value"]  = "some_hmac"
    packet_b["signature"]   = "some_signature"

    run_test(
        "Excluded fields (hash_value, hmac_value, signature) do not affect hash input",
        fields_to_hash(packet_a) == fields_to_hash(packet_b),
    )


def test_protected_fields_list():
    """Sanity check — FIELDS_TO_PROTECT contains the expected field names."""
    expected = {"device_id", "timestamp", "nonce", "encrypted_data", "encrypted_key"}
    run_test(
        "FIELDS_TO_PROTECT contains all required packet fields",
        set(FIELDS_TO_PROTECT) == expected,
    )


# ──────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────

def main():
    tests = [
        test_hash_format,
        test_intact_packet,
        test_tampered_packet,
        test_canonical_serialisation,
        test_excluded_fields_do_not_affect_hash,
        test_protected_fields_list,
    ]

    print("=" * 60)
    print(" SHA-256 Integrity Module — Test Suite")
    print(" Anit Benny | Project 5 — IoMT Secure Transmission")
    print("=" * 60)

    passed = 0
    failed = 0

    for test_fn in tests:
        print(f"\n[TEST] {test_fn.__name__}")
        try:
            test_fn()
            passed += 1
        except AssertionError as err:
            print(f"       {err}")
            failed += 1

    print("\n" + "=" * 60)
    print(f" Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)

    if failed:
        sys.exit(1)   # non-zero exit for CI pipelines


if __name__ == "__main__":
    main()
