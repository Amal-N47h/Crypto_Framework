"""
test_replay.py
==============
Tests for the Replay Protection Module


Run with:
    python test_replay.py

What we test:
    1. A fresh, valid packet passes both checks.
    2. Replaying the same packet fails with DUPLICATE_NONCE.
    3. A packet with an old timestamp fails with EXPIRED_TIMESTAMP.
"""

# We import datetime tools to manually craft old timestamps for testing.
from datetime import datetime, timezone, timedelta

# We import our own module. The dot (.) means "from the same folder".
from replay_module import (
    generate_timestamp,
    generate_nonce,
    check_replay_protection,
    reset_nonce_store,
)


# ─────────────────────────────────────────────
# HELPER: build a packet easily in tests
# ─────────────────────────────────────────────

def make_packet(timestamp: str = None, nonce: str = None) -> dict:
    """
    Build a minimal test packet.
    If timestamp or nonce are not given, generate fresh ones.
    Other team members' fields (encrypted_data, hmac, etc.) are
    not needed here — we only test the replay-protection fields.
    """
    return {
        "device_id": "TEST_DEVICE_001",
        "timestamp": timestamp if timestamp is not None else generate_timestamp(),
        "nonce":     nonce     if nonce     is not None else generate_nonce(),
        "encrypted_data": "dummy_ciphertext",   # placeholder for integration
    }


# ─────────────────────────────────────────────
# TEST FUNCTIONS
# ─────────────────────────────────────────────

def test_fresh_packet_passes():
    """
    TEST 1 — A brand-new packet with a current timestamp and a new nonce
    should pass replay protection.

    Expected result: (True, "OK")
    """
    # Always start each test with a clean nonce store so tests don't
    # interfere with each other.
    reset_nonce_store()

    # Build a completely fresh packet.
    packet = make_packet()

    # Run the combined check.
    result, reason = check_replay_protection(packet)

    # Assert — if this fails, Python prints what we expected vs what we got.
    assert result == True,  f"Expected True  but got {result}"
    assert reason == "OK",  f"Expected 'OK' but got '{reason}'"

    print("✅ TEST 1 PASSED — Fresh packet accepted correctly.")


def test_replayed_packet_fails_with_duplicate_nonce():
    """
    TEST 2 — If the exact same packet is submitted twice (a replay attack),
    the second submission must be rejected with DUPLICATE_NONCE.

    Why this matters:
        An attacker captures a valid packet and resends it immediately.
        The timestamp is still fresh, so timestamp-check alone won't catch it.
        The nonce check is what saves us here.

    Expected result of 2nd call: (False, "DUPLICATE_NONCE")
    """
    reset_nonce_store()

    # Create one packet. Both calls below use the SAME packet object,
    # meaning the same timestamp AND the same nonce.
    packet = make_packet()

    # First submission — should succeed.
    result1, reason1 = check_replay_protection(packet)
    assert result1 == True,  f"First call should pass. Got: {result1}, {reason1}"
    assert reason1 == "OK",  f"First call should return OK. Got: {reason1}"

    # Second submission of the SAME packet — replay attack.
    result2, reason2 = check_replay_protection(packet)
    assert result2 == False,               f"Expected False but got {result2}"
    assert reason2 == "DUPLICATE_NONCE",   f"Expected 'DUPLICATE_NONCE' but got '{reason2}'"

    print("✅ TEST 2 PASSED — Replayed packet (duplicate nonce) rejected correctly.")


def test_old_timestamp_fails_with_expired_timestamp():
    """
    TEST 3 — A packet with a timestamp older than 60 seconds must be
    rejected with EXPIRED_TIMESTAMP, even if the nonce is new.

    Why this matters:
        An attacker captures a packet and replays it 2 minutes later.
        The nonce might not be in our store (if the server restarted),
        but the timestamp check catches it.

    Expected result: (False, "EXPIRED_TIMESTAMP")
    """
    reset_nonce_store()

    # Manually craft a timestamp that is 120 seconds in the past.
    # timedelta(seconds=120) represents a duration of 2 minutes.
    # Subtracting it from now() gives us a time 2 minutes ago.
    old_time = datetime.now(timezone.utc) - timedelta(seconds=120)

    # .isoformat() converts the datetime object back into the string format
    # our module expects.
    old_timestamp_str = old_time.isoformat()

    # Build a packet with the old timestamp but a brand-new nonce.
    packet = make_packet(timestamp=old_timestamp_str)

    # Run the check.
    result, reason = check_replay_protection(packet)

    assert result == False,                   f"Expected False but got {result}"
    assert reason == "EXPIRED_TIMESTAMP",     f"Expected 'EXPIRED_TIMESTAMP' but got '{reason}'"

    print("✅ TEST 3 PASSED — Expired timestamp rejected correctly.")


# ─────────────────────────────────────────────
# BONUS TEST — future timestamp rejected too
# ─────────────────────────────────────────────

def test_future_timestamp_rejected():
    """
    BONUS TEST — A packet claiming to be from the future is also rejected.
    This can happen if a device has a misconfigured clock or an attacker
    tries to pre-generate packets.

    Expected result: (False, "EXPIRED_TIMESTAMP")
    """
    reset_nonce_store()

    future_time = datetime.now(timezone.utc) + timedelta(seconds=300)
    future_timestamp_str = future_time.isoformat()

    packet = make_packet(timestamp=future_timestamp_str)
    result, reason = check_replay_protection(packet)

    assert result == False,                 f"Expected False but got {result}"
    assert reason == "EXPIRED_TIMESTAMP",   f"Expected 'EXPIRED_TIMESTAMP' but got '{reason}'"

    print("✅ BONUS TEST PASSED — Future timestamp rejected correctly.")


# ─────────────────────────────────────────────
# RUN ALL TESTS
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Replay Protection Module — Test Suite")
    print("  Author: Sajan Baby P")
    print("="*55 + "\n")

    test_fresh_packet_passes()
    test_replayed_packet_fails_with_duplicate_nonce()
    test_old_timestamp_fails_with_expired_timestamp()
    test_future_timestamp_rejected()

    print("\n" + "="*55)
    print("  All tests passed. Module is ready for integration.")
    print("="*55 + "\n")
