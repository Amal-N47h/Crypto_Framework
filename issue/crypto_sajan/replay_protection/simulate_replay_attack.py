"""
simulate_replay_attack.py
=========================
Replay Attack Simulation Script
Author  : Sajan Baby P
Module  : Replay Protection — Attack Injection Tester

What this file does:
    Simulates three real-world replay attack scenarios against the
    IoMT pipeline and shows whether each attack is detected or not.

    This is the "Attack Injection Tester" integration responsibility —
    it proves the replay protection module works under actual attack
    conditions, not just unit test conditions.

Scenarios simulated:
    1. NORMAL — legitimate packet sent and received correctly
    2. REPLAY  — same packet resent immediately (duplicate nonce attack)
    3. EXPIRED — old packet replayed after 2+ minutes (expired timestamp)
    4. DUPLICATE NONCE — fresh timestamp but reused nonce (crafted attack)

Tasks covered:
    ✅ Attach timestamp + nonce to packets (sender)
    ✅ Detect replayed or expired packets (receiver)
    ✅ Script to simulate and identify replay attacks
"""

import json
import time
from datetime import datetime, timezone, timedelta

from replay_module import (
    generate_timestamp,
    generate_nonce,
    check_replay_protection,
    reset_nonce_store,
)
from sender import build_packet


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_header(title: str) -> None:
    print("\n" + "━" * 55)
    print(f"  {title}")
    print("━" * 55)


def print_packet(packet: dict) -> None:
    """Print only the replay-relevant fields of a packet."""
    print(f"  device_id  : {packet['device_id']}")
    print(f"  timestamp  : {packet['timestamp']}")
    print(f"  nonce      : {packet['nonce']}")


def print_result(label: str, result: bool, reason: str) -> None:
    """Print the receiver's decision on a packet."""
    status = "✅ ACCEPTED" if result else "🚨 REJECTED"
    print(f"\n  [{label}]")
    print(f"  Receiver decision : {status}")
    print(f"  Reason            : {reason}")


# ─────────────────────────────────────────────
# RECEIVER SIMULATION
# ─────────────────────────────────────────────

def receiver_process(packet: dict, label: str) -> tuple[bool, str]:
    """
    Simulates the gateway receiver processing an incoming packet.

    In the full system this is where all verification happens.
    For now it runs only the replay protection check — our module.

    Parameters
    ----------
    packet : dict
        Incoming packet to verify.
    label : str
        Description label for display purposes.

    Returns
    -------
    tuple[bool, str]
        Result and reason from check_replay_protection().
    """
    result, reason = check_replay_protection(packet)
    print_result(label, result, reason)
    return result, reason


# ─────────────────────────────────────────────
# ATTACK SCENARIOS
# ─────────────────────────────────────────────

def scenario_1_legitimate_packet():
    """
    SCENARIO 1 — Legitimate packet
    ───────────────────────────────
    A genuine IoMT device sends a fresh packet with a new timestamp
    and a new nonce. This should be accepted normally.

    Expected: ✅ ACCEPTED — OK
    """
    print_header("SCENARIO 1 — Legitimate Packet")
    print("\n  A genuine device sends a fresh packet.")

    # Build a real packet using the sender module.
    packet = build_packet(device_id="DEVICE_HEART_MONITOR_01")

    print("\n  Packet sent by device:")
    print_packet(packet)

    result, reason = receiver_process(packet, "Legitimate packet")

    assert result == True,  f"Scenario 1 failed: expected ACCEPTED, got {reason}"
    print("\n  ✔ Correct — legitimate packet was accepted.")
    return packet   # Return so scenario 2 can reuse this same packet.


def scenario_2_replay_attack(original_packet: dict):
    """
    SCENARIO 2 — Replay attack (duplicate nonce)
    ─────────────────────────────────────────────
    An attacker captures the legitimate packet from Scenario 1
    and immediately resends it. The timestamp is still fresh
    (within 60 seconds) so timestamp check alone won't catch it.
    The nonce check must catch it.

    This is the most dangerous replay — happens fast, looks valid.

    Expected: 🚨 REJECTED — DUPLICATE_NONCE
    """
    print_header("SCENARIO 2 — Replay Attack (Duplicate Nonce)")
    print("\n  Attacker captures the packet and resends it immediately.")
    print("  Timestamp is still fresh — only the nonce check saves us.")

    print("\n  Replayed packet (identical to original):")
    print_packet(original_packet)

    result, reason = receiver_process(original_packet, "Replayed packet")

    assert result == False,              f"Scenario 2 failed: expected REJECTED"
    assert reason == "DUPLICATE_NONCE",  f"Scenario 2 failed: expected DUPLICATE_NONCE, got {reason}"
    print("\n  ✔ Correct — replay attack detected via duplicate nonce.")


def scenario_3_expired_timestamp():
    """
    SCENARIO 3 — Expired timestamp attack
    ──────────────────────────────────────
    An attacker captured a packet 2 minutes ago and is now
    replaying it. Maybe the nonce store was cleared (server restart)
    so the nonce check might not catch it. But the timestamp will.

    Expected: 🚨 REJECTED — EXPIRED_TIMESTAMP
    """
    print_header("SCENARIO 3 — Expired Timestamp Attack")
    print("\n  Attacker replays a packet captured 2 minutes ago.")
    print("  Even if nonce store was wiped, timestamp check catches it.")

    # Build a packet but manually set the timestamp to 2 minutes ago.
    # This simulates a packet that was captured earlier and replayed now.
    old_time = datetime.now(timezone.utc) - timedelta(seconds=120)
    old_timestamp = old_time.isoformat()

    packet = build_packet(device_id="DEVICE_HEART_MONITOR_01")
    packet["timestamp"] = old_timestamp   # Inject old timestamp.

    print("\n  Packet with old timestamp:")
    print_packet(packet)
    print(f"\n  Packet age : ~120 seconds (limit is 60 seconds)")

    result, reason = receiver_process(packet, "Expired timestamp packet")

    assert result == False,                  f"Scenario 3 failed: expected REJECTED"
    assert reason == "EXPIRED_TIMESTAMP",    f"Scenario 3 failed: expected EXPIRED_TIMESTAMP, got {reason}"
    print("\n  ✔ Correct — expired timestamp attack detected.")


def scenario_4_crafted_duplicate_nonce():
    """
    SCENARIO 4 — Crafted duplicate nonce attack
    ─────────────────────────────────────────────
    A sophisticated attacker creates a brand-new packet with a
    fresh timestamp BUT reuses a nonce from a previously seen packet.
    This tests whether the nonce store correctly remembers past nonces
    even when the timestamp is completely valid.

    Expected: 🚨 REJECTED — DUPLICATE_NONCE
    """
    print_header("SCENARIO 4 — Crafted Duplicate Nonce Attack")
    print("\n  Attacker builds a fresh packet but reuses a known nonce.")
    print("  Timestamp is valid — only nonce tracking catches this.")

    # First send a legitimate packet and record its nonce.
    legitimate = build_packet(device_id="DEVICE_TEMP_SENSOR_02")
    stolen_nonce = legitimate["nonce"]

    # Process it so the nonce gets stored.
    check_replay_protection(legitimate)
    print(f"\n  Legitimate packet processed. Nonce stored: {stolen_nonce[:18]}...")

    # Now build a fresh packet but inject the stolen nonce.
    crafted = build_packet(device_id="DEVICE_TEMP_SENSOR_02")
    crafted["nonce"] = stolen_nonce   # Inject the reused nonce.

    print("\n  Crafted packet with reused nonce:")
    print_packet(crafted)

    result, reason = receiver_process(crafted, "Crafted duplicate nonce packet")

    assert result == False,              f"Scenario 4 failed: expected REJECTED"
    assert reason == "DUPLICATE_NONCE",  f"Scenario 4 failed: expected DUPLICATE_NONCE, got {reason}"
    print("\n  ✔ Correct — crafted duplicate nonce attack detected.")


# ─────────────────────────────────────────────
# SUMMARY REPORT
# ─────────────────────────────────────────────

def print_summary(results: list) -> None:
    print_header("SIMULATION SUMMARY")
    print()
    print(f"  {'Scenario':<45} {'Result'}")
    print(f"  {'-'*44} {'-'*10}")
    for label, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {label:<45} {status}")
    print()
    total  = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"  {passed}/{total} scenarios passed.")
    print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  IoMT Replay Attack Simulation")
    print("  Author : Sajan Baby P")
    print("  Module : Replay Protection — Attack Injection Tester")
    print("=" * 55)

    # Fresh nonce store before simulation starts.
    reset_nonce_store()

    results = []

    # ── Scenario 1 ──────────────────────────────
    try:
        original = scenario_1_legitimate_packet()
        results.append(("Scenario 1 — Legitimate packet accepted", True))
    except AssertionError as e:
        print(f"\n  ❌ {e}")
        results.append(("Scenario 1 — Legitimate packet accepted", False))
        original = build_packet("FALLBACK")   # Fallback so scenario 2 can still run.

    # ── Scenario 2 ──────────────────────────────
    try:
        scenario_2_replay_attack(original)
        results.append(("Scenario 2 — Replay (duplicate nonce) rejected", True))
    except AssertionError as e:
        print(f"\n  ❌ {e}")
        results.append(("Scenario 2 — Replay (duplicate nonce) rejected", False))

    # ── Scenario 3 ──────────────────────────────
    try:
        scenario_3_expired_timestamp()
        results.append(("Scenario 3 — Expired timestamp rejected", True))
    except AssertionError as e:
        print(f"\n  ❌ {e}")
        results.append(("Scenario 3 — Expired timestamp rejected", False))

    # ── Scenario 4 ──────────────────────────────
    try:
        scenario_4_crafted_duplicate_nonce()
        results.append(("Scenario 4 — Crafted duplicate nonce rejected", True))
    except AssertionError as e:
        print(f"\n  ❌ {e}")
        results.append(("Scenario 4 — Crafted duplicate nonce rejected", False))

    # ── Summary ─────────────────────────────────
    print_summary(results)
