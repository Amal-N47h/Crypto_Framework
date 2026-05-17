"""
attack_simulation.py
====================
Simulates three attack scenarios against the receiver.
Author: Sajan Baby P

Scenarios:
    1. Valid packet          — should PASS
    2. Timestamp attack      — old timestamp injected — should FAIL
    3. Nonce attack          — same nonce reused — should FAIL
"""

import uuid
from datetime import datetime, timezone, timedelta
import receiver
from receiver import check_packet


# ── HELPER: print result nicely ────────────────────────
def show_result(scenario, result, reason):
    status = "✅ PASSED" if result else "🚨 " + reason
    print(f"\n  {scenario}")
    print(f"  Result : {status}")


# ── RESET: clear the receiver's nonce store ────────────
def reset():
    # receiver.seen_nonces is the actual live set inside receiver.py
    # calling .clear() on it empties it properly
    receiver.seen_nonces.clear()


# ══════════════════════════════════════════════════════
# SCENARIO 1 — Valid Packet
# A genuine device sends a fresh packet.
# Timestamp is current. Nonce is brand new.
# Expected: PASSED
# ══════════════════════════════════════════════════════
def scenario_1_valid_packet():

    # Build a normal fresh packet.
    packet = {
        "device_id": "DEVICE_001",
        "timestamp": datetime.now(timezone.utc).isoformat(),  # current time
        "nonce":     str(uuid.uuid4()),                        # new unique ID
        "data":      "heart_rate=82"
    }

    print("\n  Packet details:")
    print(f"    timestamp : {packet['timestamp']}")
    print(f"    nonce     : {packet['nonce']}")

    result, reason = check_packet(packet)
    show_result("Scenario 1 — Valid Packet", result, reason)
    return packet   # return so scenario 3 can reuse this nonce


# ══════════════════════════════════════════════════════
# SCENARIO 2 — Timestamp Attack
# Attacker replays a packet that is 2 minutes old.
# The timestamp is expired so it must be rejected.
# Expected: FAILED — EXPIRED TIMESTAMP
# ══════════════════════════════════════════════════════
def scenario_2_timestamp_attack():
    # No reset here — scenario 1's nonce must stay stored for scenario 3.

    # Manually create a timestamp from 2 minutes ago.
    # timedelta(seconds=120) = 2 minutes duration
    # Subtracting it from now gives a time 2 minutes in the past.
    old_time = datetime.now(timezone.utc) - timedelta(seconds=120)

    packet = {
        "device_id": "DEVICE_001",
        "timestamp": old_time.isoformat(),    # old timestamp — 2 mins ago
        "nonce":     str(uuid.uuid4()),        # fresh nonce (doesn't matter)
        "data":      "heart_rate=82"
    }

    print("\n  Packet details:")
    print(f"    timestamp : {packet['timestamp']}  ← 2 minutes old")
    print(f"    nonce     : {packet['nonce']}")

    result, reason = check_packet(packet)
    show_result("Scenario 2 — Timestamp Attack", result, reason)


# ══════════════════════════════════════════════════════
# SCENARIO 3 — Nonce Attack (Replay)
# Attacker captures a valid packet and resends it.
# Timestamp is still fresh but nonce is already seen.
# Expected: FAILED — DUPLICATE NONCE
# ══════════════════════════════════════════════════════
def scenario_3_nonce_attack(original_packet):
    # Do NOT reset here — we need the nonce from scenario 1 to still be stored.

    print("\n  Attacker resends the exact same packet from Scenario 1.")
    print(f"    timestamp : {original_packet['timestamp']}  ← still fresh")
    print(f"    nonce     : {original_packet['nonce']}  ← already seen")

    result, reason = check_packet(original_packet)
    show_result("Scenario 3 — Nonce Attack (Replay)", result, reason)


# ── MAIN ───────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  IoMT Replay Attack Simulation")
    print("  Author: Sajan Baby P")
    print("=" * 50)

    # Clear nonce store once at the start.
    reset()

    # Run all three scenarios.
    original = scenario_1_valid_packet()
    scenario_2_timestamp_attack()
    scenario_3_nonce_attack(original)

    print("\n" + "=" * 50)
    print("  Simulation complete.")
    print("=" * 50)
