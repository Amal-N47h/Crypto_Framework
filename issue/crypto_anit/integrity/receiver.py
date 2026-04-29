# receiver.py
# Simulates the IoMT gateway receiving and verifying a packet.

import json
import copy
from packet_builder import verify_packet_integrity


def receive_and_verify(json_string: str, simulate_tamper: bool = False):
    print("\n" + "=" * 60)
    print("IoMT RECEIVER — Verifying packet integrity")
    print("=" * 60)

    # Step 1: Deserialise the JSON string (as received from MQTT)
    try:
        packet = json.loads(json_string)
    except json.JSONDecodeError as e:
        print(f"[RECEIVER] ERROR: Could not parse JSON — {e}")
        return

    print(f"\n[RECEIVER] Packet received from device: {packet.get('device_id')}")
    print(f"[RECEIVER] Timestamp                 : {packet.get('timestamp')}")
    print(f"[RECEIVER] Received hash_value        : {packet.get('hash_value', 'MISSING')}")

    # Step 2 (optional): Simulate an attacker modifying the packet in transit
    if simulate_tamper:
        print("\n[ATTACK SIMULATION] Tampering with heart_rate field...")
        packet["vitals"]["heart_rate"] = 999  # Attacker injects false data

    # Step 3: Verify integrity using SHA-256
    is_valid, message = verify_packet_integrity(packet)

    # Step 4: Report result
    print(f"\n[RECEIVER] Integrity check: {'PASS ✓' if is_valid else 'FAIL ✗'}")
    print(f"[RECEIVER] {message}")

    if is_valid:
        print("\n[RECEIVER] Packet accepted. Forwarding to:")
       
    else:
        print("\n[RECEIVER] Packet REJECTED. Logging tamper attempt.")
        


if __name__ == "__main__":
    from sender import send_packet

    print("\n--- TEST 1: Normal (untampered) packet ---")
    transmitted_json = send_packet()
    receive_and_verify(transmitted_json, simulate_tamper=False)

    print("\n\n--- TEST 2: Tampered packet (attacker modifies vitals) ---")
    transmitted_json = send_packet()
    receive_and_verify(transmitted_json, simulate_tamper=True)