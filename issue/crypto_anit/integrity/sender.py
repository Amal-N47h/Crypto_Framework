# sender.py
# Simulates the IoMT device building and transmitting a secure packet.

import json
import secrets
from packet_builder import build_final_packet


def simulate_sensor_reading():
    """Simulate realistic patient vitals from an IoMT sensor."""
    return {
        "heart_rate": 82,
        "spo2": 97,
        "temperature": 36.7,
        "blood_pressure": "120/80"
    }


def create_nonce():
    """
    Generate a cryptographically random nonce (16 hex characters = 64 bits).
    Used by the replay protection module (Sajan) to detect duplicate packets.
    """
    return secrets.token_hex(8)  # 8 bytes = 16 hex chars


def send_packet():
    print("=" * 60)
    print("IoMT SENDER — Building secure packet")
    print("=" * 60)

    # Device identity
    device_id = "IOMT-DEV-00423"
    patient_id = "PAT-9981"
    nonce = create_nonce()
    vitals = simulate_sensor_reading()

    print(f"\n[SENDER] Device     : {device_id}")
    print(f"[SENDER] Patient    : {patient_id}")
    print(f"[SENDER] Nonce      : {nonce}")
    print(f"[SENDER] Vitals     : {vitals}")

    # Build the packet with SHA-256 hash embedded
    packet = build_final_packet(device_id, patient_id, nonce, vitals)

    print(f"\n[SENDER] hash_value : {packet['hash_value']}")
    print("\n[SENDER] Final packet (JSON to be sent via MQTT):")
    print(json.dumps(packet, indent=2))

    # In the real pipeline, this JSON string goes to MQTT publisher (Fuad's module)
    # For testing, we return it as a string simulating transmission
    return json.dumps(packet)


if __name__ == "__main__":
    transmitted = send_packet()
    print("\n[SENDER] Packet serialised and ready for MQTT transmission.")