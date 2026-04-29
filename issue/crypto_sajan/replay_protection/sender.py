"""
sender.py
=========
IoMT Device - Sender Side
Author  : Sajan Baby P
Module  : Replay Protection (Week 1 - Task 1)

What this file does:
    Simulates an IoMT medical device (like a heart rate monitor) building
    a packet and attaching timestamp + nonce before sending it.

    In the full integrated system:
        - encrypted_data  comes from Adithyan's AES module
        - encrypted_key   comes from Alwin's ECC module
        - hash_value      comes from Anit's SHA-256 module
        - hmac_value      comes from Fuad's HMAC module
        - signature       comes from John's ECDSA module

    For now, those fields use placeholder strings so this module can
    be developed and tested independently.

Task covered:
    ✅ Attach timestamp + nonce to packets (sender side)
"""

import json
from datetime import datetime, timezone
from replay_module import generate_timestamp, generate_nonce


# ─────────────────────────────────────────────
# SIMULATED PATIENT DATA
# ─────────────────────────────────────────────

def get_patient_data() -> dict:
    """
    Simulate a medical device reading patient vitals.

    In a real system this would read from actual sensors.
    Here we return hardcoded sample values.

    Returns
    -------
    dict
        Raw patient vitals before any cryptographic processing.
    """
    return {
        "heart_rate":     82,
        "temperature":    37.1,
        "blood_pressure": "120/80",
        "spo2":           98,
    }


# ─────────────────────────────────────────────
# PACKET BUILDER
# ─────────────────────────────────────────────

def build_packet(device_id: str) -> dict:
    """
    Build a complete IoMT packet with all required fields.

    This is the core sender-side function. It:
        1. Reads patient vitals
        2. Attaches a fresh timestamp (YOUR TASK)
        3. Attaches a fresh nonce    (YOUR TASK)
        4. Fills in placeholder values for other teammates' fields

    Parameters
    ----------
    device_id : str
        Unique identifier of the sending device.
        Example: "DEVICE_HEART_MONITOR_01"

    Returns
    -------
    dict
        Complete packet ready for transmission via MQTT.

    Packet fields (agreed by the full team):
        device_id      → who sent this packet
        timestamp      → when it was created (UTC, ISO 8601)    ← YOUR FIELD
        nonce          → unique one-time ID                      ← YOUR FIELD
        encrypted_data → AES-encrypted patient vitals (Adithyan)
        encrypted_key  → ECC-protected AES key (Alwin)
        hash_value     → SHA-256 hash for tamper detection (Anit)
        hmac_value     → HMAC for integrity verification (Fuad)
        signature      → ECDSA digital signature (John)
    """

    # Step 1: Get raw patient vitals from the simulated sensor.
    raw_data = get_patient_data()

    # Step 2: Attach timestamp — current UTC time in ISO 8601.
    # This is what the receiver uses to check if the packet is too old.
    timestamp = generate_timestamp()

    # Step 3: Attach nonce — a random unique ID for this specific packet.
    # No two packets should ever share a nonce.
    nonce = generate_nonce()

    # Step 4: Build the full packet with all team-agreed fields.
    # Placeholder strings mark where other modules will plug in later.
    packet = {
        "device_id":      device_id,
        "timestamp":      timestamp,          # ← YOUR CONTRIBUTION
        "nonce":          nonce,              # ← YOUR CONTRIBUTION
        "encrypted_data": "PLACEHOLDER_AES_ENCRYPTED_DATA",   # Adithyan
        "encrypted_key":  "PLACEHOLDER_ECC_ENCRYPTED_KEY",    # Alwin
        "hash_value":     "PLACEHOLDER_SHA256_HASH",           # Anit
        "hmac_value":     "PLACEHOLDER_HMAC_VALUE",            # Fuad
        "signature":      "PLACEHOLDER_ECDSA_SIGNATURE",       # John
    }

    return packet


def packet_to_json(packet: dict) -> str:
    """
    Convert a packet dictionary to a JSON string for transmission.

    MQTT sends data as bytes/strings, not Python dictionaries.
    JSON is the standard format for structured data over the wire.

    Parameters
    ----------
    packet : dict
        The packet built by build_packet().

    Returns
    -------
    str
        JSON string representation of the packet.
    """
    # indent=2 makes it human-readable when printed.
    return json.dumps(packet, indent=2)


# ─────────────────────────────────────────────
# MAIN — demo the sender
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*55)
    print("  IoMT Sender — Packet Builder Demo")
    print("  Author: Sajan Baby P")
    print("="*55 + "\n")

    # Simulate building 3 packets from the same device.
    # Each packet gets a fresh timestamp and a unique nonce.
    for i in range(1, 4):
        print(f"--- Packet {i} ---")
        packet = build_packet(device_id="DEVICE_HEART_MONITOR_01")
        print(packet_to_json(packet))
        print()

    print("Notice: every packet has a different nonce.")
    print("This is what prevents replay attacks.\n")
