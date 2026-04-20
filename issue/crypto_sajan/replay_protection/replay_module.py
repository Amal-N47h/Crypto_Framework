"""
replay_module.py
================
Replay Protection Module for IoMT Cryptographic Framework
Author  : Sajan Baby P
Module  : Replay Protection (Week 1)

What this file does:
    When a medical device sends a packet, an attacker could capture that
    packet and resend it later to fake data or flood the system. This
    module detects such "replay attacks" using two mechanisms:

    1. Timestamp check  → reject packets older than MAX_PACKET_AGE_SECONDS
    2. Nonce check      → reject packets whose nonce has been seen before
"""

import uuid
from datetime import datetime, timezone, timedelta


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# A packet older than this many seconds is considered expired / replayed.
# You can change this number without touching any other code.
MAX_PACKET_AGE_SECONDS = 60


# ─────────────────────────────────────────────
# INTERNAL STATE
# ─────────────────────────────────────────────

# An in-memory set that stores every nonce we have seen so far.
# If the same nonce arrives again, we know it's a replayed packet.
_seen_nonces: set = set()


# ─────────────────────────────────────────────
# TIMESTAMP FUNCTIONS
# ─────────────────────────────────────────────

def generate_timestamp() -> str:
    """
    Create a timestamp string for right now (UTC).

    Returns
    -------
    str
        Current UTC time in ISO 8601 format.
        Example: "2025-04-19T10:30:00.123456+00:00"

    Why UTC?
        Medical devices may be in different time zones. UTC is a
        universal standard so everyone agrees on what "now" means.

    Why ISO 8601?
        It is a widely accepted format that Python can parse back
        into a datetime object easily. Other team members reading
        the packet can parse it without writing custom code.
    """
    # datetime.now(timezone.utc) gives current time with UTC timezone info.
    # .isoformat() converts it to the string format described above.
    return datetime.now(timezone.utc).isoformat()


def is_timestamp_valid(timestamp_str: str) -> bool:
    """
    Check whether a packet's timestamp is recent enough to be trusted.

    A packet is valid only if:
        current_time - packet_time  <=  MAX_PACKET_AGE_SECONDS

    Parameters
    ----------
    timestamp_str : str
        The timestamp string taken from the incoming packet.
        Expected format: ISO 8601 (same format generate_timestamp produces).

    Returns
    -------
    bool
        True  → packet is fresh, timestamp is acceptable.
        False → packet is too old (expired or replayed).
    """
    # Step 1: Parse the timestamp string back into a datetime object.
    # fromisoformat() is the reverse of .isoformat() — it reads the string.
    packet_time = datetime.fromisoformat(timestamp_str)

    # Step 2: Get the current UTC time so we can compare.
    current_time = datetime.now(timezone.utc)

    # Step 3: Calculate how old the packet is.
    # timedelta is Python's way of representing a difference between two times.
    age: timedelta = current_time - packet_time

    # Step 4: Compare the age against our configured maximum.
    # age.total_seconds() converts the timedelta to a plain number of seconds.
    # If the age is negative (packet from the future) we also reject it.
    return 0 <= age.total_seconds() <= MAX_PACKET_AGE_SECONDS


# ─────────────────────────────────────────────
# NONCE FUNCTIONS
# ─────────────────────────────────────────────

def generate_nonce() -> str:
    """
    Generate a universally unique nonce (Number Used Once).

    Returns
    -------
    str
        A UUID4 string.
        Example: "a3f2c1d4-89ab-4cde-b012-3456789abcde"

    Why UUID4?
        UUID4 generates a random 128-bit number. The chance of two
        devices accidentally generating the same UUID is astronomically
        small (~1 in 5.3 × 10^36). This makes it safe for global use
        without any central coordinator.
    """
    # uuid.uuid4() creates a UUID object. str() converts it to a readable string.
    return str(uuid.uuid4())


def is_nonce_fresh(nonce: str) -> bool:
    """
    Check whether a nonce has been used before.

    The first time a nonce is seen → it is stored and True is returned.
    Any subsequent time the same nonce arrives → False is returned.

    Parameters
    ----------
    nonce : str
        The nonce value from the incoming packet.

    Returns
    -------
    bool
        True  → nonce is new, packet has not been seen before.
        False → nonce already exists, this is a duplicate / replayed packet.
    """
    # _seen_nonces is the set declared at the top of this file.
    # Sets store unique values only and support very fast "is X in here?" checks.
    if nonce in _seen_nonces:
        # We have seen this nonce before → replay detected.
        return False

    # Nonce is new → record it so we can catch if this packet is replayed later.
    _seen_nonces.add(nonce)
    return True


def reset_nonce_store() -> None:
    """
    Clear all stored nonces.

    This is a helper used ONLY in tests so each test starts with a
    clean slate. Do NOT call this in production code.
    """
    # .clear() empties the set in-place without replacing the object itself.
    # This matters because other parts of the code hold a reference to _seen_nonces.
    _seen_nonces.clear()


# ─────────────────────────────────────────────
# COMBINED CHECK
# ─────────────────────────────────────────────

def check_replay_protection(packet: dict) -> tuple[bool, str]:
    """
    Run both replay-protection checks on an incoming packet.

    This is the main function that other team members (gateway, subscriber)
    will call. It checks the timestamp first, then the nonce.

    Parameters
    ----------
    packet : dict
        The incoming packet dictionary. Must contain at minimum:
            "timestamp" : str   (ISO 8601 UTC time string)
            "nonce"     : str   (UUID4 string)

    Returns
    -------
    tuple[bool, str]
        (True,  "OK")                  → packet is genuine, process it.
        (False, "EXPIRED_TIMESTAMP")   → packet is too old, reject it.
        (False, "DUPLICATE_NONCE")     → packet was already processed, reject it.

    Example usage (by gateway team member):
        ok, reason = check_replay_protection(received_packet)
        if not ok:
            print(f"Replay attack detected: {reason}")
    """
    # ── Check 1: Timestamp ──────────────────────────────────────────
    # Pull the "timestamp" field out of the packet dictionary.
    timestamp_str = packet["timestamp"]

    if not is_timestamp_valid(timestamp_str):
        # Packet is too old. Do NOT record the nonce — no need.
        return (False, "EXPIRED_TIMESTAMP")

    # ── Check 2: Nonce ──────────────────────────────────────────────
    # Pull the "nonce" field out of the packet dictionary.
    nonce = packet["nonce"]

    if not is_nonce_fresh(nonce):
        # Nonce already seen. This is a replayed packet.
        return (False, "DUPLICATE_NONCE")

    # ── Both checks passed ──────────────────────────────────────────
    return (True, "OK")
