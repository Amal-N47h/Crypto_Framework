# packet_builder.py
# Anit Benny | SHA-256 Integrity + Packet Builder
# This module defines the canonical shared packet structure for the IoMT pipeline.

import json
import hashlib
import time


def build_base_packet(device_id, patient_id, nonce, vitals: dict) -> dict:
    """
    Build the base packet WITHOUT hash_value.
    This is the raw payload that gets hashed before transmission.
    
    All other modules (AES, ECC, HMAC, ECDSA) will plug their fields
    into this structure. For now we use placeholder values for those fields.
    """
    packet = {
        "device_id": device_id,
        "patient_id": patient_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nonce": nonce,
        "vitals": vitals,
        # Fields populated by other modules — placeholders until integration
        "encrypted_data": None,       
        "encrypted_key": None,       
        "hmac_value": None,          
        "signature": None,           
    }
    return packet


def canonical_json(packet_without_hash: dict) -> bytes:
    """
    Produce a CANONICAL (deterministic) JSON encoding of the packet.
    
    Why this matters: Python dicts have no guaranteed key order. If you hash
    a dict directly, two machines might produce different byte sequences for 
    the same data (different key order = different bytes = different hash).
    
    Solution: sort_keys=True + separators=(',', ':') gives us a fixed,
    compact, reproducible byte string every time on every machine.
    """
    return json.dumps(packet_without_hash, sort_keys=True, separators=(',', ':')).encode('utf-8')


def compute_sha256(data_bytes: bytes) -> str:
    """
    Compute SHA-256 hash and return as hex string (64 characters).
    This is the 'fingerprint' of the packet content.
    """
    return hashlib.sha256(data_bytes).hexdigest()


def build_final_packet(device_id, patient_id, nonce, vitals: dict) -> dict:
    """
    Full pipeline: build base packet → compute hash → attach hash_value.
    This is what gets sent over MQTT.
    """
    base = build_base_packet(device_id, patient_id, nonce, vitals)
    
    # IMPORTANT: We hash the base packet WITHOUT hash_value in it.
    # The receiver will also remove hash_value before recomputing — must match.
    canonical = canonical_json(base)
    hash_value = compute_sha256(canonical)
    
    # Now add hash_value to the final packet
    final_packet = dict(base)
    final_packet["hash_value"] = hash_value
    
    return final_packet


def verify_packet_integrity(received_packet: dict) -> tuple[bool, str]:
    """
    Verify the SHA-256 hash of a received packet.
    
    Steps:
    1. Extract the received hash_value from the packet
    2. Remove hash_value from a copy of the packet (to recreate original base)
    3. Recompute SHA-256 on that copy
    4. Compare: if they match → intact, if not → tampered
    
    Returns: (is_valid: bool, message: str)
    """
    # Step 1: Extract the hash that was sent
    received_hash = received_packet.get("hash_value")
    if received_hash is None:
        return False, "MISSING hash_value field — packet is malformed."
    
    # Step 2: Create a copy WITHOUT hash_value (recreates what sender hashed)
    packet_copy = {k: v for k, v in received_packet.items() if k != "hash_value"}
    
    # Step 3: Recompute the hash using the same canonical method
    canonical = canonical_json(packet_copy)
    recomputed_hash = compute_sha256(canonical)
    
    # Step 4: Compare
    if received_hash == recomputed_hash:
        return True, f"INTEGRITY OK — Hash verified: {recomputed_hash[:16]}..."
    else:
        return False, (
            f"TAMPER DETECTED!\n"
            f"  Expected : {received_hash[:32]}...\n"
            f"  Got      : {recomputed_hash[:32]}..."
        )