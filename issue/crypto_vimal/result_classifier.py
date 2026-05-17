# result_classifier.py
from enum import Enum
import time
import hashlib
import json
from datetime import datetime

# ===================== ENUM =====================

class PacketStatus(Enum):
    VALID = "VALID"
    TAMPERED = "TAMPERED"
    REPLAYED = "REPLAYED"
    INVALID_DEVICE = "INVALID_DEVICE"
    INVALID_FORMAT = "INVALID_FORMAT"
    DECRYPTION_ERROR = "DECRYPTION_ERROR"


# ===================== RESULT CLASS =====================

class VerificationResult:
    def __init__(self, status: PacketStatus, reason: str, packet_id: str):
        self.status = status
        self.reason = reason
        self.packet_id = packet_id

    def is_valid(self):
        return self.status == PacketStatus.VALID


# ===================== MEMORY (for replay detection) =====================

seen_nonces = set()


# ===================== HELPER: TIMESTAMP =====================

def parse_timestamp(ts: str):
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        return dt.timestamp()
    except:
        return None


# ===================== HELPER: HASH VERIFY =====================

def verify_hash(packet: dict):
    received_hash = packet.get("hash_value")

    # remove hash field before recomputing
    packet_copy = {k: v for k, v in packet.items() if k != "hash_value"}

    canonical = json.dumps(
        packet_copy,
        sort_keys=True,
        separators=(',', ':')
    ).encode("utf-8")

    recomputed_hash = hashlib.sha256(canonical).hexdigest()

    return received_hash == recomputed_hash


# ===================== MAIN VERIFIER =====================

def verify_packet(packet: dict) -> VerificationResult:

    # Unified packet fields (see README.md)
    required_fields = [
        "device_id",
        "timestamp",
        "nonce",
        "encrypted_data",
        "ephemeral_public_key",
        "hash_value",
        "signature"
    ]

    # 1. FORMAT CHECK
    for field in required_fields:
        if field not in packet:
            return VerificationResult(
                PacketStatus.INVALID_FORMAT,
                f"Missing field: {field}",
                packet.get("nonce", "UNKNOWN")
            )

    # 2. DEVICE AUTH (placeholder: trusted device list)
    if not packet["device_id"].startswith("IOMT"):
        return VerificationResult(
            PacketStatus.INVALID_DEVICE,
            "Unknown / unauthorized device",
            packet["nonce"]
        )
    # TODO: Check against trusted device registry

    # 3. SIGNATURE VERIFICATION (placeholder)
    # TODO: Import and verify ECDSA signature
    # if not verify_signature(packet):
    #     return VerificationResult(PacketStatus.TAMPERED, "Invalid signature", packet["nonce"])

    # 4. HASH/HMAC CHECK
    received_hash = packet["hash_value"]
    packet_copy = {k: v for k, v in packet.items() if k != "hash_value"}
    canonical = json.dumps(
        packet_copy,
        sort_keys=True,
        separators=(',', ':')
    ).encode('utf-8')
    recomputed_hash = hashlib.sha256(canonical).hexdigest()
    if received_hash != recomputed_hash:
        return VerificationResult(
            PacketStatus.TAMPERED,
            "Hash mismatch (data tampered)",
            packet["nonce"]
        )
    # TODO: Optionally verify HMAC if present

    # 5. TIMESTAMP CHECK
    from datetime import datetime, timezone
    try:
        packet_time = datetime.fromisoformat(packet["timestamp"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if abs((now - packet_time).total_seconds()) > 60:
            return VerificationResult(
                PacketStatus.REPLAYED,
                "Old / expired packet",
                packet["nonce"]
            )
    except:
        return VerificationResult(
            PacketStatus.INVALID_FORMAT,
            "Invalid timestamp",
            packet["nonce"]
        )

    # 6. NONCE/REPLAY CHECK
    if packet["nonce"] in seen_nonces:
        return VerificationResult(
            PacketStatus.REPLAYED,
            "Duplicate nonce (Replay attack)",
            packet["nonce"]
        )
    seen_nonces.add(packet["nonce"])

    # 7. DECRYPTION (placeholder)
    # TODO: Decrypt encrypted_data using AES/ECC/Hybrid
    # If decryption fails:
    #     return VerificationResult(PacketStatus.DECRYPTION_ERROR, "Decryption failed", packet["nonce"])

    # 8. FINAL
    return VerificationResult(
        PacketStatus.VALID,
        "All checks passed",
        packet["nonce"]
    )

   


# ===================== DASHBOARD PRINT =====================

def print_dashboard(results: list):
    print("\n=== VERIFICATION DASHBOARD ===")

    total = len(results)
    valid = sum(1 for r in results if r.status == PacketStatus.VALID)
    invalid = total - valid

    print(f"\nTotal: {total} | Valid: {valid} | Invalid: {invalid}\n")

    print("{:<20} {:<20} {:<30}".format("Packet ID", "Status", "Reason"))
    print("-" * 70)

    for r in results:
        print("{:<20} {:<20} {:<30}".format(
            r.packet_id,
            r.status.value,
            r.reason
        ))