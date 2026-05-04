from enum import Enum

class PacketStatus(Enum):
    VALID = "VALID"
    TAMPERED = "TAMPERED"
    REPLAYED = "REPLAYED"
    INVALID_DEVICE = "INVALID_DEVICE"
    INVALID_FORMAT = "INVALID_FORMAT"
    DECRYPTION_ERROR = "DECRYPTION_ERROR"

class VerificationResult:
    def __init__(self, status: PacketStatus, reason: str, packet_id: str):
        self.status = status
        self.reason = reason
        self.packet_id = packet_id

    def is_valid(self):
        return self.status == PacketStatus.VALID


def verify_packet(packet: dict) -> VerificationResult:

    required_fields = [
        "device_id", "timestamp", "nonce",
        "encrypted_data", "hash_value",
        "hmac_value", "signature"
    ]

    # Step 1: Format validation
    for field in required_fields:
        if field not in packet:
            return VerificationResult(
                PacketStatus.INVALID_FORMAT,
                f"Missing field: {field}",
                packet.get("nonce", "UNKNOWN")
            )

    # TODO: Step 2 - Device authentication
    # TODO: Step 3 - Timestamp validation
    # TODO: Step 4 - Replay protection (nonce)
    # TODO: Step 5 - Signature verification
    # TODO: Step 6 - Hash/HMAC validation
    # TODO: Step 7 - Decryption

    return VerificationResult(
        PacketStatus.VALID,
        "Stub validation passed",
        packet["nonce"]
    )

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
