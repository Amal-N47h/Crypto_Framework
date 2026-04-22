from crypto_vimal.result_classifier import *
from crypto_vimal.verifier_logger import log_result

def run_tests():

    results = [
        VerificationResult(PacketStatus.VALID, "All checks passed", "pkt1"),
        VerificationResult(PacketStatus.TAMPERED, "HMAC mismatch", "pkt2"),
        VerificationResult(PacketStatus.REPLAYED, "Duplicate nonce", "pkt3"),
        VerificationResult(PacketStatus.INVALID_DEVICE, "Unknown device", "pkt4"),
        VerificationResult(PacketStatus.INVALID_FORMAT, "Missing field", "pkt5"),
        VerificationResult(PacketStatus.DECRYPTION_ERROR, "AES failed", "pkt6"),
    ]

    for r in results:
        log_result(r)

    print_dashboard(results)


if __name__ == "__main__":
    run_tests()