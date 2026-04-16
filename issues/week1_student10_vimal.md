---
title: "[Week 1] Vimal Mudalagi – Attack/Tampering Detection: Define Result Categories & Logging"
assignee: ""
labels: ["Week 1", "attack-detection", "verification"]
---

## Assigned To
**Vimal Mudalagi** — Student 10

## Module
**Attack / Tampering Detection** | Integration Role: *Dashboard Integrator*

## Week 1 Goal (Apr 13–19)
> Define the packet result classification system (valid, tampered, replayed, invalid) and set up the logging/output framework that will host the final verifier dashboard.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment.
- No extra libraries needed; use the standard `logging` module.
- Create your module folder:
  ```
  crypto_framework/
  └── verifier/
      ├── result_classifier.py
      ├── verifier_logger.py
      └── test_classifier.py
  ```

### 2. Define the Result Classification System
In `result_classifier.py`, define all possible packet outcomes:
```python
from enum import Enum

class PacketStatus(Enum):
    VALID            = "VALID"             # All checks passed; decryption succeeded
    TAMPERED         = "TAMPERED"          # Hash or HMAC or signature check failed
    REPLAYED         = "REPLAYED"          # Nonce already seen or timestamp expired
    INVALID_DEVICE   = "INVALID_DEVICE"    # device_id not in trusted registry
    INVALID_FORMAT   = "INVALID_FORMAT"    # Missing required fields or malformed packet
    DECRYPTION_ERROR = "DECRYPTION_ERROR"  # Decryption step failed unexpectedly

class VerificationResult:
    def __init__(self, status: PacketStatus, reason: str, packet_id: str = ""):
        self.status = status
        self.reason = reason
        self.packet_id = packet_id

    def is_valid(self) -> bool:
        return self.status == PacketStatus.VALID

    def __repr__(self):
        return f"VerificationResult(status={self.status.value}, reason='{self.reason}', packet_id='{self.packet_id}')"
```

### 3. Implement the Logging Framework
In `verifier_logger.py`:
```python
import logging
from result_classifier import VerificationResult

# Configure a logger for the framework
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),            # Print to console
        logging.FileHandler("verifier.log") # Also save to file
    ]
)
logger = logging.getLogger("iomt_verifier")

def log_result(result: VerificationResult) -> None:
    """
    Logs a VerificationResult with appropriate log level:
    - VALID → INFO
    - REPLAYED / INVALID_DEVICE / INVALID_FORMAT → WARNING
    - TAMPERED / DECRYPTION_ERROR → ERROR
    """
    msg = f"Packet '{result.packet_id}' | {result.status.value} | {result.reason}"
    if result.status.value == "VALID":
        logger.info(msg)
    elif result.status.value in ("TAMPERED", "DECRYPTION_ERROR"):
        logger.error(msg)
    else:
        logger.warning(msg)
```

### 4. Write a Simple Stub Verifier
Write a stub `verify_packet` function in `result_classifier.py` that will be filled in Week 2–3 as other modules become available:
```python
def verify_packet(packet: dict) -> VerificationResult:
    """
    Full verification pipeline (stub — to be completed in Weeks 2–3).

    Pipeline order (from Student 8's verification_order.md):
    1. Check required fields (INVALID_FORMAT)
    2. Device authentication (INVALID_DEVICE)
    3. Timestamp + nonce check (REPLAYED)
    4. ECDSA signature verification (TAMPERED)
    5. SHA-256 hash verification (TAMPERED)
    6. HMAC verification (TAMPERED)
    7. AES decryption (DECRYPTION_ERROR)
    """
    packet_id = packet.get("nonce", "unknown")

    # Step 1: Check required fields
    required_fields = ["encrypted_data", "device_id", "timestamp", "nonce",
                       "hash_value", "hmac_value", "signature", "ephemeral_public_key"]
    for field in required_fields:
        if field not in packet:
            return VerificationResult(
                PacketStatus.INVALID_FORMAT,
                f"Missing field: {field}",
                packet_id
            )

    # Steps 2–7: TODO in Week 2–3 (import and call other students' modules)
    return VerificationResult(PacketStatus.VALID, "All checks passed (stub)", packet_id)
```

### 5. Define the Dashboard Output Format
Write a `print_dashboard` function to display results clearly:
```python
def print_dashboard(results: list) -> None:
    """
    Prints a summary table of verification results.
    """
    print("\n" + "="*60)
    print("  IoMT Packet Verification Dashboard")
    print("="*60)
    print(f"{'Packet ID':<20} {'Status':<20} {'Reason'}")
    print("-"*60)
    for r in results:
        print(f"{r.packet_id:<20} {r.status.value:<20} {r.reason}")
    print("="*60)

    valid_count   = sum(1 for r in results if r.status == PacketStatus.VALID)
    invalid_count = len(results) - valid_count
    print(f"  Total: {len(results)}  |  Valid: {valid_count}  |  Rejected: {invalid_count}")
    print("="*60 + "\n")
```

### 6. Test the Classification and Logging
In `test_classifier.py`:
```python
from result_classifier import PacketStatus, VerificationResult, verify_packet, print_dashboard
from verifier_logger import log_result

# Create sample results for each status type
results = [
    VerificationResult(PacketStatus.VALID, "All checks passed", "nonce-001"),
    VerificationResult(PacketStatus.TAMPERED, "Hash mismatch", "nonce-002"),
    VerificationResult(PacketStatus.REPLAYED, "Duplicate nonce", "nonce-003"),
    VerificationResult(PacketStatus.INVALID_DEVICE, "Unknown device DEV-999", "nonce-004"),
    VerificationResult(PacketStatus.INVALID_FORMAT, "Missing field: signature", "nonce-005"),
]

for r in results:
    log_result(r)

print_dashboard(results)
print("Classification and dashboard tests complete.")
```

---

## Deliverables by End of Week 1
- [ ] `PacketStatus` enum with all 6 categories defined.
- [ ] `VerificationResult` class implemented.
- [ ] `log_result` logging framework working (console + file).
- [ ] `verify_packet` stub with pipeline steps commented in.
- [ ] `print_dashboard` output function working.
- [ ] Tests: all 6 status types log correctly and display in dashboard.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Students 5–9** — read all their modules to understand what each check produces, so you can correctly map failure modes to your `PacketStatus` enum.
- **Student 8 (Noufan)** — use the `verification_order.md` pipeline order in your stub.

## Notes
Your dashboard is the **final output of the entire project** — everything leads to your `print_dashboard`. In Week 3 you will replace the stubs with real calls to each student's module. Start now by reading everyone's code and noting the exact function signatures you will call. Any mismatch in return types or packet field names should be raised as a team issue immediately.
