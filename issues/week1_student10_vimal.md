# [Week 1] Vimal Mudalagi – Attack/Tampering Detection

**Module:** Attack/Tampering Detection | **Role:** Dashboard Integrator

**Goal (Apr 13–19):** Define the packet result classification system and set up the logging and dashboard output framework that the final verifier will use.

## Tasks

1. Create folder `crypto_framework/verifier/` with `result_classifier.py`, `verifier_logger.py`, and `test_classifier.py`. No extra libraries needed.
2. In `result_classifier.py`, define a `PacketStatus` enum with six values: `VALID`, `TAMPERED`, `REPLAYED`, `INVALID_DEVICE`, `INVALID_FORMAT`, `DECRYPTION_ERROR`. Add a `VerificationResult` class holding `status`, `reason`, and `packet_id`, with an `is_valid()` method.
3. In `verifier_logger.py`, configure a logger that writes to both the console and a `verifier.log` file. Implement `log_result(result)`: log `VALID` at INFO level, `TAMPERED`/`DECRYPTION_ERROR` at ERROR, everything else at WARNING.
4. Write a `verify_packet(packet: dict) -> VerificationResult` stub in `result_classifier.py`. Step 1: check all required fields are present (return `INVALID_FORMAT` if not). Steps 2–7: add `# TODO` comments for each pipeline step in order from Student 8's `verification_order.md`. Return `VALID` stub result.
5. Implement `print_dashboard(results: list)` that prints a formatted table of all results with a summary count (total / valid / rejected).
6. In `test_classifier.py`, create one `VerificationResult` for each status type, call `log_result` on each, and call `print_dashboard` to confirm the output looks correct.

## Deliverables
- [ ] `PacketStatus` enum with all 6 categories
- [ ] `VerificationResult` class with `is_valid()`
- [ ] Logger writing to console + file with correct log levels
- [ ] `verify_packet` stub with pipeline steps as `# TODO` comments
- [ ] `print_dashboard` producing a readable summary table
- [ ] All status types logged and displayed correctly in tests
- [ ] Code pushed to your branch
