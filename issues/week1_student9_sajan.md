---
title: "[Week 1] Sajan Baby P – Replay Protection: Implement Timestamp & Nonce Logic"
assignee: ""
labels: ["Week 1", "replay-protection", "security"]
---

## Assigned To
**Sajan Baby P** — Student 9

## Module
**Replay Protection** | Integration Role: *Attack Injection Tester*

## Week 1 Goal (Apr 13–19)
> Implement timestamp generation/validation and nonce creation/tracking so that replayed and expired packets can be detected.

---

## Detailed Tasks

### 1. Environment Setup
- Set up Python 3.10+ virtual environment.
- No extra libraries needed (`datetime`, `uuid`, `time` are all standard library).
- Create your module folder:
  ```
  crypto_framework/
  └── replay_protection/
      ├── replay_module.py
      └── test_replay.py
  ```

### 2. Implement Timestamp Generation & Validation
In `replay_module.py`:
```python
from datetime import datetime, timezone, timedelta

TIMESTAMP_WINDOW_SECONDS = 60  # Accept packets no older than 60 seconds

def generate_timestamp() -> str:
    """Returns current UTC time as ISO 8601 string, e.g. '2025-04-15T10:00:00Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_timestamp_valid(timestamp_str: str) -> bool:
    """
    Returns True if the timestamp is within TIMESTAMP_WINDOW_SECONDS of now.
    Returns False if the packet is too old or timestamp is in the future.
    """
    try:
        ts = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = abs((now - ts).total_seconds())
        return delta <= TIMESTAMP_WINDOW_SECONDS
    except ValueError:
        return False  # Malformed timestamp
```

### 3. Implement Nonce Generation & Replay Detection
```python
import uuid

# In-memory nonce store (replace with persistent storage in production)
_seen_nonces: set = set()

def generate_nonce() -> str:
    """Generates a unique random nonce string."""
    return str(uuid.uuid4())

def is_nonce_fresh(nonce: str) -> bool:
    """
    Returns True if this nonce has NOT been seen before.
    Returns False if it has been seen (replay detected).
    Records the nonce as seen.
    """
    if nonce in _seen_nonces:
        return False
    _seen_nonces.add(nonce)
    return True

def reset_nonce_store() -> None:
    """Clears the nonce store — for testing only."""
    _seen_nonces.clear()
```

### 4. Combine Into a Single Replay Check Function
```python
def check_replay_protection(packet: dict) -> tuple[bool, str]:
    """
    Checks timestamp and nonce for the given packet.
    Returns (True, "OK") if both checks pass.
    Returns (False, reason) if either check fails.
    reason is one of: "EXPIRED_TIMESTAMP", "FUTURE_TIMESTAMP", "DUPLICATE_NONCE"
    """
    timestamp = packet.get("timestamp", "")
    nonce = packet.get("nonce", "")

    if not is_timestamp_valid(timestamp):
        return False, "EXPIRED_TIMESTAMP"

    if not is_nonce_fresh(nonce):
        return False, "DUPLICATE_NONCE"

    return True, "OK"
```

### 5. Test Replay Scenarios
In `test_replay.py`:
```python
import time

# Fresh packet — should pass
reset_nonce_store()
packet_fresh = {
    "timestamp": generate_timestamp(),
    "nonce": generate_nonce(),
}
ok, reason = check_replay_protection(packet_fresh)
assert ok == True, f"Fresh packet should pass, got: {reason}"

# Replay same packet — should fail with DUPLICATE_NONCE
ok, reason = check_replay_protection(packet_fresh)
assert ok == False and reason == "DUPLICATE_NONCE", f"Replay should be rejected, got: {reason}"

# Expired timestamp — should fail
reset_nonce_store()
old_packet = {
    "timestamp": "2020-01-01T00:00:00Z",  # Far in the past
    "nonce": generate_nonce(),
}
ok, reason = check_replay_protection(old_packet)
assert ok == False and reason == "EXPIRED_TIMESTAMP", f"Expired packet should fail, got: {reason}"

print("All replay protection tests passed.")
```

---

## Deliverables by End of Week 1
- [ ] `generate_timestamp` and `is_timestamp_valid` implemented.
- [ ] `generate_nonce` and `is_nonce_fresh` implemented.
- [ ] `check_replay_protection` combining both checks.
- [ ] Tests: fresh packet passes, replay fails with DUPLICATE_NONCE, old packet fails with EXPIRED_TIMESTAMP.
- [ ] Code pushed to your branch.

---

## Dependencies
- **Student 5 (Anit)** — coordinate on packet field names (`timestamp`, `nonce`).
- **Student 8 (Noufan)** — your checks are steps 2–3 in the verification pipeline defined by Student 8. Review `verification_order.md`.

## Notes
In a real IoMT deployment the nonce store needs to be persistent (database or file) and cleaned up periodically to avoid unbounded growth. For this project, an in-memory set is acceptable. Document this limitation in your code. In Week 3 you will run attack injection tests using your `check_replay_protection` function.
