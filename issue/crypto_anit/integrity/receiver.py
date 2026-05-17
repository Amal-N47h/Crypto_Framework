import json
import hashlib
import sys

print("Paste packet JSON (press Enter twice when done):")
lines = []
while True:
    line = sys.stdin.readline().rstrip('\n')
    if line == "":
        break
    lines.append(line)

json_string = "\n".join(lines)
packet = json.loads(json_string)

received_hash = packet.get("hash_value")
packet_copy = {k: v for k, v in packet.items() if k != "hash_value"}

canonical = json.dumps(packet_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
recomputed_hash = hashlib.sha256(canonical).hexdigest()

print(f"\nReceived hash   : {received_hash}")
print(f"Recomputed hash : {recomputed_hash}")

if received_hash == recomputed_hash:
    print("Integrity Check : PASS")
else:
    print("Integrity Check : FAIL — packet tampered")