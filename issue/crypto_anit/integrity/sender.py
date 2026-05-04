import json
import hashlib
import time
import secrets

device_id = "IOMT-DEV-00423"
patient_id = "PAT-9981"
nonce = secrets.token_hex(8)
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

vitals = {
    "heart_rate": 82,
    "spo2": 97,
    "temperature": 36.7,
    "blood_pressure": "120/80"
}

packet = {
    "device_id": device_id,
    "patient_id": patient_id,
    "timestamp": timestamp,
    "nonce": nonce,
    "vitals": vitals
}

canonical = json.dumps(packet, sort_keys=True, separators=(',', ':')).encode('utf-8')
packet["hash_value"] = hashlib.sha256(canonical).hexdigest()

print(json.dumps(packet, indent=2))