pip install pycryptodome
import json
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
# =========================
# 1. SAMPLE PATIENT DATA
# =========================
patient_data = {
    "device_id": "IoMT_001",
    "heart_rate": 78,
    "bp": "120/80",
    "timestamp": "2026-04-16 10:30:00"
}
# =========================
# 2. GENERATE AES KEY (128-bit)
# =========================
key = get_random_bytes(16)  # 16 bytes = AES-128
# =========================
# 3. ENCRYPT FUNCTION
# =========================
def encrypt_data(data, key):
    # Convert JSON → string → bytes
    json_data = json.dumps(data).encode('utf-8')

    # Create cipher (CBC mode)
    cipher = AES.new(key, AES.MODE_CBC)

    # Pad and encrypt
    ciphertext = cipher.encrypt(pad(json_data, AES.block_size))

    # Encode IV + ciphertext to Base64
    encrypted_payload = base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

    return encrypted_payload
  # =========================
# 4. DECRYPT FUNCTION
# =========================
def decrypt_data(encrypted_payload, key):
    raw = base64.b64decode(encrypted_payload.encode('utf-8'))

    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return json.loads(decrypted.decode('utf-8'))
  # =========================
# 5. TEST RUN
# =========================
encrypted = encrypt_data(patient_data, key)
print("Encrypted Data:\n", encrypted)

decrypted = decrypt_data(encrypted, key)
print("\nDecrypted Data:\n", decrypted)


# FINAL PACKET STRUCTURE (to be used by all modules)
'''packet = {
    "device_id": <string>,
    "timestamp": <string>,
    "encrypted_data": <Base64 string>
}'''

# NOTE FOR HASHING MODULE:
# Apply hash on 'encrypted_data'

# NOTE FOR HMAC MODULE:
# Generate HMAC using the complete packet

# NOTE FOR MQTT MODULE:
# Transmit this packet as JSON
