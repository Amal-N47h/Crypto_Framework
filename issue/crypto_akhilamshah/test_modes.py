import json
from aes_cbc import encrypt_cbc, decrypt_cbc
from aes_gcm import encrypt_gcm, decrypt_gcm

def main():
    key = b'1234567890123456'  # 16 bytes key

    patient_data = {
        "patient_id": "P001",
        "heart_rate": 78,
        "spo2": 98,
        "temperature": 36.7
    }

    plaintext = json.dumps(patient_data).encode()

    print("=== AES-CBC ===")
    enc_cbc = encrypt_cbc(key, plaintext)
    dec_cbc = decrypt_cbc(key, enc_cbc)

    assert dec_cbc == plaintext
    print("CBC Success ✅")

    print("Encrypted:", enc_cbc)

    print("\n=== AES-GCM ===")
    enc_gcm = encrypt_gcm(key, plaintext)
    dec_gcm = decrypt_gcm(key, enc_gcm)

    assert dec_gcm == plaintext
    print("GCM Success ✅")

    print("Encrypted:", enc_gcm)


if __name__ == "__main__":
    main()