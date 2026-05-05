from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

key = get_random_bytes(16)

def encrypt(message):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode(), key

if __name__ == "__main__":
    msg = "Patient Heart Rate: 72 bpm"
    encrypted, key = encrypt(msg)
    print("Encrypted:", encrypted)
    print("Key:", key)
