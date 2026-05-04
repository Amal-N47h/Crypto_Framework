from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_gcm(key: bytes, plaintext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # prepend nonce + tag
    combined = cipher.nonce + tag + ciphertext

    return base64.b64encode(combined).decode()

def decrypt_gcm(key: bytes, b64_data: str) -> bytes:
    data = base64.b64decode(b64_data)

    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    return cipher.decrypt_and_verify(ciphertext, tag)