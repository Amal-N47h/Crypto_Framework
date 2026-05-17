from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

BLOCK_SIZE = 16

def encrypt_cbc(key: bytes, plaintext: bytes) -> str:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_data = pad(plaintext, BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)

    # prepend IV
    combined = iv + ciphertext

    return base64.b64encode(combined).decode()

def decrypt_cbc(key: bytes, b64_data: str) -> bytes:
    data = base64.b64decode(b64_data)

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted, BLOCK_SIZE)