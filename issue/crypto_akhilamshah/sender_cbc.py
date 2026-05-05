from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import base64

key = get_random_bytes(16)  # 128-bit key

def encrypt(message):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode(), key

if __name__ == "__main__":
    msg = "Patient Heart Rate: 72 bpm"
    encrypted, key = encrypt(msg)
    print("Encrypted:", encrypted)
    print("Key:", key)
