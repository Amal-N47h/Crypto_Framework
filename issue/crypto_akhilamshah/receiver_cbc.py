from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt(encrypted_data, key):
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()

if __name__ == "__main__":
    encrypted = input("Enter encrypted data: ")
    key = eval(input("Enter key: "))
    print("Decrypted:", decrypt(encrypted, key))
