from Crypto.Cipher import AES
import base64

def decrypt(encrypted_data, key):
    raw = base64.b64decode(encrypted_data)
    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode()

if __name__ == "__main__":
    encrypted = input("Enter encrypted data: ")
    key = eval(input("Enter key: "))
    print("Decrypted:", decrypt(encrypted, key))
