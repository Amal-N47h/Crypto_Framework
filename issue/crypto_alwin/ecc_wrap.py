import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_aes_key(aes_key, wrapping_key):
    """
    Encrypt (wrap) AES session key using derived shared key
    """
    iv = os.urandom(12)

    cipher = Cipher(
        algorithms.AES(wrapping_key),
        modes.GCM(iv)
    )

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(aes_key) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag


def decrypt_aes_key(iv, ciphertext, tag, wrapping_key):
    """
    Decrypt (unwrap) AES session key
    """
    cipher = Cipher(
        algorithms.AES(wrapping_key),
        modes.GCM(iv, tag)
    )

    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()