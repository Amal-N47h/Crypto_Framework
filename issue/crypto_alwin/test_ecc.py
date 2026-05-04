import os
from ecc_keygen import generate_ecc_keypair
from ecc_exchange import derive_shared_secret
from ecc_wrap import encrypt_aes_key, decrypt_aes_key


def test_full_flow():
    print("🔑 Generating ECC keys...")

    # Receiver generates key pair
    receiver_priv, receiver_pub = generate_ecc_keypair()

    # Sender generates key pair
    sender_priv, sender_pub = generate_ecc_keypair()

    print("📡 Sharing receiver public key...")

    # Both derive same shared key
    sender_shared = derive_shared_secret(sender_priv, receiver_pub)
    receiver_shared = derive_shared_secret(receiver_priv, sender_pub)

    assert sender_shared == receiver_shared
    print("✅ Shared key established")

    # AES session key (payload key)
    aes_session_key = os.urandom(32)

    print("🔐 Wrapping AES session key...")

    # Sender encrypts AES key
    iv, encrypted_key, tag = encrypt_aes_key(aes_session_key, sender_shared)

    print("📦 Transmitting encrypted AES key...")

    # Receiver decrypts AES key
    decrypted_key = decrypt_aes_key(iv, encrypted_key, tag, receiver_shared)

    assert aes_session_key == decrypted_key

    print("✅ SUCCESS: AES key securely transmitted!")
    print("🔑 AES Key:", aes_session_key.hex())


if __name__ == "__main__":
    test_full_flow()