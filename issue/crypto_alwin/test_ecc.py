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
from ecc_keygen import generate_ecc_keypair
from ecc_exchange import derive_shared_secret


def test_ecdh_key_exchange():
    # Generate key pairs
    sender_private, sender_public = generate_ecc_keypair()
    receiver_private, receiver_public = generate_ecc_keypair()

    # Derive shared secrets
    sender_secret = derive_shared_secret(sender_private, receiver_public)
    receiver_secret = derive_shared_secret(receiver_private, sender_public)

    # Validate
    assert sender_secret == receiver_secret, "Shared secrets do not match!"

    print("✅ ECDH key exchange successful!")
    print("🔑 Shared key (32 bytes):", sender_secret.hex())


if __name__ == "__main__":
    test_ecdh_key_exchange()
