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