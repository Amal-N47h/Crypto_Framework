from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_shared_secret(private_key, peer_public_key):
    """
    Perform ECDH and derive a 32-byte AES key using HKDF-SHA256.
    """

    # Raw ECDH shared secret
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # HKDF -> 32 bytes (AES-256 key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh aes key"
    ).derive(shared_key)

    return derived_key