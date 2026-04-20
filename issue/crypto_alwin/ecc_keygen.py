from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_ecc_keypair():
    """
    Generate ECC key pair using NIST P-256 curve.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


# ---------- Serialization ----------

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# ---------- Deserialization ----------

def load_private_key(pem_bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


def load_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes)