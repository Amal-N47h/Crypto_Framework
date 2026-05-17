# STEP 1: Import required modules
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


# STEP 2: Define function
def generate_keys():

    # STEP 3: Generate private key
    # Command executed internally:
    # -> Creates random number 'd' on elliptic curve SECP256R1
    private_key = ec.generate_private_key(ec.SECP256R1())

    # STEP 4: Generate public key from private key
    # -> public_key = d * G (elliptic curve math)
    public_key = private_key.public_key()

    # STEP 5: Convert private key to PEM format
    # Equivalent concept command:
    # -> serialize(private_key)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,          # Convert to PEM format
        format=serialization.PrivateFormat.PKCS8,     # Standard structure
        encryption_algorithm=serialization.NoEncryption()  # No password
    )

    # STEP 6: Convert public key to PEM
    # -> serialize(public_key)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # STEP 7: Save private key to file
    # Terminal equivalent:
    # -> write private_key.pem
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    # STEP 8: Save public key to file
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    # STEP 9: Print keys
    print("=== PRIVATE KEY ===")
    print(private_pem.decode())

    print("=== PUBLIC KEY ===")
    print(public_pem.decode())

    print("Key pair generated and displayed.")




#Private key loading
# STEP 1: Import module for deserialization
from cryptography.hazmat.primitives import serialization


# STEP 2: Define function to load private key
def load_private_key():

    # STEP 3: Open private key file in binary read mode
    # Command concept:
    # -> read file "private_key.pem"
    with open("private_key.pem", "rb") as f:

        # STEP 4: Deserialize PEM → Python object
        # Command concept:
        # -> parse PEM structure
        # -> reconstruct EC private key
        private_key = serialization.load_pem_private_key(
            f.read(),        # Read file content (bytes)
            password=None    # No encryption on key
        )

    # STEP 5: Return key object
    return private_key





# Signing function 
# STEP 1: Imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# STEP 2: Load private key from file
def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# STEP 3: Sign function
def sign_data(data: bytes, private_key):

    # Internal operation:
    # 1. Hash the data using SHA256
    # 2. Apply ECDSA signing using private key
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    return signature





# Simulated packet creation 
# STEP 1: Imports
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# STEP 2: Load private key
def load_private_key():
    with open("private_key.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# STEP 3: Sign data
def sign_data(data: bytes, private_key):
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


# STEP 4: Create signed packet
def create_signed_packet(data_str):

    # Load key
    private_key = load_private_key()

    # Convert string → bytes
    data_bytes = data_str.encode()

    # Generate signature
    signature = sign_data(data_bytes, private_key)

    # Create packet (dictionary)
    packet = {
        "data": data_str,
        "signature": signature.hex()
    }

    # Convert to JSON format
    return json.dumps(packet, indent=2)



# main
if __name__ == "__main__":
    generate_keys()

    packet = create_signed_packet("patient_heart_rate=85")
    print("Signed Packet:")
    print(packet)

