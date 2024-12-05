from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os

# Key generation for asymmetric encryption (RSA)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Symmetric key generation using Fernet
symmetric_key = Fernet.generate_key()
cipher_suite = Fernet(symmetric_key)

# Encrypting data using Fernet symmetric encryption
message = b"Secret message"
encrypted_message = cipher_suite.encrypt(message)

# Decrypting the data
decrypted_message = cipher_suite.decrypt(encrypted_message)

print(f"Original message: {message}")
print(f"Encrypted message: {encrypted_message}")
print(f"Decrypted message: {decrypted_message}")

# Signing data using RSA private key
message = b"Important message"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verifying the signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid.")
except Exception as e:
    print(f"Signature verification failed: {e}")

# Example of using a key derivation function (KDF) to generate a key from a password
password = b"my_secure_password"
salt = os.urandom(16)  # Secure random salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
derived_key = kdf.derive(password)

print(f"Derived key from password: {derived_key.hex()}")

# Creating a secure token using Fernet
secure_token = cipher_suite.encrypt(b"Sensitive information")
print(f"Secure token: {secure_token}")

# Decrypting the secure token
decrypted_token = cipher_suite.decrypt(secure_token)
print(f"Decrypted token: {decrypted_token}")
