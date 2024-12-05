from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_fernet_key():
    # Generates a Fernet key
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_fernet_key():
    # Loads the Fernet key from a file
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_fernet_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message):
    key = load_fernet_key()
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message

def generate_rsa_key_pair():
    # Generates RSA public and private keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

if __name__ == "__main__":
    generate_fernet_key()
    message = "This is a secret message."
    encrypted = encrypt_message(message)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt_message(encrypted)
    print(f"Decrypted: {decrypted}")
    
    private_key, public_key = generate_rsa_key_pair()
    print("RSA keys generated.")

    

    