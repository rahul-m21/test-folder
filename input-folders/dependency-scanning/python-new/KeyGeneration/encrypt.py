from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_aes(key, plaintext):
    # Ensure the key is 256 bits (32 bytes) long
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 128, 192, or 256 bits long.")
    
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Initialize AES cipher in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the plaintext
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return the IV and ciphertext
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    # Split the IV and the actual ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    # Initialize AES cipher in CBC mode with the same IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

# Example usage
key = os.urandom(32)  # 256-bit key
plaintext = b"Secret message to encrypt!"

# Encrypt the plaintext
ciphertext = encrypt_aes(key, plaintext)
print("Ciphertext:", ciphertext)

# Decrypt the ciphertext
decrypted_text = decrypt_aes(key, ciphertext)
print("Decrypted Text:", decrypted_text.decode('utf-8'))
