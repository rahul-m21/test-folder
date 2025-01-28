from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save keys to files
with open('private.pem', 'wb') as f:
    f.write(private_key)
with open('public.pem', 'wb') as f:
    f.write(public_key)

# RSA Encryption
def rsa_encrypt(data, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

# RSA Decryption
def rsa_decrypt(encrypted_data, private_key):
    recipient_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)
    return decrypted_data

# Test encryption and decryption
data = b"Secret message using RSA"
encrypted = rsa_encrypt(data, public_key)
print("Encrypted:", encrypted)

decrypted = rsa_decrypt(encrypted, private_key)
print("Decrypted:", decrypted)
