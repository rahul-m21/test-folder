# Filename: pqcrypto_dilithium_sign.py

from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify

# Generate a public/private keypair
public_key, private_key = generate_keypair()

# Message to be signed
message = b"Hello, Post-Quantum Cryptography!"

# Sign the message
signature = sign(message, private_key)

print(f"Signature: {signature}")

# Verify the signature
is_valid = verify(message, signature, public_key)

if is_valid:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
