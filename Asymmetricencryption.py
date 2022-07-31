#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size=3072,
    backend=default_backend(),
)

public_key = private_key.public_key()

private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

with open('private_key.pem', 'xb') as private_file:
    private_file.write(private_bytes)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open('public_key.pem', 'xb') as public_file:
    public_file.write(public_bytes)

with open('private_key.pem', 'rb') as private_file:
    loaded_private_key = serialization.load_pem_private_key(
        private_file.read(),
        password=None,
        backend=default_backend()
    )

with open('public_key.pem', 'rb') as public_file:
    loaded_public_key = serialization.load_pem_public_key(
        public_file.read(),
        backend=default_backend()
    )
padding_config = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None, 
    )

plaintext = b'from A to B'

ciphertext = loaded_public_key.encrypt(
    plaintext=plaintext,
    padding=padding_config,
)
print('Ciphertext: ',ciphertext)
#decrypt with private key

cleartext = loaded_private_key.decrypt(ciphertext=ciphertext,padding=padding_config)
print('Cleartext: ',cleartext)