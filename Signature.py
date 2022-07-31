#!/usr/bin/env python3
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

message = b'From A to B'

padding_config = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)
def load_rsa_private_key():
    with open('private_key.pem', 'rb') as private_file:
        load_rsa_private_key = serialization.load_pem_private_key(
            private_file.read(),
            password=None,
            backend=default_backend()
    )
    return load_rsa_private_key

private_key = load_rsa_private_key()
signature = private_key.sign(
    message,
    padding_config,
    hashes.SHA256())

signed_msg = {
    'message': str(message),
    'signature': list(signature),
}

outbound_msg_to_b = json.dumps(signed_msg)