#!/usr/bin/env python3
import sys
import base64
from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def readPasswords():
    with open("rockyou.txt", 'r', encoding='utf-8', errors='ignore') as file:
        passwords = file.read().splitlines()
    return passwords


def getKey(passwd, salt):
    passwdBytes = passwd.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwdBytes))
    f = Fernet(key)
    return f


def main(cryptedFile, student, clearTextFile):
    # replace pass with yout code
    # create salt using SHA256 algorithm and your userId.
    # salt = ?
    with open(cryptedFile, mode='rb') as file:  # b binary
        crypted = file.read()
    passwords = readPasswords()
    # try to decrypt file content with a password - one password in passwords will be correct
    # Fernet key is provided by getKey(passwd, salt)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise ValueError(
            "Usage: assignment1.py cryptedFile studentUserId decryptedfile")
    main(sys.argv[1], sys.argv[2], sys.argv[3])