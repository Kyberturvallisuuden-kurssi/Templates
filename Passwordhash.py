#!/usr/bin/env python3
import sys
import base64

from hashlib import sha256
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def getPasswords():
    with open("rockyou.txt", 'r', encoding='utf-8', errors='ignore') as file:
        passwds = file.read().splitlines()
    return passwds


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


def main(inputfile, student, outputfile):
    passwords = getPasswords()
    password = passwords[99]
    salt = sha256()
    salt.update(student.encode('utf-8'))
    print("Salt: ", salt.digest())
    print("Selected password:", password)
    fernetKey = getKey(password, salt.digest())
    with open(inputfile, mode='rb') as file:  # b binary
        fileContent = file.read()
    crypted = fernetKey.encrypt(fileContent)
    f = open(outputfile, 'w+b')
    f.write(crypted)
    f.close()


# Three arguments needed:
# file to encrypt
# student id
if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise ValueError(
            "Usage: password_hash.py Message studentUserId encryptedfile")
    inputfile = sys.argv[1]
    student = sys.argv[2]
    outputfile = sys.argv[3]
    print('inputfile:', inputfile, ' student:',
          student, ' outputfile:', outputfile)
    main(inputfile, student, outputfile)
