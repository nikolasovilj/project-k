#!/usr/bin/env python3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
import argparse
from getpass import getpass

parser = argparse.ArgumentParser(description="encryption/decryption utility")
parser.add_argument("--encrypt", "-e", action="store_true", help="Encrypt the file")
parser.add_argument("--decrypt", "-d", action="store_true", help="Decrypt the file")
args = parser.parse_args()

if len(sys.argv) < 2:
    parser.print_help(sys.stderr)
    sys.exit(1)
if args.encrypt:
    print("encryption of a file")
elif args.decrypt:
    print("decryption of a file")

password = getpass("enter your password: ").encode()

salt = b'\x86J\x1c\xd2`\xdf\xd0\xd9\tf\xbb\x07\x1c\xf9\x16C%azJ+\xd8\xc6\x82ieo\xde'

kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# create a Fernet instance

cipher_suite = Fernet(key)
if args.encrypt:
    try:
        with open("data.data", "rb") as f:
            data = f.read()
    except Exception as e:
        print("failed to open data.png")
        print(e)
        sys.exit(1)

    encrypted_data = cipher_suite.encrypt(data)

    try:
        with open("encrypted.data", "wb") as f:
            f.write(encrypted_data)
    except Exception as e:
        print("failed to write data into encrypted.data")
        print(e)
        sys.exit(1)

    print("encryption successfull")

elif args.decrypt:
    print("staring decryption process")
    try:
        with open("encrypted.data", "rb") as f:
            encrypted_data = f.read()
    except Exception as e:
        print("failed to open encrypted.data")
        print(e)
        sys.exit(1)

    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
    except Exception as e:
        print("wrong key")
        print(e)
        sys.exit(1)

    try:
        with open("decrypted.data", "wb") as f:
            f.write(decrypted_data)
    except Exception as e:
        print("failed to write data.data")
        print(e)
        sys.exit(1)

    print("decryption successfull!")
