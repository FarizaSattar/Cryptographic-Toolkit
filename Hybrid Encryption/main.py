#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import binascii
import argparse


# -----------------------------
# RSA Key Generation
# -----------------------------
def generate_rsa_keys(key_size: int, private_file: str, public_file: str, passphrase: str):
    try:
        key = RSA.generate(key_size)

        private_key = key.export_key(
            passphrase=passphrase,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )

        public_key = key.publickey().export_key()

        with open(private_file, "wb") as f:
            f.write(private_key)

        with open(public_file, "wb") as f:
            f.write(public_key)

        print("[+] RSA key pair generated successfully")

    except Exception as e:
        raise RuntimeError(f"Key generation failed: {e}")


# -----------------------------
# Encrypt session key with RSA
# -----------------------------
def encrypt_session_key(public_key_file: str):
    try:
        session_key = os.urandom(32)

        with open(public_key_file, "rb") as f:
            public_key = RSA.import_key(f.read())

        cipher = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher.encrypt(session_key)

        print("session_key (hex):", binascii.hexlify(session_key).decode())
        print("encrypted_session_key (hex):", binascii.hexlify(encrypted_key).decode())

        return encrypted_key

    except Exception as e:
        raise RuntimeError(f"Encryption failed: {e}")


# -----------------------------
# Decrypt session key with RSA
# -----------------------------
def decrypt_session_key(private_key_file: str, passphrase: str, encrypted_hex: str):
    try:
        encrypted_key = binascii.unhexlify(encrypted_hex)

        with open(private_key_file, "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase=passphrase)

        cipher = PKCS1_OAEP.new(private_key)
        decrypted_key = cipher.decrypt(encrypted_key)

        print("decrypted_session_key (hex):", binascii.hexlify(decrypted_key).decode())

        return decrypted_key

    except Exception as e:
        raise RuntimeError(f"Decryption failed: {e}")


# -----------------------------
# CLI Interface
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Hybrid RSA Session Key Encryption Tool")

    parser.add_argument("-m", "--mode", required=True,
                        choices=["gen", "encrypt", "decrypt"])

    parser.add_argument("-k", "--keysize", type=int, default=2048)

    parser.add_argument("-pr", "--private", default="private_key.pem")
    parser.add_argument("-pu", "--public", default="public_key.pem")

    parser.add_argument("-p", "--passphrase", default="Password_For_Private_Key")

    parser.add_argument("-e", "--encrypted")

    args = parser.parse_args()

    if args.mode == "gen":
        generate_rsa_keys(args.keysize, args.private, args.public, args.passphrase)

    elif args.mode == "encrypt":
        encrypt_session_key(args.public)

    elif args.mode == "decrypt":
        if not args.encrypted:
            raise ValueError("Encrypted hex must be provided using -e")

        decrypt_session_key(args.private, args.passphrase, args.encrypted)


if __name__ == "__main__":
    main()
