#!/usr/bin/env python3

import argparse
import binascii
from os import urandom
from Crypto.Cipher import AES


# -----------------------------
# Padding (PKCS7)
# -----------------------------
def pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# -----------------------------
# Key generation
# -----------------------------
def generate_key():
    key = urandom(32)  # AES-256
    print(binascii.hexlify(key).decode())
    return key


# -----------------------------
# Encryption
# -----------------------------
def encrypt(plaintext: str, key_hex: str):
    key = binascii.unhexlify(key_hex)

    iv = urandom(16)  # NEW IV per encryption (important security fix)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    ciphertext = cipher.encrypt(plaintext.encode())

    print("iv:", binascii.hexlify(iv).decode())
    print("ciphertext:", binascii.hexlify(ciphertext).decode())


# -----------------------------
# Decryption
# -----------------------------
def decrypt(ciphertext_hex: str, key_hex: str, iv_hex: str):
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext)

    print("plaintext:", plaintext.decode(errors="ignore"))


# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="AES Encryption Tool (CFB Mode)")

    parser.add_argument("-m", "--mode", required=True,
                        choices=["generate", "encrypt", "decrypt"])

    parser.add_argument("-p", "--plaintext")
    parser.add_argument("-c", "--ciphertext")
    parser.add_argument("-k", "--key")
    parser.add_argument("-i", "--iv")

    args = parser.parse_args()

    if args.mode == "generate":
        generate_key()

    elif args.mode == "encrypt":
        if not args.plaintext or not args.key:
            raise ValueError("encrypt requires --plaintext and --key")

        encrypt(args.plaintext, args.key)

    elif args.mode == "decrypt":
        if not args.ciphertext or not args.key or not args.iv:
            raise ValueError("decrypt requires --ciphertext, --key, and --iv")

        decrypt(args.ciphertext, args.key, args.iv)


if __name__ == "__main__":
    main()
