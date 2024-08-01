from Crypto.PublicKey import RSA
import os, binascii
from Crypto.Cipher import PKCS1_OAEP

def RSA_KEY_generate(key_size):
    try:
        key = RSA.generate(key_size)

        # get private key
        private_key = key.export_key(passphrase="Password_For_Private_Key", pkcs=8, protection="scryptAndAES128-CBC").decode()
        print(private_key)
        fp = open("private_key.pem", "wt")
        fp.write(private_key)
        fp.close()

        # get public key
        public_key = key.publickey().export_key().decode()
        print(public_key)
        fp = open("public_key.pem", "wt")
        fp.write(public_key)
        fp.close()
    except Exception as e:
        print("Error:", e)
        exit(1)

#RSA_KEY_generate(2048)

session_key = os.urandom(32)
print("session_key:", binascii.b2a_hex(session_key).decode())

# get public key
public_key = RSA.import_key(open("public_key.pem").read())

# construct rsa cipher object
rsa_cipher = PKCS1_OAEP.new(public_key)

def RSA_SESSION_KEY_DECRYPT(private_key_file):
    try:
        encrypted_session_key = "71cf2bcecff88d9cdc0cca522a4066ffceca0de86c6e5aec1d06989a8ace16d6bda2e6defeb651fa029ddec3c385990b236b7d73b15fb10fcf6cd363400d0bb192e7815"
        encrypted_session_key = binascii.a2b_hex(encrypted_session_key.encode())

        # get private key
        private_key = RSA.import_key(open(private_key_file).read(), passphrase="Password_For_Private_Key")

        # construct rsa cipher object and decrypt the session key
        rsa_cipher = PKCS1_OAEP.new(private_key)
        session_key = rsa_cipher.decrypt(encrypted_session_key)
        print("decrypted session_key:", binascii.b2a_hex(session_key).decode())
    except Exception as e:
        print("Error:", e)
        exit(1)

RSA_SESSION_KEY_DECRYPT("private_key.pem")

def RSA_SESSION_KEY_ENCRYPT(public_key_file):
    try:
        session_key = os.urandom(32)
        print("session_key:", binascii.b2a_hex(session_key).decode())

        # get public key
        public_key = RSA.import_key(open(public_key_file).read())

        # construct rsa cipher object and encrypt the session key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_session_key = rsa_cipher.encrypt(session_key)
        print("encrypted session_key:", binascii.b2a_hex(encrypted_session_key).decode())
    except Exception as e:
        print("Error:", e)
        exit(1)

#RSA_SESSION_KEY_ENCRYPT("public_key.pem")
