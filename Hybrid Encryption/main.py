from Crypto.PublicKey import RSA  # Import RSA for generating and managing RSA keys
import os  # Import os for generating random data (e.g., session keys)
import binascii  # Import binascii for converting between binary and ASCII
from Crypto.Cipher import PKCS1_OAEP  # Import PKCS1_OAEP for RSA encryption and decryption

# A Python script for generating RSA keys, encrypting, and decrypting session keys using RSA with PKCS1_OAEP.

# Function to generate RSA key pair and save to PEM files
def RSA_KEY_generate(key_size):
    try:
        key = RSA.generate(key_size)  # Generate an RSA key pair with the specified size

        # Get the private key and export it with protection, save to a file
        private_key = key.export_key(passphrase="Password_For_Private_Key", pkcs=8, protection="scryptAndAES128-CBC").decode()
        print(private_key)
        fp = open("private_key.pem", "wt")  # Open file to write the private key
        fp.write(private_key)  # Write private key to file
        fp.close()  # Close the file

        # Get the public key and save it to a file
        public_key = key.publickey().export_key().decode()
        print(public_key)
        fp = open("public_key.pem", "wt")  # Open file to write the public key
        fp.write(public_key)  # Write public key to file
        fp.close()  # Close the file
    except Exception as e:
        print("Error:", e)  # Print the error message if something goes wrong
        exit(1)  # Exit with an error status

# Example usage: Uncomment to generate a 2048-bit RSA key pair
# RSA_KEY_generate(2048)

# Generate a random 32-byte session key and print it
session_key = os.urandom(32)  # Generate a 32-byte random session key
print("session_key:", binascii.b2a_hex(session_key).decode())  # Convert session key to hex and print

# Load the public key from the PEM file
public_key = RSA.import_key(open("public_key.pem").read())  # Import the public key from a file

# Construct RSA cipher object using PKCS1_OAEP for encryption
rsa_cipher = PKCS1_OAEP.new(public_key)  # Create a new cipher object for encryption with RSA and OAEP

# Function to decrypt an encrypted session key using a private key
def RSA_SESSION_KEY_DECRYPT(private_key_file):
    try:
        # Simulated encrypted session key in hexadecimal format
        encrypted_session_key = "71cf2bcecff88d9cdc0cca522a4066ffceca0de86c6e5aec1d06989a8ace16d6bda2e6defeb651fa029ddec3c385990b236b7d73b15fb10fcf6cd363400d0bb192e7815"
        encrypted_session_key = binascii.a2b_hex(encrypted_session_key.encode())  # Convert hex to binary

        # Load the private key from the PEM file
        private_key = RSA.import_key(open(private_key_file).read(), passphrase="Password_For_Private_Key")

        # Construct RSA cipher object using PKCS1_OAEP for decryption and decrypt the session key
        rsa_cipher = PKCS1_OAEP.new(private_key)  # Create a new cipher object for decryption
        session_key = rsa_cipher.decrypt(encrypted_session_key)  # Decrypt the encrypted session key
        print("decrypted session_key:", binascii.b2a_hex(session_key).decode())  # Convert decrypted key to hex and print
    except Exception as e:
        print("Error:", e)  # Print the error message if something goes wrong
        exit(1)  # Exit with an error status

# Example usage: Decrypt session key using the private key
RSA_SESSION_KEY_DECRYPT("private_key.pem")

# Function to encrypt a session key using a public key
def RSA_SESSION_KEY_ENCRYPT(public_key_file):
    try:
        session_key = os.urandom(32)  # Generate a 32-byte random session key
        print("session_key:", binascii.b2a_hex(session_key).decode())  # Convert session key to hex and print

        # Load the public key from the PEM file
        public_key = RSA.import_key(open(public_key_file).read())  # Import the public key from a file

        # Construct RSA cipher object using PKCS1_OAEP for encryption and encrypt the session key
        rsa_cipher = PKCS1_OAEP.new(public_key)  # Create a new cipher object for encryption
        encrypted_session_key = rsa_cipher.encrypt(session_key)  # Encrypt the session key
        print("encrypted session_key:", binascii.b2a_hex(encrypted_session_key).decode())  # Convert encrypted key to hex and print
    except Exception as e:
        print("Error:", e)  # Print the error message if something goes wrong
        exit(1)  # Exit with an error status

# Example usage: Uncomment to encrypt a session key using the public key
# RSA_SESSION_KEY_ENCRYPT("public_key.pem")
