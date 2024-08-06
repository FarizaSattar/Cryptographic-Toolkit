#!/usr/bin/python3

# Import libraries for various functionalities:
from os import urandom  # Provides functions to generate secure random numbers
import binascii  # Allows conversion between binary and ASCII (Base64 and Hex) formats
from Crypto.Cipher import AES  # Implements the AES encryption algorithm in various modes (CFB in this case)
import argparse  # Facilitates parsing command-line arguments for script execution

# A Python script for generating AES keys, and encrypting and decrypting data using AES in CFB mode.

# Function to generate a random AES key and initialization vector (IV)
def aes_generate_key_iv():
    AES_KEY = urandom(32)  # Generate a 32-byte AES key (suitable for AES-256)
    AES_IV = urandom(16)   # Generate a 16-byte AES initialization vector (IV)
    print("AES KEY:", binascii.b2a_hex(AES_KEY).decode())  # Print the AES key in hexadecimal format
    print("AES IV:", binascii.b2a_hex(AES_IV).decode())    # Print the AES IV in hexadecimal format

# Function to encrypt plaintext using AES with CFB mode
def aes_encrypt(plaintext, AES_KEY, AES_IV):
    plaintext = binascii.a2b_hex(plaintext)  # Convert the plaintext from a hex string to binary data
    AES_Cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV)  # Create a new AES cipher object using CFB mode
    ciphertext = AES_Cipher.encrypt(plaintext)  # Encrypt the plaintext using the AES cipher
    print("ciphertext:", binascii.b2a_hex(ciphertext).decode())  # Print the ciphertext in hexadecimal format

# Function to decrypt ciphertext using AES with CFB mode
def aes_decrypt(ciphertext, AES_KEY, AES_IV):
    ciphertext = binascii.a2b_hex(ciphertext)  # Convert the ciphertext from a hex string to binary data
    AES_Cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV)  # Create a new AES cipher object using CFB mode
    plaintext = AES_Cipher.decrypt(ciphertext)  # Decrypt the ciphertext using the AES cipher
    print("plaintext:", plaintext.decode())  # Print the decrypted plaintext

# Example usage of encrypting and decrypting with hardcoded values (can be commented out or used for testing purposes)
#aes_generate_key_iv()  # Uncomment this line to generate and display a random AES key and IV
aes_encrypt("secret message that must be encrypted", "a8fe5d3d847b401de526c4269fde3f306617fbb7fb1d79eeee960159da412faa0", "1e2948a79b7fabbfc8aecd211db2f3f3")  # Encrypt the message
aes_decrypt("48e9b01563773387b260b7f864cabcd0a6b6708e7769bf11b13027d18eec13d61ba12596b08b4", "a8fe5d3d847b401de526c4269fde3f306617fbb7fb1d79eeee960159da412faa0", "1e2948a79b7fabbfc8aecd211db2f3f3")  # Decrypt the message

# Main function to handle command-line arguments and call the appropriate functions
def main(mode, plaintext, AES_KEY, AES_IV, ciphertext):
    if mode == "aes_generate_key_iv":
        aes_generate_key_iv()  # Call the key and IV generation function
    elif mode == "aes_encrypt":
        aes_encrypt(plaintext, AES_KEY, AES_IV)  # Call the encryption function
    elif mode == "aes_decrypt":
        aes_decrypt(ciphertext, AES_KEY, AES_IV)  # Call the decryption function
    else:
        print("Invalid mode")  # Print an error message if the mode is invalid
        exit(1)  # Exit the program with an error status

# Entry point of the script, parses command-line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encryption and Decryption using AES")  # Set up the argument parser
    parser.add_argument("-m", "--mode", help="mode can only be: aes_generate_key_iv, aes_encrypt, or aes_decrypt")  # Define the mode argument
    parser.add_argument("-p", "--plaintext", help="data to be encrypted")  # Define the plaintext argument for encryption
    parser.add_argument("-c", "--ciphertext", help="data to be decrypted")  # Define the ciphertext argument for decryption
    parser.add_argument("-k", "--aes_key", help="AES KEY of size 32 bytes in hexadecimal format")  # Define the AES key argument
    parser.add_argument("-i", "--aes_iv", help="AES IV of size 16 bytes in hexadecimal format")  # Define the AES IV argument

    # Get the value of the options
    args = parser.parse_args()  # Parse the command-line arguments
    mode = args.mode  # Store the mode value
    plaintext = args.plaintext  # Store the plaintext value
    ciphertext = args.ciphertext  # Store the ciphertext value
    AES_KEY = args.aes_key  # Store the AES key value
    AES_IV = args.aes_iv  # Store the AES IV value

    # Call the main function with parsed arguments
    main(mode=mode, plaintext=plaintext, AES_KEY=AES_KEY, AES_IV=AES_IV, ciphertext=ciphertext)  # Execute the main function
    exit(0)  # Exit the script with a success status
