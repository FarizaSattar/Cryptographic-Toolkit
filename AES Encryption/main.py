from os import urandom
import binascii
from Crypto.Cipher import AES
import argparse

# AES Encryption, with CFB mode
# AES KEY : 32 bytes
# AES IV : 16 bytes

def aes_generate_key_iv():
    AES_KEY = urandom(32)
    AES_IV = urandom(16)
    print("AES KEY:", binascii.b2a_hex(AES_KEY).decode())
    print("AES IV:", binascii.b2a_hex(AES_IV).decode())

def aes_encrypt(plaintext, AES_KEY, AES_IV):
    plaintext = binascii.a2b_hex(plaintext) # convert hex string to binary
    AES_Cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV) # create a cipher object
    ciphertext = AES_Cipher.encrypt(plaintext) # encrypting
    print("ciphertext:", binascii.b2a_hex(ciphertext).decode())

def aes_decrypt(ciphertext, AES_KEY, AES_IV):
    ciphertext = binascii.a2b_hex(ciphertext) # convert hex string to binary
    AES_Cipher = AES.new(AES_KEY, AES.MODE_CFB, AES_IV) # create a cipher object
    plaintext = AES_Cipher.decrypt(ciphertext) # decrypting
    print("plaintext:", plaintext.decode())

#aes_generate_key_iv()
aes_encrypt("secret message that must be encrypted", "a8fe5d3d847b401de526c4269fde3f306617fbb7fb1d79eeee960159da412faa0", "1e2948a79b7fabbfc8aecd211db2f3f3")

aes_decrypt("48e9b01563773387b260b7f864cabcd0a6b6708e7769bf11b13027d18eec13d61ba12596b08b4", "a8fe5d3d847b401de526c4269fde3f306617fbb7fb1d79eeee960159da412faa0", "1e2948a79b7fabbfc8aecd211db2f3f3")

def main(mode, plaintext, AES_KEY, AES_IV, ciphertext):
  if mode == "aes_generate_key_iv":
      aes_generate_key_iv()
  elif mode == "aes_encrypt":
      aes_encrypt(plaintext, AES_KEY, AES_IV)
  elif mode == "aes_decrypt":
      aes_decrypt(ciphertext, AES_KEY, AES_IV)
  else:
      print("Invalid mode")
      exit(1)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Encryption and Decryption using AES")
  parser.add_argument("-m", "--mode", help="mode can only be: aes_generate_key_iv,aes_encrypt and aes_decrypt")
  parser.add_argument("-p", "--plaintext", help="data to be encrypted")
  parser.add_argument("-c", "--ciphertext", help="data to be decrypted")
  parser.add_argument("-k", "--aes_key", help="AES KEY of size 32 bytes in hexadecimal format")
  parser.add_argument("-i", "--aes_iv", help="AES IV of size 16 bytes in hexadecimal format")

  # get the value of this options
  args = parser.parse_args()
  mode = args.mode
  plaintext = args.plaintext
  ciphertext = args.ciphertext
  AES_KEY = args.aes_key
  AES_IV = args.aes_iv

  main(mode=mode, plaintext=plaintext, AES_KEY=AES_KEY, AES_IV=AES_IV, ciphertext=ciphertext)
  exit(0)
