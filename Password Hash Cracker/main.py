#!/usr/bin/python3
import binascii  # Import binascii for binary-to-ASCII conversions
import hashlib  # Import hashlib for various hashing algorithms
from passlib.hash import mysql323, mysql41, mssql2005, postgres_md5, oracle10, oracle11  # Import database-specific hashing functions from passlib
from passlib.hash import lmhash, nthash, msdcc, msdcc2  # Import Windows-specific hashing functions from passlib
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, sha512_crypt, sha256_crypt, bcrypt  # Import other common hashing functions from passlib
from os import urandom  # Import urandom for generating secure random numbers
import time  # Import time for measuring execution time
import argparse  # Import argparse for command-line argument parsing
import threading  # Import threading for multithreading support
import queue  # Import queue to manage the list of tasks for threads
import sys  # Import sys for handling system-specific functions

# A script for hashing and cracking passwords using various algorithms, with multithreading support for faster cracking.

# Define color codes for printing
R = "\033[1;31m"  # Red color for error or critical messages
Y = "\033[1;33m"  # Yellow color for warning or caution messages
C = "\033[1;36m"  # Cyan color for informational or neutral messages
W = "\033[0m"     # White color for reset to default terminal color

# Define available hashing algorithms
hashing_algorithms_1 = ['md4', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']  # Common hashing algorithms
hashing_algorithms_2 = hashing_algorithms_1 + ['mdc2', 'ripemd160']  # Additional algorithms including mdc2 and ripemd160
hashing_algorithms_3 = ['bcrypt', 'sha256_crypt', 'sha512_crypt', 'mysql', 'mysql323', 'mysql41', 'msql2000', 'msql2005', 'oracle10']  # More specific algorithms for databases and secure hashing

# Function to hash a password using various algorithms
def password_hash(password):
    utf_password = password.encode("UTF-8")  # Convert the password to UTF-8 encoding
    username = 'administrator'  # Default username for salt in some algorithms
    utf_username = username.encode("UTF-8")  # Convert the username to UTF-8 encoding

    # Encode the password in Base64 and Hex formats
    base64_password = binascii.b2a_base64(utf_password)
    hex_password = binascii.b2a_hex(utf_password)
    print("base64: ", base64_password.decode("UTF-8").strip("\n"))  # Print Base64-encoded password
    print("hex :", hex_password.decode("UTF-8").strip("\n"))  # Print Hex-encoded password
    print("\n")

    # Hash the password using common algorithms
    for hashing_algorithm in hashing_algorithms_1:
        password_hash = hashlib.new(hashing_algorithm, utf_password).hexdigest()  # Hash the password
        print(hashing_algorithm, " " * (15 - len(hashing_algorithm)), C, password_hash, 'hash_length_in_bytes:', int(len(password_hash) / 2))  # Print the hash and its length in bytes
    print("\n")

    # Hash the password using SQL-specific algorithms
    print("mysql323 :", C, mysql323.hash(utf_password), W)  # MySQL 3.2.3 hash
    print("mysql41 :", C, mysql41.hash(utf_password), W)  # MySQL 4.1 hash
    print("mssql2005 :", C, mssql2005.hash(utf_password), W)  # Microsoft SQL Server 2005 hash
    print("postgres_md5 :", C, postgres_md5.hash(utf_password), W)  # PostgreSQL MD5 hash
    print("oracle10 :", C, oracle10.hash(utf_password), W)  # Oracle 10g hash
    print("oracle11 :", C, oracle11.hash(utf_password), W)  # Oracle 11g hash
    print("\n")

    # Hash the password using Windows-specific algorithms
    print("Window LM hash :", C, lmhash.hash(utf_password), W)  # Windows LM hash
    print("Window NT hash :", C, nthash.hash(utf_password), W)  # Windows NT hash
    print("Window MSCCASH hash :", C, msdcc.hash(utf_password, user=utf_username), W)  # Windows MSCCASH hash
    print("Window MSCASH2 hash :", C, msdcc2.hash(utf_password, user=utf_username), W)  # Windows MSCASH2 hash
    print("\n")

    # Generate a random salt
    salt = urandom(32)  # Generate a 32-byte random salt
    decoded_salt = binascii.b2a_base64(salt).decode().strip()  # Convert the salt to Base64 and decode it
    decoded_salt = decoded_salt.replace("+", ".").replace("=", "")  # Replace certain characters to fit hashing algorithms
    print("salt : ", decoded_salt)  # Print the salt
    print("\n")

    # Hash the password with PBKDF2 and crypt algorithms using the salt
    T1 = time.time()
    print("pbkdf2_sha256 :", C, pbkdf2_sha256.hash(utf_password, rounds=100200, salt=salt), R, time.time() - T1, W, "seconds")  # PBKDF2-SHA256 hash
    T1 = time.time()
    print("pbkdf2_sha512 :", C, pbkdf2_sha512.hash(utf_password, rounds=100200, salt=salt), R, time.time() - T1, W, "seconds")  # PBKDF2-SHA512 hash

    sha512_crypt_salt = decoded_salt[:16]  # Shorten the salt for sha512_crypt
    T1 = time.time()
    print("sha512_crypt :", C, sha512_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), R, time.time() - T1, W, "seconds")  # SHA-512 crypt hash
    T1 = time.time()
    print("sha256_crypt :", C, sha256_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), R, time.time() - T1, W, "seconds")  # SHA-256 crypt hash

    bsd_salt = decoded_salt[:22]  # Shorten the salt for bcrypt
    bsd_salt = bsd_salt.replace(bsd_salt[21], ".")  # Adjust the salt format for bcrypt
    T1 = time.time()
    print("bcrypt:", C, bcrypt.hash(utf_password, rounds=12, salt=bsd_salt), R, time.time() - T1, W, "seconds")  # bcrypt hash

# Function to crack a hashed password by comparing it to a wordlist
def password_crack(passwordhash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt):
    while not q.empty():  # Continue until the queue is empty
        word = q.get()  # Get the next word from the queue
        utf_word = word.encode("UTF-8")  # Convert the word to UTF-8 encoding

        # Check against native hashing algorithms
        if hashing_algorithm in hashing_algorithms_1:
            hash_word = hashlib.new(hashing_algorithm, utf_word).hexdigest()  # Hash the word using the specified algorithm
            if hash_word == passwordhash:  # Check if the hash matches the target hash
                print(f"Password found: {word}")  # Print the found password
                return
        # Check against other hashing algorithms using passlib
        else:
            if hashing_algorithm == 'bcrypt':
                if bcrypt.verify(utf_word, passwordhash):  # Verify the hash using bcrypt
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'sha256_crypt':
                if sha256_crypt.verify(utf_word, passwordhash):  # Verify the hash using sha256_crypt
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'sha512_crypt':
                if sha512_crypt.verify(utf_word, passwordhash):  # Verify the hash using sha512_crypt
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mysql323':
                if mysql323.verify(utf_word, passwordhash):  # Verify the hash using mysql323
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mysql41':
                if mysql41.verify(utf_word, passwordhash):  # Verify the hash using mysql41
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mssql2005':
                if mssql2005.verify(utf_word, passwordhash):  # Verify the hash using mssql2005
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'postgres_md5':
                if postgres_md5.verify(utf_word, passwordhash):  # Verify the hash using postgres_md5
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'oracle10':
                if oracle10.verify(utf_word, passwordhash):  # Verify the hash using oracle10
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'lmhash':
                if lmhash.verify(utf_word, passwordhash):  # Verify the hash using lmhash
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'nthash':
                if nthash.verify(utf_word, passwordhash):  # Verify the hash using nthash
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'msdcc':
                if msdcc.verify(utf_word, passwordhash, user=username_salt):  # Verify the hash using msdcc
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'msdcc2':
                if msdcc2.verify(utf_word, passwordhash, user=username_salt):  # Verify the hash using msdcc2
                    print(f"Password found: {word}")
                    return
            else:
                pass
        q.task_done()  # Mark the task as done

# Setup argument parser for command-line usage
parser = argparse.ArgumentParser(description="Password Hasher and Cracker")  # Create a parser object with description
parser.add_argument("-m", "--mode", required=True, choices=['hash', 'crack'], help="Mode: hash or crack")  # Add mode argument
parser.add_argument("-p", "--password", required=True, help="Password to hash or hash to crack")  # Add password argument
parser.add_argument("-a", "--algorithm", help="Hashing algorithm for cracking")  # Add algorithm argument for cracking mode
parser.add_argument("-w", "--wordlist", help="Wordlist for cracking mode")  # Add wordlist argument for cracking mode
parser.add_argument("-s", "--salt", help="Salt for specific algorithms (e.g., msdcc, msdcc2)")  # Add salt argument for algorithms requiring it
args = parser.parse_args()  # Parse the arguments

# Execute the appropriate function based on the mode argument
if args.mode == 'hash':
    password_hash(args.password)  # Hash the password
elif args.mode == 'crack':
    if not args.algorithm or not args.wordlist:  # Ensure algorithm and wordlist are provided for cracking
        print(R + "Error: --algorithm and --wordlist are required for cracking mode." + W)  # Print error message
        sys.exit(1)  # Exit the program with an error code

    q = queue.Queue()  # Create a queue to hold the wordlist
    with open(args.wordlist, "r") as file:
        for line in file:  # Read each line in the wordlist
            q.put(line.strip())  # Add the line to the queue

    # Start cracking the password with threading
    threads = []
    for i in range(8):  # Start 8 threads for cracking
        t = threading.Thread(target=password_crack, args=(args.password, args.algorithm, hashing_algorithms_1, hashing_algorithms_2, args.salt))
        t.start()  # Start the thread
        threads.append(t)  # Add the thread to the list

    for t in threads:
        t.join()  # Wait for all threads to finish
    q.join()  # Wait for the queue to be empty
