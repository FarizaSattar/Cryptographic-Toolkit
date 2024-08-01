#!/usr/bin/python3
import binascii
import hashlib
from passlib.hash import mysql323, mysql41, mssql2005, postgres_md5, oracle10, oracle11
from passlib.hash import lmhash, nthash, msdcc, msdcc2
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, sha512_crypt, sha256_crypt, bcrypt
from os import urandom
import time, argparse, threading, queue, sys

# Define color codes for printing
R = "\033[1;31m"  # red color
Y = "\033[1;33m"  # yellow color
C = "\033[1;36m"  # cyan color
W = "\033[0m"     # white color

# Define available hashing algorithms
hashing_algorithms_1 = ['md4', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
hashing_algorithms_2 = hashing_algorithms_1 + ['mdc2', 'ripemd160']
hashing_algorithms_3 = ['bcrypt', 'sha256_crypt', 'sha512_crypt', 'mysql', 'mysql323', 'mysql41', 'msql2000', 'msql2005', 'oracle10']

def password_hash(password):
    utf_password = password.encode("UTF-8")
    username = 'administrator'
    utf_username = username.encode("UTF-8")

    # Encode the password
    base64_password = binascii.b2a_base64(utf_password)
    hex_password = binascii.b2a_hex(utf_password)
    print("base64: ", base64_password.decode("UTF-8").strip("\n"))
    print("hex :", hex_password.decode("UTF-8").strip("\n"))
    print("\n")

    # Hash the password using various algorithms
    for hashing_algorithm in hashing_algorithms_1:
        password_hash = hashlib.new(hashing_algorithm, utf_password).hexdigest()
        print(hashing_algorithm, " " * (15 - len(hashing_algorithm)), C, password_hash, 'hash_length_in_bytes:', int(len(password_hash) / 2))
    print("\n")

    # SQL hashing functions
    print("mysql323 :", C, mysql323.hash(utf_password), W)
    print("mysql41 :", C, mysql41.hash(utf_password), W)
    print("mssql2005 :", C, mssql2005.hash(utf_password), W)
    print("postgres_md5 :", C, postgres_md5.hash(utf_password), W)
    print("oracle10 :", C, oracle10.hash(utf_password), W)
    print("oracle11 :", C, oracle11.hash(utf_password), W)
    print("\n")

    # Windows hashing functions
    print("Window LM hash :", C, lmhash.hash(utf_password), W)
    print("Window NT hash :", C, nthash.hash(utf_password), W)
    print("Window MSCCASH hash :", C, msdcc.hash(utf_password, user=utf_username), W)
    print("Window MSCASH2 hash :", C, msdcc2.hash(utf_password, user=utf_username), W)
    print("\n")

    # Generate a random salt
    salt = urandom(32)
    decoded_salt = binascii.b2a_base64(salt).decode().strip()
    decoded_salt = decoded_salt.replace("+", ".").replace("=", "")
    print("salt : ", decoded_salt)
    print("\n")

    # Password hashing with various algorithms
    T1 = time.time()
    print("pbkdf2_sha256 :", C, pbkdf2_sha256.hash(utf_password, rounds=100200, salt=salt), R, time.time() - T1, W, "seconds")
    T1 = time.time()
    print("pbkdf2_sha512 :", C, pbkdf2_sha512.hash(utf_password, rounds=100200, salt=salt), R, time.time() - T1, W, "seconds")

    sha512_crypt_salt = decoded_salt[:16]
    T1 = time.time()
    print("sha512_crypt :", C, sha512_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), R, time.time() - T1, W, "seconds")
    T1 = time.time()
    print("sha256_crypt :", C, sha256_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), R, time.time() - T1, W, "seconds")

    bsd_salt = decoded_salt[:22]
    bsd_salt = bsd_salt.replace(bsd_salt[21], ".")
    T1 = time.time()
    print("bcrypt:", C, bcrypt.hash(utf_password, rounds=12, salt=bsd_salt), R, time.time() - T1, W, "seconds")

def password_crack(passwordhash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt):
    # Function to crack the password hash
    while not q.empty():
        word = q.get()
        utf_word = word.encode("UTF-8")

        # Check against native hashing algorithms
        if hashing_algorithm in hashing_algorithms_1:
            hash_word = hashlib.new(hashing_algorithm, utf_word).hexdigest()
            if hash_word == passwordhash:
                print(f"Password found: {word}")
                return
        # Check against other hashing algorithms using passlib
        else:
            if hashing_algorithm == 'bcrypt':
                if bcrypt.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'sha256_crypt':
                if sha256_crypt.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'sha512_crypt':
                if sha512_crypt.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mysql323':
                if mysql323.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mysql41':
                if mysql41.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'mssql2005':
                if mssql2005.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'postgres_md5':
                if postgres_md5.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'oracle10':
                if oracle10.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'oracle11':
                if oracle11.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'lmhash':
                if lmhash.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'nthash':
                if nthash.verify(utf_word, passwordhash):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'msdcc':
                if msdcc.verify(utf_word, passwordhash, user=username_salt):
                    print(f"Password found: {word}")
                    return
            elif hashing_algorithm == 'msdcc2':
                if msdcc2.verify(utf_word, passwordhash, user=username_salt):
                    print(f"Password found: {word}")
                    return
        q.task_done()

def main(mode, password, passwordhash, hashing_algorithm, n_threads, wordlist, username_salt):
    if mode == 'hashing':
        password_hash(password)
    elif mode == 'cracking':
        global q
        try:
            # Fill the queue with all wordlist items
            with open(wordlist) as wordlist_items:
                for wordlist_item in wordlist_items:
                    q.put(wordlist_item.strip())
        except FileNotFoundError:
            print("\nError: dictionary file not found.\n")
            sys.exit()
        if hashing_algorithm not in hashing_algorithms_2 and hashing_algorithm not in hashing_algorithms_3:
            print("\nError: invalid hashing algorithm.\n")
            sys.exit()
        if hashing_algorithm in hashing_algorithms_3 and username_salt is None:
            print("\nError: hashing algorithm require a username as a salt.\n")
            sys.exit()

        # Start the threads
        for i in range(n_threads):
            # Create a new thread
            worker = threading.Thread(target=password_crack, args=(passwordhash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt))
            worker.daemon = True  # A daemon thread is needed that will end when the main thread ends
            worker.start()  # Start the new thread
    else:
        print("\nmode can be only hashing or cracking.\n")
        sys.exit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="password hash generator and cracker")
    parser.add_argument("-m", "--mode", help="hash or cracking mode")
    parser.add_argument("-p", "--password", help="password to be hashed")
    parser.add_argument("-P", "--passwordhash", help="password hash to be cracked")
    parser.add_argument("-a", "--hashing_algorithm", help="hashing algorithm to be used for cracking")
    parser.add_argument("-w", "--wordlist", help="dictionary file to be used for password hash cracking")
    parser.add_argument("-U", "--username_salt", help="username to be used as a salt in hashing functions like msdcc, postgres_md5, and oracle10")
    parser.add_argument("-t", "--num_threads", type=int, default=1, help="number of threads to use in cracking")

    args = parser.parse_args()
    mode = args.mode
    password = args.password
    passwordhash = args.passwordhash
    hashing_algorithm = args.hashing_algorithm
    wordlist = args.wordlist
    num_threads = args.num_threads
    username_salt = args.username_salt

    main(mode, password, passwordhash, hashing_algorithm, num_threads, wordlist, username_salt)
    sys.exit()
