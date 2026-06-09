#!/usr/bin/env python3

import argparse
import hashlib
import threading
import queue
import sys
import time

from passlib.hash import (
    mysql323, mysql41, mssql2005, postgres_md5,
    oracle10, oracle11, lmhash, nthash,
    msdcc, msdcc2, pbkdf2_sha256, pbkdf2_sha512,
    sha512_crypt, sha256_crypt, bcrypt
)


# -----------------------------
# Hash registry (clean dispatch)
# -----------------------------
HASH_FNS = {
    "md5": lambda x: hashlib.md5(x).hexdigest(),
    "sha1": lambda x: hashlib.sha1(x).hexdigest(),
    "sha224": lambda x: hashlib.sha224(x).hexdigest(),
    "sha256": lambda x: hashlib.sha256(x).hexdigest(),
    "sha384": lambda x: hashlib.sha384(x).hexdigest(),
    "sha512": lambda x: hashlib.sha512(x).hexdigest(),
}


PASSLIB_FNS = {
    "bcrypt": bcrypt,
    "sha256_crypt": sha256_crypt,
    "sha512_crypt": sha512_crypt,
    "mysql323": mysql323,
    "mysql41": mysql41,
    "mssql2005": mssql2005,
    "postgres_md5": postgres_md5,
    "oracle10": oracle10,
    "oracle11": oracle11,
    "lmhash": lmhash,
    "nthash": nthash,
    "msdcc": msdcc,
    "msdcc2": msdcc2,
}


# -----------------------------
# Globals (thread-safe usage)
# -----------------------------
q = queue.Queue()
found_event = threading.Event()


# -----------------------------
# HASH MODE
# -----------------------------
def hash_password(password: str, algorithm: str):
    data = password.encode()

    if algorithm in HASH_FNS:
        print(f"[+] {algorithm}: {HASH_FNS[algorithm](data)}")
        return

    if algorithm in PASSLIB_FNS:
        result = PASSLIB_FNS[algorithm].hash(password)
        print(f"[+] {algorithm}: {result}")
        return

    raise ValueError("Unsupported algorithm")


# -----------------------------
# WORKER (cracking)
# -----------------------------
def worker(target_hash, algorithm, salt):
    while not q.empty() and not found_event.is_set():
        try:
            word = q.get_nowait()
        except queue.Empty:
            return

        data = word.encode()

        try:
            # native hashlib
            if algorithm in HASH_FNS:
                if HASH_FNS[algorithm](data) == target_hash:
                    print(f"[✔] Password FOUND: {word}")
                    found_event.set()

            # passlib-based verification
            else:
                handler = PASSLIB_FNS.get(algorithm)
                if not handler:
                    return

                if algorithm in ["msdcc", "msdcc2"]:
                    if handler.verify(word, target_hash, user=salt):
                        print(f"[✔] Password FOUND: {word}")
                        found_event.set()
                else:
                    if handler.verify(word, target_hash):
                        print(f"[✔] Password FOUND: {word}")
                        found_event.set()

        finally:
            q.task_done()


# -----------------------------
# CRACK MODE
# -----------------------------
def crack_password(target_hash, algorithm, wordlist, salt, threads=6):
    start = time.time()

    with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            q.put(line.strip())

    workers = []
    for _ in range(threads):
        t = threading.Thread(
            target=worker,
            args=(target_hash, algorithm, salt)
        )
        t.start()
        workers.append(t)

    for t in workers:
        t.join()

    q.join()

    if not found_event.is_set():
        print("[-] Password not found in wordlist")

    print(f"[+] Time: {time.time() - start:.2f}s")


# -----------------------------
# CLI
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Password Hash Tool")

    parser.add_argument("-m", "--mode", required=True,
                        choices=["hash", "crack"])

    parser.add_argument("-p", "--password", required=True,
                        help="Password (hash mode) or hash (crack mode)")

    parser.add_argument("-a", "--algorithm", required=True,
                        help="Hash algorithm")

    parser.add_argument("-w", "--wordlist",
                        help="Wordlist for cracking mode")

    parser.add_argument("-s", "--salt",
                        help="Salt (needed for some algorithms)")

    args = parser.parse_args()

    if args.mode == "hash":
        hash_password(args.password, args.algorithm)

    elif args.mode == "crack":
        if not args.wordlist:
            print("[-] Wordlist required for cracking")
            sys.exit(1)

        crack_password(
            target_hash=args.password,
            algorithm=args.algorithm,
            wordlist=args.wordlist,
            salt=args.salt
        )


if __name__ == "__main__":
    main()
