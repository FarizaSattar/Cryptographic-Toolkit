# 🔐 Encryptify
### A hands-on toolkit for understanding how encryption actually works

## 👋 What is this?

Cryptography has always felt like a bit of magic to me — how does a message get scrambled into nonsense and then perfectly unscrambled by exactly one person on the other end? Most tutorials teach encryption algorithms one at a time, in isolation, which makes it hard to see how they actually fit together in things like HTTPS or secure messaging apps.

Encryptify is my attempt to close that gap. It's a Python toolkit that brings together AES (symmetric encryption), RSA (asymmetric encryption), hybrid encryption workflows, and password strength analysis — all in one place, so you can actually see how these pieces work *together*, not just individually.

## ❓ Why I built this

I noticed that most people (myself included, at first!) learn encryption algorithm by algorithm, without ever seeing the bigger picture of *why* real systems combine them the way they do. I wanted to build something that answers not just "how does AES work?" but "why do we pair it with RSA in the first place?" Understanding the *why* behind each piece made the whole subject click for me in a way that isolated tutorials never did.

## 🚀 What it actually does

Encryptify is organized into a few independent, explorable modules:

- **AES Encryption** — encrypt and decrypt messages using fast symmetric encryption.
- **RSA Encryption** — explore public/private key pairs and asymmetric cryptography.
- **Hybrid Encryption** — see how RSA and AES team up: RSA securely exchanges the key, AES efficiently encrypts the actual message.
- **Password Analysis** — evaluate password strength using entropy calculations, and spot common weak-password patterns.

Each module works on its own, so you can dig into exactly the concept you're curious about, or work through all of them to build a complete picture of modern encryption.

## 📈 A quick example — why hybrid encryption exists

Say you want to send someone a confidential message.

Symmetric encryption alone (like AES) is fast, but there's a catch: both people need to already share the same secret key — which is tricky to exchange securely in the first place. Asymmetric encryption (like RSA) solves that key-exchange problem, but it's too slow to encrypt large amounts of data directly.

So modern systems do both, in sequence:

1. Generate a random AES key.
2. Encrypt the actual message with that AES key (fast).
3. Encrypt the *AES key itself* with the recipient's RSA public key (secure).
4. The recipient uses their RSA private key to unlock the AES key.
5. That AES key decrypts the original message.

This is exactly the pattern behind protocols like HTTPS — and walking through it yourself makes it click in a way that reading about it never quite does.

## 👥 Who this is for

- Cybersecurity or computer science students wanting hands-on practice with real cryptographic concepts
- Developers curious how encryption actually works under the hood, not just how to call a library function
- Anyone studying for a security-related interview or course who wants an intuitive mental model of AES, RSA, and hybrid encryption

## 🛠️ What you'll need to run it

**Software:** Python 3.10+, pip, Git (optional)

**Helpful background:** basic Python, an intro-level understanding of symmetric vs. asymmetric encryption, and password hashing concepts — though each module is built to be approachable even if this is your first time exploring cryptography.

## 💡 How it flows, visually

```
User Provides Input
        │
        ▼
Input Validation
        │
        ▼
Select Module
        │
   ┌────┴────┐
   ▼         ▼
AES        Password
Encryption  Analysis
   │         │
   ▼         ▼
Ciphertext  Strength Report
   │
   ▼
(Optional)
RSA Key Exchange
   │
   ▼
Hybrid Encryption Output
```

## ⚠️ A quick honest note

Encryptify is built for learning, not production. These implementations are meant to demonstrate cryptographic principles clearly, not to serve as an audited, battle-tested security library. If you're building something that actually needs strong security guarantees, please use established, professionally audited libraries and follow current best practices instead!

## 🧰 Built with

Python

