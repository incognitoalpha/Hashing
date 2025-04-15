import hashlib
import bcrypt
import time
import string
import itertools
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# ========== Hashing Functions ==========
def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def hash_argon2(password):
    ph = PasswordHasher()
    return ph.hash(password)

# ========== Brute-Force Attacks ==========
def brute_force_attack_hashlib(target_hash, hash_func, max_length=4):
    charset = string.ascii_lowercase
    attempts = 0
    start = time.time()
    for length in range(1, max_length + 1):
        for guess_tuple in itertools.product(charset, repeat=length):
            guess = ''.join(guess_tuple)
            attempts += 1
            if hash_func(guess) == target_hash:
                return guess, attempts, time.time() - start
    return None, attempts, time.time() - start

def brute_force_attack_bcrypt(target_hash, max_length=4):
    charset = string.ascii_lowercase
    attempts = 0
    start = time.time()
    for length in range(1, max_length + 1):
        for guess_tuple in itertools.product(charset, repeat=length):
            guess = ''.join(guess_tuple)
            attempts += 1
            if bcrypt.checkpw(guess.encode(), target_hash):
                return guess, attempts, time.time() - start
    return None, attempts, time.time() - start

def brute_force_attack_argon2(target_hash, max_length=3):
    charset = string.ascii_lowercase
    attempts = 0
    ph = PasswordHasher()
    start = time.time()
    for length in range(1, max_length + 1):
        for guess_tuple in itertools.product(charset, repeat=length):
            guess = ''.join(guess_tuple)
            attempts += 1
            try:
                if ph.verify(target_hash, guess):
                    return guess, attempts, time.time() - start
            except argon2_exceptions.VerifyMismatchError:
                continue
            except argon2_exceptions.VerificationError:
                continue
    return None, attempts, time.time() - start

# ========== Dictionary Attacks ==========
def dictionary_attack_hashlib(target_hash, hash_func, dictionary_file):
    attempts = 0
    start = time.time()
    with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            attempts += 1
            if hash_func(word) == target_hash:
                return word, attempts, time.time() - start
    return None, attempts, time.time() - start

def dictionary_attack_bcrypt(target_hash, dictionary_file):
    attempts = 0
    start = time.time()
    with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            attempts += 1
            if bcrypt.checkpw(word.encode(), target_hash):
                return word, attempts, time.time() - start
    return None, attempts, time.time() - start

def dictionary_attack_argon2(target_hash, dictionary_file):
    ph = PasswordHasher()
    attempts = 0
    start = time.time()
    with open(dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            word = line.strip()
            attempts += 1
            try:
                if ph.verify(target_hash, word):
                    return word, attempts, time.time() - start
            except argon2_exceptions.VerifyMismatchError:
                continue
    return None, attempts, time.time() - start

# ========== Main ==========
def main():
    password = "abc"
    dictionary_file = "dictionary.txt"

    print("Original Password:", password)

    # Hashing
    md5_hash = hash_md5(password)
    sha256_hash = hash_sha256(password)
    bcrypt_hash = hash_bcrypt(password)
    argon2_hash = hash_argon2(password)

    print("\nHashed Values:")
    print("MD5:     ", md5_hash)
    print("SHA-256: ", sha256_hash)
    print("bcrypt:  ", bcrypt_hash)
    print("Argon2:  ", argon2_hash)

    print("\n[ Brute Force Attack ]")
    crack, attempts, duration = brute_force_attack_hashlib(md5_hash, hash_md5)
    print(f"MD5 cracked: {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = brute_force_attack_hashlib(sha256_hash, hash_sha256)
    print(f"SHA-256 cracked: {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = brute_force_attack_bcrypt(bcrypt_hash)
    print(f"bcrypt cracked: {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = brute_force_attack_argon2(argon2_hash)
    print(f"Argon2 cracked: {crack} in {attempts} tries, {duration:.2f}s")

    print("\n[ Dictionary Attack ]")
    crack, attempts, duration = dictionary_attack_hashlib(md5_hash, hash_md5, dictionary_file)
    print(f"MD5 cracked (dict): {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = dictionary_attack_hashlib(sha256_hash, hash_sha256, dictionary_file)
    print(f"SHA-256 cracked (dict): {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = dictionary_attack_bcrypt(bcrypt_hash, dictionary_file)
    print(f"bcrypt cracked (dict): {crack} in {attempts} tries, {duration:.2f}s")

    crack, attempts, duration = dictionary_attack_argon2(argon2_hash, dictionary_file)
    print(f"Argon2 cracked (dict): {crack} in {attempts} tries, {duration:.2f}s")

if __name__ == "__main__":
    main()
