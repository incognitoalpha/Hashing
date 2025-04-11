import hashlib
import bcrypt
import time
import itertools
import string

# ============================================
# Hashing Functions
# ============================================

def hash_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_bcrypt(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# ============================================
# Password Verification Functions
# ============================================

def verify_md5(password, hashed):
    return hash_md5(password) == hashed

def verify_sha256(password, hashed):
    return hash_sha256(password) == hashed

def verify_bcrypt(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# ============================================
# Brute-Force Attack (for simple passwords)
# ============================================

# For MD5 and SHA-256
def brute_force_attack_hashlib(target_hash, hash_func, max_length=4, charset=string.ascii_lowercase):
    start_time = time.time()
    attempts = 0
    for length in range(1, max_length + 1):
        for guess in itertools.product(charset, repeat=length):
            guess = ''.join(guess)
            attempts += 1
            if hash_func(guess) == target_hash:
                end_time = time.time()
                return guess, attempts, end_time - start_time
    end_time = time.time()
    return None, attempts, end_time - start_time

# For bcrypt
def brute_force_attack_bcrypt(target_hash, max_length=4, charset=string.ascii_lowercase):
    start_time = time.time()
    attempts = 0
    for length in range(1, max_length + 1):
        for guess in itertools.product(charset, repeat=length):
            guess = ''.join(guess)
            attempts += 1
            if bcrypt.checkpw(guess.encode(), target_hash):
                end_time = time.time()
                return guess, attempts, end_time - start_time
    end_time = time.time()
    return None, attempts, end_time - start_time


# ============================================
# Dictionary Attack
# ============================================

def dictionary_attack(target_hash, hash_func, dictionary_list):
    start_time = time.time()
    for word in dictionary_list:
        word = word.strip()
        if hash_func(word) == target_hash:
            end_time = time.time()
            return word, end_time - start_time
    end_time = time.time()
    return None, end_time - start_time

# ============================================
# Benchmarking Function
# ============================================

def benchmark(password):
    print(f"\nBenchmarking password: '{password}'\n")
    
    # MD5
    start = time.time()
    md5_hash = hash_md5(password)
    end = time.time()
    print(f"MD5 Hash: {md5_hash}")
    print(f"MD5 Hashing Time: {end - start:.6f} seconds")
    
    # SHA-256
    start = time.time()
    sha256_hash = hash_sha256(password)
    end = time.time()
    print(f"SHA-256 Hash: {sha256_hash}")
    print(f"SHA-256 Hashing Time: {end - start:.6f} seconds")
    
    # bcrypt
    start = time.time()
    bcrypt_hash = hash_bcrypt(password)
    end = time.time()
    print(f"bcrypt Hash: {bcrypt_hash}")
    print(f"bcrypt Hashing Time: {end - start:.6f} seconds")

# ============================================
# Main Program
# ============================================

def main():
    print("=" * 50)
    print(" Secure Password Hashing and Cracking ")
    print("=" * 50)

    while True:
        print("\nSelect an option:")
        print("1. Hash a password")
        print("2. Verify a password")
        print("3. Perform Brute-Force Attack")
        print("4. Perform Dictionary Attack")
        print("5. Benchmark Hashing Algorithms")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            password = input("Enter password to hash: ")
            print(f"MD5: {hash_md5(password)}")
            print(f"SHA-256: {hash_sha256(password)}")
            print(f"bcrypt: {hash_bcrypt(password)}")

        elif choice == '2':
            password = input("Enter password to verify: ")
            algorithm = input("Enter algorithm (md5/sha256/bcrypt): ").lower()
            stored_hash = input("Enter stored hash: ")

            if algorithm == "md5":
                print("Match:" if verify_md5(password, stored_hash) else "No match.")
            elif algorithm == "sha256":
                print("Match:" if verify_sha256(password, stored_hash) else "No match.")
            elif algorithm == "bcrypt":
                print("Match:" if verify_bcrypt(password, stored_hash.encode()) else "No match.")
            else:
                print("Unknown algorithm.")

        elif choice == '3':
            password = input("Enter password to hash (simple lowercase): ")
            algorithm = input("Select algorithm (md5/sha256): ").lower()
            max_length = int(input("Enter maximum password length to try: "))
            
            if algorithm == "md5":
                hashed = hash_md5(password)
                print(hashed)
                guess, attempts, duration = brute_force_attack_hashlib(hashed, hash_md5, max_length)
            elif algorithm == "sha256":
                hashed = hash_sha256(password)
                print(hashed)
                guess, attempts, duration = brute_force_attack_hashlib(hashed, hash_sha256, max_length)
            elif algorithm == "bycrypt":
                hashed = hash_bcrypt(password)
                print(hashed)
                guess, attempts, duration = brute_force_attack_bcrypt(hashed, max_length)
            else:
                print("Brute-force not supported for bcrypt.")
                continue
            
            if guess:
                print(f"Password cracked: {guess} in {attempts} attempts and {duration:.2f} seconds.")
            else:
                print(f"Password not cracked after {attempts} attempts.")

        elif choice == '4':
            password = input("Enter password to hash: ")
            algorithm = input("Select algorithm (md5/sha256): ").lower()
            dictionary = input("Enter dictionary words (comma separated): ").split(',')

            if algorithm == "md5":
                hashed = hash_md5(password)
                guess, duration = dictionary_attack(hashed, hash_md5, dictionary)
            elif algorithm == "sha256":
                hashed = hash_sha256(password)
                guess, duration = dictionary_attack(hashed, hash_sha256, dictionary)
            else:
                print("Dictionary attack not supported for bcrypt.")
                continue
            
            if guess:
                print(f"Password found: {guess} in {duration:.2f} seconds.")
            else:
                print("Password not found.")

        elif choice == '5':
            password = input("Enter password to benchmark: ")
            benchmark(password)

        elif choice == '6':
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Try again.")

# ============================================
# Run the program
# ============================================

if __name__ == "__main__":
    main()
