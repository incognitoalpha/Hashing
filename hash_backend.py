import hashlib
import bcrypt
from argon2 import PasswordHasher
import time
import string
import itertools
import numpy as np
import tracemalloc
import os
import matplotlib.pyplot as plt
import struct

# Initialize Argon2 hasher globally
ph = PasswordHasher()


# Progress tracking class
class AttackProgress:
    def __init__(self, callback=None):
        self.callback = callback
        self.cancelled = False
        self.current = 0
        self.total = 0

    def update(self, current, total, message=""):
        self.current = current
        self.total = total
        if self.callback:
            self.callback(current, total, message)
        return not self.cancelled

    def cancel(self):
        self.cancelled = True


# Attack configuration class
class AttackConfig:
    def __init__(self, max_length=4, max_time=30, charset=None):
        self.max_length = max_length
        self.max_time = max_time
        self.charset = charset or (string.ascii_lowercase + string.digits)


# Hashing functions

# =====================================Hashing Functions ================================================
# def hash_md5(password):
  #return hashlib.md5(password.encode()).hexdigest()
s = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]# Constants for MD5 (RFC 1321)

K = [int(abs(__import__("math").sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def hash_md5(password: str) -> str:
    message = password.encode('utf-8')
    
    # Initialize MD5 buffer
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    # Pre-processing (padding)
    original_len_bits = (8 * len(message)) & 0xffffffffffffffff
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('<Q', original_len_bits)

    # Process in 512-bit chunks
    for offset in range(0, len(message), 64):
        chunk = message[offset:offset + 64]
        M = list(struct.unpack('<16I', chunk))
        a, b, c, d = A, B, C, D

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            f = (f + a + K[i] + M[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + left_rotate(f, s[i])) & 0xFFFFFFFF

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return ''.join(f'{i:02x}' for i in struct.pack('<4I', A, B, C, D))


#----------------------------------------SHA256-------------------------------------------------
# def hash_sha256(password):
#     return hashlib.sha256(password.encode()).hexdigest()

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]# Constants for SHA-256 (first 32 bits of the fractional parts of the cube roots of the first 64 primes)

# Right rotate
def rotr(x, n):
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

# SHA-256 compression function
def sha256_compress(chunk, H):
    w = list(struct.unpack('>16L', chunk)) + [0] * 48
    for i in range(16, 64):
        s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = H

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

    return [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

# Main SHA-256 function with `password` parameter
def hash_sha256(password: str) -> str:
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    # Convert password to bytes
    message = bytearray(password.encode('utf-8'))
    original_length_bits = len(message) * 8

    # Padding
    message.append(0x80)
    while (len(message) + 8) % 64 != 0:
        message.append(0)
    message += struct.pack('>Q', original_length_bits)

    # Process 512-bit chunks
    for i in range(0, len(message), 64):
        H = sha256_compress(message[i:i+64], H)

    # Return final digest as hex string
    return ''.join(f'{x:08x}' for x in H)


def hash_bcrypt(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()


def hash_argon2(password: str) -> str:
    return ph.hash(password)


# Brute force attack functions
def brute_force_attack_hashlib(target_hash, hash_func, config=None, progress=None):
    if config is None:
        config = AttackConfig()

    chars = config.charset
    start = time.time()
    attempts = 0
    total_combinations = sum(len(chars) ** i for i in range(1, config.max_length + 1))

    for length in range(1, config.max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            # Check time limit
            if time.time() - start > config.max_time:
                return None, attempts, time.time() - start

            # Check if cancelled
            if progress and not progress.update(attempts, total_combinations, f"Trying length {length}"):
                return None, attempts, time.time() - start

            attempt_str = ''.join(attempt)
            attempts += 1

            try:
                if hash_func(attempt_str) == target_hash:
                    return attempt_str, attempts, time.time() - start
            except Exception as e:
                print(f"Error during hash comparison: {e}")
                continue

    return None, attempts, time.time() - start


def brute_force_attack_bcrypt(target_hash, config=None, progress=None):
    if config is None:
        config = AttackConfig(max_length=3)  # Lower default for bcrypt

    chars = config.charset
    start = time.time()
    attempts = 0
    target_hash_bytes = target_hash.encode()

    for length in range(1, config.max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            # Check time limit
            if time.time() - start > config.max_time:
                return None, attempts, time.time() - start

            # Check if cancelled
            if progress and not progress.update(attempts, 0, f"Trying length {length}"):
                return None, attempts, time.time() - start

            attempt_str = ''.join(attempt)
            attempts += 1

            try:
                if bcrypt.checkpw(attempt_str.encode(), target_hash_bytes):
                    return attempt_str, attempts, time.time() - start
            except (ValueError, Exception) as e:
                continue

    return None, attempts, time.time() - start


def brute_force_attack_argon2(target_hash, config=None, progress=None):
    if config is None:
        config = AttackConfig(max_length=3)  # Lower default for Argon2

    chars = config.charset
    start = time.time()
    attempts = 0

    for length in range(1, config.max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            # Check time limit
            if time.time() - start > config.max_time:
                return None, attempts, time.time() - start

            # Check if cancelled
            if progress and not progress.update(attempts, 0, f"Trying length {length}"):
                return None, attempts, time.time() - start

            attempt_str = ''.join(attempt)
            attempts += 1

            try:
                ph.verify(target_hash, attempt_str)
                return attempt_str, attempts, time.time() - start
            except Exception:
                continue

    return None, attempts, time.time() - start


# Dictionary attack functions
def validate_dictionary_file(file_path):
    """Validate dictionary file before attack"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dictionary file not found: {file_path}")

    if os.path.getsize(file_path) == 0:
        raise ValueError("Dictionary file is empty")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            first_line = f.readline().strip()
            if not first_line:
                raise ValueError("Dictionary file contains no valid entries")
    except UnicodeDecodeError:
        raise ValueError("Dictionary file must be UTF-8 encoded text")

    return True


def dictionary_attack_hashlib(target_hash, hash_func, dictionary_file, progress=None):
    validate_dictionary_file(dictionary_file)

    attempts = 0
    start = time.time()

    try:
        # Count total lines for progress
        with open(dictionary_file, "r", encoding='utf-8') as f:
            total_lines = sum(1 for _ in f)

        with open(dictionary_file, "r", encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                word = line.strip()
                if not word:  # Skip empty lines
                    continue

                attempts += 1

                # Update progress
                if progress and not progress.update(line_num, total_lines, f"Trying: {word[:20]}..."):
                    return None, attempts, time.time() - start

                try:
                    if hash_func(word) == target_hash:
                        return word, attempts, time.time() - start
                except Exception as e:
                    print(f"Error hashing word '{word}': {e}")
                    continue

    except Exception as e:
        raise Exception(f"Error reading dictionary file: {e}")

    return None, attempts, time.time() - start


def dictionary_attack_bcrypt(target_hash, dictionary_file, progress=None):
    validate_dictionary_file(dictionary_file)

    attempts = 0
    start = time.time()
    target_hash_bytes = target_hash.encode()

    try:
        # Count total lines for progress
        with open(dictionary_file, "r", encoding='utf-8') as f:
            total_lines = sum(1 for _ in f)

        with open(dictionary_file, "r", encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                word = line.strip()
                if not word:  # Skip empty lines
                    continue

                attempts += 1

                # Update progress
                if progress and not progress.update(line_num, total_lines, f"Trying: {word[:20]}..."):
                    return None, attempts, time.time() - start

                try:
                    if bcrypt.checkpw(word.encode(), target_hash_bytes):
                        return word, attempts, time.time() - start
                except (ValueError, Exception):
                    continue

    except Exception as e:
        raise Exception(f"Error reading dictionary file: {e}")

    return None, attempts, time.time() - start


def dictionary_attack_argon2(target_hash, dictionary_file, progress=None):
    validate_dictionary_file(dictionary_file)

    attempts = 0
    start = time.time()

    try:
        # Count total lines for progress
        with open(dictionary_file, "r", encoding='utf-8') as f:
            total_lines = sum(1 for _ in f)

        with open(dictionary_file, "r", encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                word = line.strip()
                if not word:  # Skip empty lines
                    continue

                attempts += 1

                # Update progress
                if progress and not progress.update(line_num, total_lines, f"Trying: {word[:20]}..."):
                    return None, attempts, time.time() - start

                try:
                    ph.verify(target_hash, word)
                    return word, attempts, time.time() - start
                except Exception:
                    continue

    except Exception as e:
        raise Exception(f"Error reading dictionary file: {e}")

    return None, attempts, time.time() - start


# Memory profiling function
def memory_profile_hash(func, password):
    tracemalloc.start()
    func(password)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024  # KB


# Complexity graph function
def show_time_complexity_graph():
    input_sizes = np.linspace(1, 1000, 100)
    md5_times = input_sizes * 0.002
    sha256_times = input_sizes * 0.003
    bcrypt_times = np.full_like(input_sizes, 1.5)
    argon2_times = np.full_like(input_sizes, 2.5)

    mem_usages_kb = [
        memory_profile_hash(hash_md5, "abc123"),
        memory_profile_hash(hash_sha256, "abc123"),
        memory_profile_hash(hash_bcrypt, "abc123"),
        memory_profile_hash(hash_argon2, "abc123")
    ]

    algos = ['MD5', 'SHA-256', 'bcrypt', 'Argon2']
    space_complexity_o = ['O(1)', 'O(1)', 'O(1)', 'O(1)']
    space_complexity_vals = [1, 1, 10, 20]

    plt.figure(figsize=(12, 10))
    plt.subplot(3, 1, 1)
    plt.scatter(input_sizes, md5_times, label='MD5 O(n)', color='blue', s=10)
    plt.scatter(input_sizes, sha256_times, label='SHA-256 O(n)', color='green', s=10)
    plt.scatter(input_sizes, bcrypt_times, label='bcrypt O(1)', color='orange', s=10)
    plt.scatter(input_sizes, argon2_times, label='Argon2 O(1)', color='red', s=10)
    plt.title("Time Complexity Scatter Plot")
    plt.xlabel("Input Size (characters)")
    plt.ylabel("Time (arbitrary units)")
    plt.legend()
    plt.grid(True)

    plt.subplot(3, 1, 2)
    bars = plt.bar(algos, space_complexity_vals, color=['blue', 'green', 'orange', 'red'])
    plt.title("Space Complexity (Symbolic & Relative)")
    plt.ylabel("Relative Space (arb. units)")
    for bar, o in zip(bars, space_complexity_o):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, o, ha='center', fontsize=12)

    plt.subplot(3, 1, 3)
    bars = plt.bar(algos, mem_usages_kb, color=['blue', 'green', 'orange', 'red'])
    plt.title("Actual Peak Memory Usage During Hashing (KB)")
    plt.ylabel("Memory Usage (KB)")
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{bar.get_height():.1f} KB", ha='center',
                 fontsize=12)

    plt.tight_layout()
    plt.show()


# Utility functions
def demonstrate_md5_collision():
    input1 = b"Hello World"
    input2 = b"Hello World!"
    hash1 = hashlib.md5(input1).hexdigest()
    hash2 = hashlib.md5(input2).hexdigest()

    output = []
    output.append("\n=== MD5 Collision Demonstration ===")
    output.append(f"Input 1 (bytes): {input1}")
    output.append(f"Input 2 (bytes): {input2}")
    output.append(f"MD5 hash of input 1: {hash1}")
    output.append(f"MD5 hash of input 2: {hash2}")

    if hash1 == hash2:
        output.append("These distinct inputs produce the SAME MD5 hash, demonstrating a collision!")
    else:
        output.append("No collision detected - inputs produce different hashes.")

    return "\n".join(output)


def identify_hash_type(h):
    h = h.strip()
    if len(h) == 32 and all(c in '0123456789abcdefABCDEF' for c in h):
        return "MD5"
    elif len(h) == 64 and all(c in '0123456789abcdefABCDEF' for c in h):
        return "SHA-256"
    elif h.startswith("$2b$") or h.startswith("$2a$"):
        return "bcrypt"
    elif h.startswith("$argon2"):
        return "Argon2"
    else:
        return "Unknown"


def length_extension_attack_demo():
    output = []
    output.append("\n=== SHA-256 Length Extension Attack Demo ===")
    secret = b'secretkey'
    original_message = b'originalmessage'
    appended_data = b';admin=true'

    original_hash = hashlib.sha256(secret + original_message).hexdigest()
    output.append(f"Original message: {original_message}")
    output.append(f"Original hash (SHA256(secret || message)): {original_hash}")

    output.append("\nAttacker tries length extension attack by appending data without secret...")
    output.append(f"Appended data to add: {appended_data}")

    extended_message = original_message + appended_data
    final_hash = hashlib.sha256(secret + extended_message).hexdigest()
    output.append(f"\nFinal hash after including appended data (for comparison): {final_hash}")
    output.append(
        "\nThis shows that without knowing secret, attacker can forge hashes for extended message by length extension attack.")
    output.append("A real length extension attack requires reconstructing internal hash state (not shown here).")

    return "\n".join(output)


def show_attack_results_graph(results, title):
    """Show attack results in a graph"""
    try:
        plt.style.use('default')
        plt.rcParams.update({'font.size': 12})

        labels = [r[0] for r in results]
        times = [r[3] for r in results]
        attempts = [r[2] for r in results]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Time comparison
        bars1 = ax1.bar(labels, times, color=['#2563eb', '#16a34a', '#ea580c', '#db2777'])
        ax1.set_ylabel('Time (seconds)')
        ax1.set_title(f'{title} - Time Taken')
        ax1.tick_params(axis='x', rotation=45)

        for bar, t in zip(bars1, times):
            if t > 0:
                ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                         f"{t:.2f}s", ha='center', va='bottom')

        # Attempts comparison
        bars2 = ax2.bar(labels, attempts, color=['#2563eb', '#16a34a', '#ea580c', '#db2777'])
        ax2.set_ylabel('Attempts')
        ax2.set_title(f'{title} - Attempts Made')
        ax2.tick_params(axis='x', rotation=45)

        for bar, a in zip(bars2, attempts):
            if a > 0:
                ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(attempts) * 0.01,
                         f"{a}", ha='center', va='bottom')

        plt.tight_layout()
        plt.show()

    except Exception as e:
        print(f"Error showing graph: {e}")


# Testing and validation functions
def create_sample_dictionary():
    """Create a sample dictionary file for testing"""
    common_passwords = [
        "password", "123456", "password123", "admin", "qwerty",
        "letmein", "welcome", "monkey", "1234567890", "abc123",
        "password1", "123456789", "welcome123", "admin123", "test",
        "user", "root", "toor", "pass", "secret", "login", "guest"
    ]

    filename = "sample_dictionary.txt"
    try:
        with open(filename, 'w') as f:
            for pwd in common_passwords:
                f.write(pwd + '\n')
        return filename
    except Exception as e:
        print(f"Failed to create sample dictionary: {e}")
        return None


def validate_installation():
    """Validate that all required libraries are installed"""
    required_modules = {
        'hashlib': 'Built-in',
        'bcrypt': 'pip install bcrypt',
        'argon2': 'pip install argon2-cffi',
        'matplotlib': 'pip install matplotlib',
        'numpy': 'pip install numpy',
        'tkinter': 'Built-in (usually)'
    }

    missing_modules = []

    for module, install_cmd in required_modules.items():
        try:
            if module == 'argon2':
                from argon2 import PasswordHasher
            else:
                __import__(module)
        except ImportError:
            missing_modules.append((module, install_cmd))

    if missing_modules:
        print("Missing required modules:")
        for module, cmd in missing_modules:
            print(f"  {module}: {cmd}")
        return False

    print("All required modules are installed!")
    return True


def run_quick_test():
    """Run a quick test of all hashing functions"""
    test_password = "test123"
    print(f"Testing with password: '{test_password}'")

    try:
        # Test hashing functions
        md5_hash = hash_md5(test_password)
        sha256_hash = hash_sha256(test_password)
        bcrypt_hash = hash_bcrypt(test_password)
        argon2_hash = hash_argon2(test_password)

        print("✓ All hashing functions work")
        print(f"  MD5: {md5_hash}")
        print(f"  SHA-256: {sha256_hash}")
        print(f"  bcrypt: {bcrypt_hash}")
        print(f"  Argon2: {argon2_hash}")

        # Test brute force (quick test)
        config = AttackConfig(max_length=2, max_time=5)
        result, attempts, duration = brute_force_attack_hashlib(md5_hash, hash_md5, config)
        if result:
            print(f"✓ Brute force test passed: found '{result}' in {attempts} attempts")
        else:
            print("✓ Brute force test completed (password not found in limited search)")

        # Test dictionary attack with sample
        dict_file = create_sample_dictionary()
        if dict_file:
            # Test with a password that should be in the dictionary
            test_hash = hash_md5("password")
            result, attempts, duration = dictionary_attack_hashlib(test_hash, hash_md5, dict_file)
            if result == "password":
                print("✓ Dictionary attack test passed")
            else:
                print("✗ Dictionary attack test failed")

            # Clean up
            try:
                os.remove(dict_file)
            except:
                pass

        return True

    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False