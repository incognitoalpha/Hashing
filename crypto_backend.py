#!/usr/bin/env python3
"""
Cryptographic Security Demonstration Backend
==========================================

Educational tool demonstrating various password hashing vulnerabilities.
Modified for GUI integration with dynamic inputs.
"""

import time
import statistics
import hashlib
import secrets
import string
from collections import defaultdict, Counter
import json

# Optional imports with graceful fallbacks
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False


class CryptographicSecurityDemo:
    """Main class containing all cryptographic security demonstrations"""
    
    def __init__(self):
        self.results = {}
        
    def get_available_libraries(self):
        """Return which libraries are available"""
        return {
            'argon2': ARGON2_AVAILABLE,
            'bcrypt': BCRYPT_AVAILABLE
        }
    
    # ================== ARGON2 DEMONSTRATIONS ==================
    
    def argon2_timing_attack(self, target_password, test_passwords=None):
        """Argon2 timing attack simulation with custom inputs"""
        if not ARGON2_AVAILABLE:
            return {"error": "Argon2 library not available. Install with: pip install argon2-cffi"}
            
        if test_passwords is None:
            test_passwords = [
                ("wrong", "Completely incorrect"),
                ("password", "Common weak password"),
                (target_password[:len(target_password)//2], "Partial match"),
                (target_password, "Correct password"),
                (target_password + "x", "Correct + extra char"),
            ]
        
        ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
        
        try:
            hashed = ph.hash(target_password)
        except Exception as e:
            return {"error": f"Failed to hash password: {str(e)}"}
        
        results = []
        
        for password_attempt, description in test_passwords:
            times = []
            
            for trial in range(5):  # Reduced trials for GUI responsiveness
                start_time = time.perf_counter()
                
                try:
                    ph.verify(hashed, password_attempt)
                    verification_success = True
                except VerifyMismatchError:
                    verification_success = False
                except Exception:
                    verification_success = False
                
                end_time = time.perf_counter()
                duration = end_time - start_time
                times.append(duration)
            
            avg_time = statistics.mean(times)
            std_dev = statistics.stdev(times) if len(times) > 1 else 0
            
            results.append({
                'password': password_attempt,
                'description': description,
                'avg_time': avg_time,
                'std_dev': std_dev,
                'success': verification_success
            })
        
        # Analysis
        correct_time = next((r['avg_time'] for r in results if r['success']), None)
        incorrect_times = [r['avg_time'] for r in results if not r['success']]
        
        analysis = {}
        if correct_time and incorrect_times:
            avg_incorrect = statistics.mean(incorrect_times)
            time_difference = abs(correct_time - avg_incorrect)
            
            analysis = {
                'correct_time': correct_time,
                'avg_incorrect_time': avg_incorrect,
                'time_difference': time_difference,
                'vulnerable': time_difference > 0.001
            }
        
        return {
            'target_password': target_password,
            'hash': hashed[:50] + "...",
            'results': results,
            'analysis': analysis
        }
    
    # ================== BCRYPT DEMONSTRATIONS ==================
    
    def bcrypt_truncation_demo(self, custom_suffix="X"):
        """Demonstrate bcrypt 72-byte truncation with custom suffix"""
        if not BCRYPT_AVAILABLE:
            return {"error": "bcrypt library not available. Install with: pip install bcrypt"}
        
        base_password = "A" * 72
        password1 = base_password + custom_suffix
        password2 = base_password + "Y"
        password3 = base_password + "completely_different_suffix"
        
        try:
            salt = bcrypt.gensalt()
            hash1 = bcrypt.hashpw(password1.encode('utf-8'), salt)
            
            test_passwords = [
                ("Original password", password1),
                ("Different single char", password2),
                ("Long different suffix", password3),
                ("Base password (72 bytes)", base_password),
            ]
            
            results = []
            vulnerability_count = 0
            
            for desc, pwd in test_passwords:
                is_valid = bcrypt.checkpw(pwd.encode('utf-8'), hash1)
                results.append({
                    'description': desc,
                    'password': pwd[:50] + "..." if len(pwd) > 50 else pwd,
                    'length': len(pwd),
                    'matches': is_valid
                })
                
                if is_valid and pwd != password1:
                    vulnerability_count += 1
            
            return {
                'base_password_length': len(base_password),
                'test_password': password1[:50] + "..." if len(password1) > 50 else password1,
                'test_password_length': len(password1),
                'hash': hash1.decode('utf-8'),
                'results': results,
                'vulnerability_count': vulnerability_count,
                'is_vulnerable': vulnerability_count > 0
            }
            
        except Exception as e:
            return {"error": f"bcrypt operation failed: {str(e)}"}
    
    def bcrypt_length_analysis(self, test_lengths=None):
        """Analyze bcrypt truncation at different lengths"""
        if not BCRYPT_AVAILABLE:
            return {"error": "bcrypt library not available"}
        
        if test_lengths is None:
            test_lengths = [70, 71, 72, 73, 74, 75, 80]
        
        results = []
        
        for length in test_lengths:
            try:
                base_pwd = "A" * length
                test_pwd = base_pwd + "X"
                
                salt = bcrypt.gensalt()
                base_hash = bcrypt.hashpw(base_pwd.encode('utf-8'), salt)
                is_vulnerable = bcrypt.checkpw(test_pwd.encode('utf-8'), base_hash)
                
                results.append({
                    'length': length,
                    'is_vulnerable': is_vulnerable,
                    'status': "🚨 VULNERABLE" if is_vulnerable else "✓ SECURE",
                    'is_boundary': length == 72
                })
                
            except Exception as e:
                results.append({
                    'length': length,
                    'error': str(e)
                })
        
        return {'results': results}
    
    # ================== SHA-256 DEMONSTRATIONS ==================
    
    def sha256_no_salt_demo(self, user_passwords=None):
        """Demonstrate SHA-256 without salt vulnerabilities with custom data"""
        if user_passwords is None:
            user_passwords = [
                ("alice@example.com", "password123"),
                ("bob@company.com", "password123"),
                ("charlie@site.org", "secret456"),
                ("diana@domain.net", "secret456"),
            ]
        
        user_hashes = {}
        hash_frequency = Counter()
        
        for email, password in user_passwords:
            hash_value = hashlib.sha256(password.encode('utf-8')).hexdigest()
            user_hashes[email] = hash_value
            hash_frequency[hash_value] += 1
        
        duplicate_hashes = {h: count for h, count in hash_frequency.items() if count > 1}
        
        results = []
        for email, password in user_passwords:
            hash_val = user_hashes[email]
            is_duplicate = hash_val in duplicate_hashes
            
            results.append({
                'email': email,
                'password': password,
                'hash': hash_val,
                'hash_short': hash_val[:16] + "...",
                'is_duplicate': is_duplicate,
                'duplicate_count': hash_frequency[hash_val] if is_duplicate else 1
            })
        
        return {
            'results': results,
            'total_duplicates': len(duplicate_hashes),
            'vulnerability_detected': len(duplicate_hashes) > 0
        }
    
    def rainbow_table_attack_sim(self, target_hashes=None):
        """Simulate rainbow table attack"""
        common_passwords = [
            "123456", "password", "123456789", "12345678", "12345",
            "qwerty", "abc123", "password1", "admin", "password123",
            "welcome", "monkey", "letmein", "dragon", "1234567890"
        ]
        
        # Build rainbow table
        rainbow_table = {}
        for password in common_passwords:
            hash_value = hashlib.sha256(password.encode('utf-8')).hexdigest()
            rainbow_table[hash_value] = password
        
        if target_hashes is None:
            # Create some example hashes
            test_passwords = ["admin", "password123", "123456", "P@ssw0rd2024!"]
            target_hashes = []
            for pwd in test_passwords:
                hash_val = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
                target_hashes.append({
                    'user': f"user_{len(target_hashes)+1}@example.com",
                    'hash': hash_val,
                    'actual_password': pwd  # Only for demo purposes
                })
        
        results = []
        cracked_count = 0
        
        for target in target_hashes:
            hash_val = target['hash']
            if hash_val in rainbow_table:
                cracked_password = rainbow_table[hash_val]
                results.append({
                    'user': target['user'],
                    'hash': hash_val[:20] + "...",
                    'cracked': True,
                    'password': cracked_password
                })
                cracked_count += 1
            else:
                results.append({
                    'user': target['user'],
                    'hash': hash_val[:20] + "...",
                    'cracked': False,
                    'password': "Not found"
                })
        
        return {
            'rainbow_table_size': len(rainbow_table),
            'results': results,
            'cracked_count': cracked_count,
            'total_targets': len(target_hashes),
            'success_rate': (cracked_count / len(target_hashes) * 100) if target_hashes else 0
        }
    
    def proper_salting_demo(self, user_passwords=None):
        """Demonstrate proper salting technique"""
        if user_passwords is None:
            user_passwords = [
                ("alice@example.com", "password123"),
                ("bob@company.com", "password123"),
                ("charlie@site.org", "secret456"),
            ]
        
        results = []
        
        for email, password in user_passwords:
            salt = secrets.token_hex(16)
            salted_input = salt + password
            hash_value = hashlib.sha256(salted_input.encode('utf-8')).hexdigest()
            
            results.append({
                'email': email,
                'password': password,
                'salt': salt,
                'hash': hash_value,
                'hash_short': hash_value[:32] + "..."
            })
        
        # Check if same passwords produce different hashes
        password_groups = {}
        for result in results:
            pwd = result['password']
            if pwd not in password_groups:
                password_groups[pwd] = []
            password_groups[pwd].append(result['hash'])
        
        unique_hashes_per_password = {}
        for pwd, hashes in password_groups.items():
            unique_hashes_per_password[pwd] = len(set(hashes)) == len(hashes)
        
        return {
            'results': results,
            'password_groups': password_groups,
            'all_unique': all(unique_hashes_per_password.values()),
            'uniqueness_check': unique_hashes_per_password
        }
    
    def weak_salt_analysis(self, password="testpassword", custom_salts=None):
        """Analyze different salt implementations"""
        if custom_salts is None:
            weak_salts = [
                ("Fixed Salt", "company_salt_2024"),
                ("Username as Salt", "john.doe"),
                ("Sequential Salt", "000001"),
                ("Short Salt", "abc"),
                ("Common String", "salt"),
            ]
        else:
            weak_salts = custom_salts
        
        results = []
        
        for salt_type, salt_value in weak_salts:
            hash_result = hashlib.sha256((salt_value + password).encode()).hexdigest()
            
            # Assess weakness
            weakness_score = 0
            issues = []
            
            if len(salt_value) < 8:
                weakness_score += 3
                issues.append("Too short")
            if salt_value.isdigit():
                weakness_score += 2
                issues.append("Numeric only")
            if salt_value.isalpha() and salt_value.lower() in ['salt', 'password', 'admin']:
                weakness_score += 3
                issues.append("Common word")
            if not any(c.isdigit() for c in salt_value) and not any(c.isupper() for c in salt_value):
                weakness_score += 1
                issues.append("Low entropy")
            
            results.append({
                'type': salt_type,
                'salt': salt_value,
                'hash': hash_result,
                'hash_short': hash_result[:40] + "...",
                'weakness_score': weakness_score,
                'issues': issues,
                'security_level': "High Risk" if weakness_score >= 4 else "Medium Risk" if weakness_score >= 2 else "Low Risk"
            })
        
        # Add proper random salt for comparison
        proper_salt = secrets.token_hex(32)
        proper_hash = hashlib.sha256((proper_salt + password).encode()).hexdigest()
        results.append({
            'type': "Proper Random Salt",
            'salt': proper_salt,
            'hash': proper_hash,
            'hash_short': proper_hash[:40] + "...",
            'weakness_score': 0,
            'issues': [],
            'security_level': "Secure"
        })
        
        return {
            'password': password,
            'results': results
        }


# Helper functions for GUI
def format_time(seconds):
    """Format time for display"""
    if seconds < 0.001:
        return f"{seconds*1000000:.2f} μs"
    elif seconds < 1:
        return f"{seconds*1000:.2f} ms"
    else:
        return f"{seconds:.4f} s"

def truncate_string(s, max_length=50):
    """Truncate string for display"""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."