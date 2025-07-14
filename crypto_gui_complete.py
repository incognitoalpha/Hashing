#!/usr/bin/env python3
"""
Cryptographic Security Demonstration GUI
=======================================

Tkinter-based GUI for demonstrating password hashing vulnerabilities.
Requires crypto_backend.py in the same directory.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import sys
import os

# Import the backend
try:
    from crypto_backend import CryptographicSecurityDemo, format_time, truncate_string
except ImportError:
    print("Error: crypto_backend.py not found in the same directory!")
    sys.exit(1)


class CryptoSecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Security Demonstration")
        self.root.geometry("1200x800")
        
        # Initialize backend
        self.demo = CryptographicSecurityDemo()
        self.result_queue = queue.Queue()
        
        # Setup GUI
        self.setup_gui()
        self.check_libraries()
        
    def setup_gui(self):
        """Setup the main GUI layout"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔐 Cryptographic Security Demonstration", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Left panel - Controls
        controls_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        controls_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.setup_controls(controls_frame)
        self.setup_results(results_frame)
        
    def setup_controls(self, parent):
        """Setup the controls panel"""
        # Notebook for different demonstrations
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Argon2 Tab
        self.setup_argon2_tab()
        
        # bcrypt Tab
        self.setup_bcrypt_tab()
        
        # SHA-256 Tab
        self.setup_sha256_tab()
        
    def setup_argon2_tab(self):
        """Setup Argon2 demonstration tab"""
        argon2_frame = ttk.Frame(self.notebook)
        self.notebook.add(argon2_frame, text="Argon2 Timing")
        
        # Target password input
        ttk.Label(argon2_frame, text="Target Password:").pack(anchor=tk.W, pady=(0, 5))
        self.argon2_password = tk.StringVar(value="MySecurePassword123!")
        ttk.Entry(argon2_frame, textvariable=self.argon2_password, width=30).pack(anchor=tk.W, pady=(0, 10))
        
        # Test passwords
        ttk.Label(argon2_frame, text="Test Passwords (one per line):").pack(anchor=tk.W, pady=(0, 5))
        self.argon2_tests = tk.Text(argon2_frame, height=8, width=35)
        self.argon2_tests.pack(anchor=tk.W, pady=(0, 10))
        
        # Default test passwords
        default_tests = """wrong
password
MySecure
MySecurePassword
MySecurePassword123!
MySecurePassword123?"""
        self.argon2_tests.insert("1.0", default_tests)
        
        # Run button
        ttk.Button(argon2_frame, text="Run Argon2 Timing Attack", 
                  command=self.run_argon2_timing).pack(pady=10)
        
        # Info label
        info_text = """📋 Conditions for vulnerability:
• Significant timing differences between correct/incorrect passwords
• Consistent timing patterns across multiple tests
• Timing difference > 0.001 seconds typically indicates vulnerability"""
        
        info_label = ttk.Label(argon2_frame, text=info_text, 
                              font=("Arial", 9), foreground="blue")
        info_label.pack(anchor=tk.W, pady=(10, 0))
        
    def setup_bcrypt_tab(self):
        """Setup bcrypt demonstration tab"""
        bcrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(bcrypt_frame, text="bcrypt Truncation")
        
        # Custom suffix input
        ttk.Label(bcrypt_frame, text="Custom Suffix (after 72 bytes):").pack(anchor=tk.W, pady=(0, 5))
        self.bcrypt_suffix = tk.StringVar(value="X")
        suffix_entry = ttk.Entry(bcrypt_frame, textvariable=self.bcrypt_suffix, width=20)
        suffix_entry.pack(anchor=tk.W, pady=(0, 10))
        
        # Run buttons
        ttk.Button(bcrypt_frame, text="Test bcrypt Truncation", 
                  command=self.run_bcrypt_truncation).pack(pady=5)
        
        ttk.Button(bcrypt_frame, text="Length Analysis", 
                  command=self.run_bcrypt_length).pack(pady=5)
        
        # Length analysis inputs
        ttk.Label(bcrypt_frame, text="Test Lengths (comma-separated):").pack(anchor=tk.W, pady=(10, 5))
        self.bcrypt_lengths = tk.StringVar(value="70,71,72,73,74,75,80")
        ttk.Entry(bcrypt_frame, textvariable=self.bcrypt_lengths, width=30).pack(anchor=tk.W, pady=(0, 10))
        
        # Info label
        info_text = """📋 Conditions for vulnerability:
• Password length > 72 bytes
• Different suffixes after 72nd byte should be treated as same password
• Vulnerability occurs at exactly 72-byte boundary
• Any character after 72 bytes is ignored by bcrypt"""
        
        info_label = ttk.Label(bcrypt_frame, text=info_text, 
                              font=("Arial", 9), foreground="blue")
        info_label.pack(anchor=tk.W, pady=(10, 0))
        
    def setup_sha256_tab(self):
        """Setup SHA-256 demonstration tab"""
        sha256_frame = ttk.Frame(self.notebook)
        self.notebook.add(sha256_frame, text="SHA-256 Attacks")
        
        # User data input
        ttk.Label(sha256_frame, text="User Data (email:password, one per line):").pack(anchor=tk.W, pady=(0, 5))
        self.sha256_users = tk.Text(sha256_frame, height=6, width=35)
        self.sha256_users.pack(anchor=tk.W, pady=(0, 10))
        
        # Default user data
        default_users = """alice@example.com:password123
bob@company.com:password123
charlie@site.org:secret456
diana@domain.net:secret456
eve@test.com:admin"""
        self.sha256_users.insert("1.0", default_users)
        
        # Run buttons
        ttk.Button(sha256_frame, text="Test No Salt Vulnerability", 
                  command=self.run_sha256_no_salt).pack(pady=5)
        
        ttk.Button(sha256_frame, text="Rainbow Table Attack", 
                  command=self.run_rainbow_table).pack(pady=5)
        
        ttk.Button(sha256_frame, text="Proper Salting Demo", 
                  command=self.run_proper_salting).pack(pady=5)
        
        # Weak salt analysis
        ttk.Label(sha256_frame, text="Test Password for Salt Analysis:").pack(anchor=tk.W, pady=(10, 5))
        self.salt_test_password = tk.StringVar(value="testpassword123")
        ttk.Entry(sha256_frame, textvariable=self.salt_test_password, width=25).pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Button(sha256_frame, text="Weak Salt Analysis", 
                  command=self.run_weak_salt_analysis).pack(pady=5)
        
        # Info label
        info_text = """📋 Conditions for vulnerability:
• No Salt: Same passwords = same hashes
• Weak Salt: Predictable/reused salts enable targeted attacks
• Rainbow Tables: Pre-computed hash lookups for common passwords
• Proper salting prevents all above attacks"""
        
        info_label = ttk.Label(sha256_frame, text=info_text, 
                              font=("Arial", 9), foreground="blue")
        info_label.pack(anchor=tk.W, pady=(10, 0))
        
    def setup_results(self, parent):
        """Setup the results panel"""
        # Results text area with scrollbar
        self.results_text = scrolledtext.ScrolledText(parent, width=70, height=35, 
                                                     font=("Consolas", 10))
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Clear button
        ttk.Button(parent, text="Clear Results", 
                  command=self.clear_results).pack(pady=(10, 0))
        
    def check_libraries(self):
        """Check available libraries and display status"""
        libs = self.demo.get_available_libraries()
        
        status_text = "📚 Library Status:\n"
        status_text += f"• Argon2: {'✅ Available' if libs['argon2'] else '❌ Not installed (pip install argon2-cffi)'}\n"
        status_text += f"• bcrypt: {'✅ Available' if libs['bcrypt'] else '❌ Not installed (pip install bcrypt)'}\n"
        status_text += f"• SHA-256: ✅ Available (built-in)\n\n"
        
        self.append_results(status_text)
        
    def append_results(self, text):
        """Append text to results area"""
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def clear_results(self):
        """Clear the results area"""
        self.results_text.delete(1.0, tk.END)
        self.check_libraries()
        
    def run_in_thread(self, func, *args):
        """Run function in separate thread to prevent GUI freezing"""
        def worker():
            try:
                result = func(*args)
                self.result_queue.put(('success', result))
            except Exception as e:
                self.result_queue.put(('error', str(e)))
        
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()
        
        # Check for results
        self.root.after(100, self.check_result_queue)
        
    def check_result_queue(self):
        """Check for results from background thread"""
        try:
            result_type, result = self.result_queue.get_nowait()
            if result_type == 'success':
                self.handle_result(result)
            elif result_type == 'error':
                self.append_results(f"❌ Error: {result}\n\n")
        except queue.Empty:
            # No result yet, check again later
            self.root.after(100, self.check_result_queue)
            
    def handle_result(self, result):
        """Handle results from demonstrations"""
        if 'error' in result:
            self.append_results(f"❌ {result['error']}\n\n")
            return
            
        # Format and display results based on type
        if 'target_password' in result:  # Argon2 timing
            self.display_argon2_results(result)
        elif 'base_password_length' in result:  # bcrypt truncation
            self.display_bcrypt_results(result)
        elif 'vulnerability_detected' in result:  # SHA-256 no salt
            self.display_sha256_no_salt_results(result)
        elif 'rainbow_table_size' in result:  # Rainbow table
            self.display_rainbow_table_results(result)
        elif 'all_unique' in result:  # Proper salting
            self.display_proper_salting_results(result)
        elif 'password' in result and 'results' in result:  # Weak salt analysis
            self.display_weak_salt_results(result)
        else:
            self.append_results(f"Results: {result}\n\n")
            
    def display_argon2_results(self, result):
        """Display Argon2 timing attack results"""
        self.append_results("🕐 ARGON2 TIMING ATTACK RESULTS\n")
        self.append_results("=" * 50 + "\n")
        self.append_results(f"Target Password: {result['target_password']}\n")
        self.append_results(f"Hash: {result['hash']}\n\n")
        
        self.append_results("Test Results:\n")
        self.append_results("-" * 30 + "\n")
        
        for r in result['results']:
            status = "✅ SUCCESS" if r['success'] else "❌ FAILED"
            self.append_results(f"Password: {truncate_string(r['password'], 20):<20} | "
                              f"Time: {format_time(r['avg_time']):<10} | {status}\n")
        
        if result['analysis']:
            analysis = result['analysis']
            self.append_results(f"\n🔍 ANALYSIS:\n")
            self.append_results(f"Correct password time: {format_time(analysis['correct_time'])}\n")
            self.append_results(f"Average incorrect time: {format_time(analysis['avg_incorrect_time'])}\n")
            self.append_results(f"Time difference: {format_time(analysis['time_difference'])}\n")
            
            if analysis['vulnerable']:
                self.append_results("⚠️  WARNING: Potential timing vulnerability detected!\n")
            else:
                self.append_results("✅ No significant timing vulnerability detected.\n")
        
        self.append_results("\n" + "=" * 50 + "\n\n")
        
    def display_bcrypt_results(self, result):
        """Display bcrypt truncation results"""
        self.append_results("🔒 BCRYPT TRUNCATION TEST RESULTS\n")
        self.append_results("=" * 50 + "\n")
        
        if 'base_password_length' in result:
            # Truncation test results
            self.append_results(f"Base Password Length: {result['base_password_length']} bytes\n")
            self.append_results(f"Custom Suffix: '{result['custom_suffix']}'\n\n")
            
            self.append_results("Test Results:\n")
            self.append_results("-" * 40 + "\n")
            
            for r in result['results']:
                suffix_info = f" + '{r['suffix']}'" if r['suffix'] else ""
                match_status = "✅ MATCH" if r['passwords_match'] else "❌ NO MATCH"
                self.append_results(f"Length {r['length']}: {truncate_string(r['password'], 30)}{suffix_info}\n")
                self.append_results(f"  Hash matches base: {match_status}\n")
                
            vulnerability = "⚠️  VULNERABLE" if result['vulnerability_detected'] else "✅ SECURE"
            self.append_results(f"\nVulnerability Status: {vulnerability}\n")
            
            if result['vulnerability_detected']:
                self.append_results("bcrypt truncates passwords at 72 bytes - different suffixes ignored!\n")
        else:
            # Length analysis results
            self.append_results("Password Length Analysis:\n")
            self.append_results("-" * 30 + "\n")
            
            for r in result['results']:
                self.append_results(f"Length {r['length']}: {r['truncated_length']} bytes after truncation\n")
                self.append_results(f"  Password: {truncate_string(r['password'], 40)}\n")
                self.append_results(f"  Hash: {r['hash'][:32]}...\n\n")
        
        self.append_results("=" * 50 + "\n\n")
        
    def display_sha256_no_salt_results(self, result):
        """Display SHA-256 no salt vulnerability results"""
        self.append_results("🔓 SHA-256 NO SALT VULNERABILITY TEST\n")
        self.append_results("=" * 50 + "\n")
        
        self.append_results("User Data Analysis:\n")
        self.append_results("-" * 25 + "\n")
        
        for user in result['users']:
            self.append_results(f"Email: {user['email']}\n")
            self.append_results(f"Password: {user['password']}\n")
            self.append_results(f"Hash: {user['hash']}\n\n")
        
        if result['duplicate_hashes']:
            self.append_results("🚨 DUPLICATE HASHES FOUND:\n")
            for hash_val, emails in result['duplicate_hashes'].items():
                self.append_results(f"Hash: {hash_val}\n")
                self.append_results(f"Users: {', '.join(emails)}\n\n")
        
        vulnerability = "⚠️  VULNERABLE" if result['vulnerability_detected'] else "✅ SECURE"
        self.append_results(f"Vulnerability Status: {vulnerability}\n")
        
        if result['vulnerability_detected']:
            self.append_results("Same passwords produce identical hashes - passwords easily crackable!\n")
        
        self.append_results("=" * 50 + "\n\n")
        
    def display_rainbow_table_results(self, result):
        """Display rainbow table attack results"""
        self.append_results("🌈 RAINBOW TABLE ATTACK SIMULATION\n")
        self.append_results("=" * 50 + "\n")
        
        self.append_results(f"Rainbow Table Size: {result['rainbow_table_size']} entries\n")
        self.append_results(f"User Hashes Tested: {len(result['user_hashes'])}\n\n")
        
        if result['cracked_passwords']:
            self.append_results("🔓 CRACKED PASSWORDS:\n")
            for email, password in result['cracked_passwords'].items():
                self.append_results(f"{email}: {password}\n")
        else:
            self.append_results("No passwords cracked with current rainbow table.\n")
        
        success_rate = (len(result['cracked_passwords']) / len(result['user_hashes'])) * 100
        self.append_results(f"\nSuccess Rate: {success_rate:.1f}%\n")
        
        self.append_results("=" * 50 + "\n\n")
        
    def display_proper_salting_results(self, result):
        """Display proper salting demonstration results"""
        self.append_results("🧂 PROPER SALTING DEMONSTRATION\n")
        self.append_results("=" * 50 + "\n")
        
        self.append_results("User Data with Proper Salting:\n")
        self.append_results("-" * 35 + "\n")
        
        for user in result['users']:
            self.append_results(f"Email: {user['email']}\n")
            self.append_results(f"Password: {user['password']}\n")
            self.append_results(f"Salt: {user['salt']}\n")
            self.append_results(f"Hash: {user['hash']}\n\n")
        
        uniqueness = "✅ ALL UNIQUE" if result['all_unique'] else "⚠️  DUPLICATES FOUND"
        self.append_results(f"Hash Uniqueness: {uniqueness}\n")
        
        if result['all_unique']:
            self.append_results("Even identical passwords have different hashes due to unique salts!\n")
        
        self.append_results("=" * 50 + "\n\n")
        
    def display_weak_salt_results(self, result):
        """Display weak salt analysis results"""
        self.append_results("🧪 WEAK SALT ANALYSIS\n")
        self.append_results("=" * 50 + "\n")
        
        self.append_results(f"Test Password: {result['password']}\n\n")
        
        self.append_results("Salt Strategy Analysis:\n")
        self.append_results("-" * 25 + "\n")
        
        for r in result['results']:
            self.append_results(f"Strategy: {r['strategy']}\n")
            self.append_results(f"Salt: {r['salt']}\n")
            self.append_results(f"Hash: {r['hash']}\n")
            
            if r['vulnerability']:
                self.append_results(f"⚠️  Vulnerability: {r['vulnerability']}\n")
            else:
                self.append_results("✅ Secure\n")
            
            self.append_results("\n")
        
        self.append_results("=" * 50 + "\n\n")
        
    # Event handlers for GUI buttons
    def run_argon2_timing(self):
        """Run Argon2 timing attack demonstration"""
        password = self.argon2_password.get()
        test_passwords = self.argon2_tests.get("1.0", tk.END).strip().split('\n')
        test_passwords = [p.strip() for p in test_passwords if p.strip()]
        
        if not password:
            messagebox.showerror("Error", "Please enter a target password")
            return
            
        if not test_passwords:
            messagebox.showerror("Error", "Please enter test passwords")
            return
            
        self.append_results("🕐 Running Argon2 timing attack...\n")
        self.run_in_thread(self.demo.demonstrate_argon2_timing, password, test_passwords)
        
    def run_bcrypt_truncation(self):
        """Run bcrypt truncation demonstration"""
        suffix = self.bcrypt_suffix.get()
        
        self.append_results("🔒 Running bcrypt truncation test...\n")
        self.run_in_thread(self.demo.demonstrate_bcrypt_truncation, suffix)
        
    def run_bcrypt_length(self):
        """Run bcrypt length analysis"""
        try:
            lengths_str = self.bcrypt_lengths.get()
            lengths = [int(x.strip()) for x in lengths_str.split(',')]
        except ValueError:
            messagebox.showerror("Error", "Please enter valid comma-separated numbers")
            return
            
        self.append_results("📏 Running bcrypt length analysis...\n")
        self.run_in_thread(self.demo.demonstrate_bcrypt_length_analysis, lengths)
        
    def run_sha256_no_salt(self):
        """Run SHA-256 no salt demonstration"""
        user_data = self.sha256_users.get("1.0", tk.END).strip()
        users = []
        
        for line in user_data.split('\n'):
            line = line.strip()
            if ':' in line:
                email, password = line.split(':', 1)
                users.append({'email': email.strip(), 'password': password.strip()})
                
        if not users:
            messagebox.showerror("Error", "Please enter user data in email:password format")
            return
            
        self.append_results("🔓 Running SHA-256 no salt vulnerability test...\n")
        self.run_in_thread(self.demo.demonstrate_sha256_no_salt, users)
        
    def run_rainbow_table(self):
        """Run rainbow table attack demonstration"""
        user_data = self.sha256_users.get("1.0", tk.END).strip()
        users = []
        
        for line in user_data.split('\n'):
            line = line.strip()
            if ':' in line:
                email, password = line.split(':', 1)
                users.append({'email': email.strip(), 'password': password.strip()})
                
        if not users:
            messagebox.showerror("Error", "Please enter user data in email:password format")
            return
            
        self.append_results("🌈 Running rainbow table attack...\n")
        self.run_in_thread(self.demo.demonstrate_rainbow_table_attack, users)
        
    def run_proper_salting(self):
        """Run proper salting demonstration"""
        user_data = self.sha256_users.get("1.0", tk.END).strip()
        users = []
        
        for line in user_data.split('\n'):
            line = line.strip()
            if ':' in line:
                email, password = line.split(':', 1)
                users.append({'email': email.strip(), 'password': password.strip()})
                
        if not users:
            messagebox.showerror("Error", "Please enter user data in email:password format")
            return
            
        self.append_results("🧂 Running proper salting demonstration...\n")
        self.run_in_thread(self.demo.demonstrate_proper_salting, users)
        
    def run_weak_salt_analysis(self):
        """Run weak salt analysis"""
        password = self.salt_test_password.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a test password")
            return
            
        self.append_results("🧪 Running weak salt analysis...\n")
        self.run_in_thread(self.demo.demonstrate_weak_salt_analysis, password)


def main():
    """Main application entry point"""
    root = tk.Tk()
    app = CryptoSecurityGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()