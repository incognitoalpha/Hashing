import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog, ttk
from tkinter.scrolledtext import ScrolledText
import threading
import matplotlib

matplotlib.use('TkAgg')  # Use TkAgg backend for thread safety
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from hash_backend import (
    AttackProgress, AttackConfig,
    hash_md5, hash_sha256, hash_bcrypt, hash_argon2,
    brute_force_attack_hashlib, brute_force_attack_bcrypt, brute_force_attack_argon2,
    dictionary_attack_hashlib, dictionary_attack_bcrypt, dictionary_attack_argon2,
    demonstrate_md5_collision, identify_hash_type, length_extension_attack_demo,
    validate_installation, run_quick_test
)
import psutil  # For memory monitoring


class HashingApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Password Hashing & Cracking Simulator")
        self.geometry("1000x700")
        self.configure(bg="#ffffff")

        # Hash storage
        self.md5_hash = None
        self.sha256_hash = None
        self.bcrypt_hash = None
        self.argon2_hash = None

        # Progress tracking
        self.current_progress = None
        self.progress_var = tk.StringVar()
        self.progress_var.set("Ready")

        self.create_widgets()

    def create_widgets(self):
        # Title
        self.title_label = tk.Label(self, text="🔐 Password Hash & Crack Simulator",
                                    font=("Helvetica", 28, "bold"),
                                    fg="#111111", bg="#ffffff")
        self.title_label.pack(pady=20)

        # Progress bar and status
        progress_frame = tk.Frame(self, bg="#ffffff")
        progress_frame.pack(fill=tk.X, padx=20, pady=5)

        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)

        self.status_label = tk.Label(progress_frame, textvariable=self.progress_var,
                                     font=("Helvetica", 10), bg="#ffffff")
        self.status_label.pack()

        # Cancel button (initially hidden)
        self.cancel_button = tk.Button(progress_frame, text="Cancel Attack",
                                       command=self.cancel_attack, bg="#ff4444", fg="white",
                                       font=("Helvetica", 10, "bold"))

        # Output box
        self.output_box = ScrolledText(self, height=20, bg="#fefefe", fg="#374151",
                                       font=("Consolas", 18, "bold"), wrap=tk.WORD)
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=20)

        # Button frame
        btn_frame = tk.Frame(self, bg="#ffffff")
        btn_frame.pack(pady=15, fill=tk.X, padx=20)

        button_specs = [
            ("1. Hash Password", self.hash_password),
            ("2. Brute-force Attack", self.brute_force_attack),
            ("3. Dictionary Attack", self.dictionary_attack),
            ("4. Show Complexity Graphs", self.show_complexity_graphs),
            ("5. Show Sample Hashes", self.show_sample_hashes),
            ("6. Memory Usage Analysis", self.demonstrate_md5_collision),
            ("7. Identify Hash Type", self.identify_hash_type_popup),
            ("8. Length Extension Demo", self.length_extension_demo),
        ]

        for idx, (text, cmd) in enumerate(button_specs):
            btn = tk.Button(btn_frame, text=text, command=cmd,
                            bg="#f3f4f6", fg="#111111",
                            font=("Helvetica", 14, "bold"), relief=tk.FLAT)
            btn.grid(row=idx // 4, column=idx % 4, padx=10, pady=8, sticky="nsew")
            btn_frame.grid_columnconfigure(idx % 4, weight=1)

    def update_progress(self, current, total, message=""):
        """Update progress bar and status"""
        if total > 0:
            progress = (current / total) * 100
            self.progress_bar['value'] = progress
        else:
            self.progress_bar['mode'] = 'indeterminate'
            self.progress_bar.start()

        status_text = f"{message} ({current}/{total})" if total > 0 else message
        self.progress_var.set(status_text)
        self.update_idletasks()

    def cancel_attack(self):
        """Cancel current attack"""
        if self.current_progress:
            self.current_progress.cancel()
            self.progress_var.set("Attack cancelled")
            self.cancel_button.pack_forget()

    def show_progress(self, show=True):
        """Show/hide progress elements"""
        if show:
            self.cancel_button.pack(pady=5)
        else:
            self.cancel_button.pack_forget()
            self.progress_bar.stop()
            self.progress_bar['mode'] = 'determinate'
            self.progress_bar['value'] = 0
            self.progress_var.set("Ready")

    def append_text(self, text):
        self.output_box.configure(bg="#ffffff")
        self.output_box.insert(tk.END, text + "\n")
        self.output_box.see(tk.END)

    def hash_password(self):
        pw = simpledialog.askstring("Input Password", "Enter the password to hash:")
        if not pw:
            return

        try:
            self.md5_hash = hash_md5(pw)
            self.sha256_hash = hash_sha256(pw)
            self.bcrypt_hash = hash_bcrypt(pw)
            self.argon2_hash = hash_argon2(pw)

            self.append_text(f"\n🧪 Password hashed:\n"
                             f"MD5:     {self.md5_hash}\n"
                             f"SHA-256: {self.sha256_hash}\n"
                             f"bcrypt:  {self.bcrypt_hash}\n"
                             f"Argon2:  {self.argon2_hash}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hash password: {str(e)}")

    def brute_force_attack(self):
        if not all([self.md5_hash, self.sha256_hash, self.bcrypt_hash, self.argon2_hash]):
            messagebox.showwarning("Warning", "First hash a password (Option 1).")
            return

        # Get attack configuration
        max_length = simpledialog.askinteger("Brute Force Config",
                                             "Maximum password length:",
                                             initialvalue=4, minvalue=1, maxvalue=8)
        if not max_length:
            return

        config = AttackConfig(max_length=max_length, max_time=60)

        def task():
            try:
                self.show_progress(True)
                self.current_progress = AttackProgress(self.update_progress)

                self.append_text("\n🚨 Starting Brute-force Attacks...")

                # Attack configurations
                attacks = [
                    ("MD5", brute_force_attack_hashlib, hash_md5, self.md5_hash),
                    ("SHA-256", brute_force_attack_hashlib, hash_sha256, self.sha256_hash),
                    ("bcrypt", brute_force_attack_bcrypt, None, self.bcrypt_hash),
                    ("Argon2", brute_force_attack_argon2, None, self.argon2_hash)
                ]

                results = []
                for label, attack_func, hash_func, target_hash in attacks:
                    if self.current_progress.cancelled:
                        break

                    self.progress_var.set(f"Attacking {label}...")

                    if hash_func:  # hashlib functions
                        result, attempts, duration = attack_func(target_hash, hash_func, config, self.current_progress)
                    else:  # bcrypt/argon2 functions
                        result, attempts, duration = attack_func(target_hash, config, self.current_progress)

                    results.append((label, result, attempts, duration))
                    status = "SUCCESS" if result else "FAILED"
                    self.append_text(
                        f"{label} ({status}): {result or 'Not found'} - {attempts} attempts ({duration:.2f}s)")

                # Show comparison graph on main thread
                if results and not self.current_progress.cancelled:
                    self.after(0, lambda: self.show_attack_results_graph(results, "Brute-force Attack Results"))

            except Exception as e:
                messagebox.showerror("Error", f"Brute force attack failed: {str(e)}")
            finally:
                self.show_progress(False)
                self.current_progress = None

        threading.Thread(target=task, daemon=True).start()

    def dictionary_attack(self):
        if not all([self.md5_hash, self.sha256_hash, self.bcrypt_hash, self.argon2_hash]):
            messagebox.showwarning("Warning", "First hash a password (Option 1).")
            return

        dict_path = filedialog.askopenfilename(title="Select dictionary file",
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not dict_path:
            return

        def task():
            try:
                self.show_progress(True)
                self.current_progress = AttackProgress(self.update_progress)

                self.append_text("\n📖 Starting Dictionary Attacks...")

                # Attack configurations
                attacks = [
                    ("MD5", dictionary_attack_hashlib, hash_md5, self.md5_hash),
                    ("SHA-256", dictionary_attack_hashlib, hash_sha256, self.sha256_hash),
                    ("bcrypt", dictionary_attack_bcrypt, None, self.bcrypt_hash),
                    ("Argon2", dictionary_attack_argon2, None, self.argon2_hash)
                ]

                results = []
                for label, attack_func, hash_func, target_hash in attacks:
                    if self.current_progress.cancelled:
                        break

                    self.progress_var.set(f"Dictionary attack on {label}...")

                    if hash_func:  # hashlib functions
                        result, attempts, duration = attack_func(target_hash, hash_func, dict_path,
                                                                 self.current_progress)
                    else:  # bcrypt/argon2 functions
                        result, attempts, duration = attack_func(target_hash, dict_path, self.current_progress)

                    results.append((label, result, attempts, duration))
                    status = "SUCCESS" if result else "FAILED"
                    self.append_text(
                        f"{label} ({status}): {result or 'Not found'} - {attempts} attempts ({duration:.2f}s)")

                # Show comparison graph on main thread
                if results and not self.current_progress.cancelled:
                    self.after(0, lambda: self.show_attack_results_graph(results, "Dictionary Attack Results"))

            except Exception as e:
                messagebox.showerror("Error", f"Dictionary attack failed: {str(e)}")
            finally:
                self.show_progress(False)
                self.current_progress = None

        threading.Thread(target=task, daemon=True).start()

    def show_complexity_graphs(self):
        """Show time complexity comparison graphs"""
        try:
            self.show_time_complexity_graph()
            self.append_text("\n📊 Time complexity graphs displayed.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to show graphs: {str(e)}")

    def show_time_complexity_graph(self):
        """Show time complexity graph in a new window"""
        graph_window = tk.Toplevel(self)
        graph_window.title("Hash Algorithm Time Complexity")
        graph_window.geometry("800x600")

        # Create matplotlib figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Password lengths for comparison
        lengths = list(range(1, 9))

        # Theoretical attack attempts (lowercase letters only)
        md5_attempts = [26 ** i for i in lengths]
        sha256_attempts = [26 ** i for i in lengths]
        bcrypt_attempts = [26 ** i * 100 for i in lengths]  # Slower due to rounds
        argon2_attempts = [26 ** i * 1000 for i in lengths]  # Even slower

        # Plot 1: Linear scale
        ax1.plot(lengths, md5_attempts, 'r-', label='MD5', linewidth=2)
        ax1.plot(lengths, sha256_attempts, 'b-', label='SHA-256', linewidth=2)
        ax1.plot(lengths, bcrypt_attempts, 'g-', label='bcrypt', linewidth=2)
        ax1.plot(lengths, argon2_attempts, 'orange', label='Argon2', linewidth=2)
        ax1.set_xlabel('Password Length')
        ax1.set_ylabel('Estimated Attack Attempts')
        ax1.set_title('Brute Force Complexity (Linear Scale)')
        ax1.legend()
        ax1.grid(True, alpha=0.3)

        # Plot 2: Log scale
        ax2.semilogy(lengths, md5_attempts, 'r-', label='MD5', linewidth=2)
        ax2.semilogy(lengths, sha256_attempts, 'b-', label='SHA-256', linewidth=2)
        ax2.semilogy(lengths, bcrypt_attempts, 'g-', label='bcrypt', linewidth=2)
        ax2.semilogy(lengths, argon2_attempts, 'orange', label='Argon2', linewidth=2)
        ax2.set_xlabel('Password Length')
        ax2.set_ylabel('Estimated Attack Attempts (log scale)')
        ax2.set_title('Brute Force Complexity (Log Scale)')
        ax2.legend()
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()

        # Embed in tkinter window
        canvas = FigureCanvasTkAgg(fig, graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_attack_results_graph(self, results, title):
        """Show attack results in a bar chart"""
        graph_window = tk.Toplevel(self)
        graph_window.title(title)
        graph_window.geometry("800x600")

        # Create matplotlib figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        # Extract data
        labels = [r[0] for r in results]
        success = [1 if r[1] else 0 for r in results]
        attempts = [r[2] for r in results]
        durations = [r[3] for r in results]

        # Plot 1: Success rate
        colors = ['green' if s else 'red' for s in success]
        ax1.bar(labels, success, color=colors, alpha=0.7)
        ax1.set_ylabel('Success (1) / Failure (0)')
        ax1.set_title('Attack Success Rate')
        ax1.set_ylim(0, 1.2)

        # Plot 2: Time taken
        ax2.bar(labels, durations, color='blue', alpha=0.7)
        ax2.set_ylabel('Time (seconds)')
        ax2.set_title('Attack Duration')

        plt.xticks(rotation=45)
        plt.tight_layout()

        # Embed in tkinter window
        canvas = FigureCanvasTkAgg(fig, graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_sample_hashes(self):
        """Display sample hashes for common passwords"""
        sample_passwords = ["password", "123456", "admin", "qwerty", "letmein"]

        self.append_text("\n🔍 Sample Hash Comparison:")
        self.append_text("=" * 80)

        for pw in sample_passwords:
            try:
                md5 = hash_md5(pw)
                sha256 = hash_sha256(pw)
                bcrypt_hash = hash_bcrypt(pw)
                argon2_hash = hash_argon2(pw)

                self.append_text(f"\nPassword: '{pw}'")
                self.append_text(f"MD5:     {md5}")
                self.append_text(f"SHA-256: {sha256}")
                self.append_text(f"bcrypt:  {bcrypt_hash}")
                self.append_text(f"Argon2:  {argon2_hash}")
                self.append_text("-" * 40)
            except Exception as e:
                self.append_text(f"Error hashing '{pw}': {str(e)}")

    def demonstrate_md5_collision(self):
        """Show memory usage analysis for all hashing functions"""
        try:
            self.show_memory_usage_analysis()
        except Exception as e:
            messagebox.showerror("Error", f"Memory analysis failed: {str(e)}")

    def show_memory_usage_analysis(self):
        """Analyze and display memory usage for different hashing algorithms"""
        import psutil
        import os
        import gc
        import sys

        self.append_text("\n🧠 Memory Usage Analysis for Hashing Algorithms:")
        self.append_text("=" * 70)

        # Test password
        test_password = "TestPassword123!"

        # Memory analysis for each algorithm
        algorithms = [
            ("MD5", hash_md5),
            ("SHA-256", hash_sha256),
            ("bcrypt", hash_bcrypt),
            ("Argon2", hash_argon2)
        ]

        memory_results = []

        for algo_name, hash_func in algorithms:
            try:
                # Force garbage collection before measurement
                gc.collect()

                # Get initial memory
                process = psutil.Process(os.getpid())
                initial_memory = process.memory_info().rss / 1024  # KB

                # Perform hashing operation
                hash_result = hash_func(test_password)

                # Get memory after hashing
                final_memory = process.memory_info().rss / 1024  # KB
                memory_used = final_memory - initial_memory

                # Theoretical memory complexity analysis
                if algo_name in ["MD5", "SHA-256"]:
                    complexity = "O(1) - Constant space"
                    theoretical_kb = "~1-2 KB (fixed buffer size)"
                elif algo_name == "bcrypt":
                    complexity = "O(1) - Constant space with salt"
                    theoretical_kb = "~4-8 KB (salt + rounds)"
                else:  # Argon2
                    complexity = "O(m) - Linear with memory parameter"
                    theoretical_kb = "~64-1024 KB (configurable memory)"

                memory_results.append({
                    'algorithm': algo_name,
                    'measured_kb': max(0, memory_used),  # Ensure non-negative
                    'complexity': complexity,
                    'theoretical': theoretical_kb,
                    'hash_length': len(hash_result)
                })

                # Display individual results
                self.append_text(f"\n🔍 {algo_name}:")
                self.append_text(f"   Space Complexity: {complexity}")
                self.append_text(f"   Theoretical Memory: {theoretical_kb}")
                self.append_text(f"   Measured Memory: {memory_used:.2f} KB")
                self.append_text(f"   Hash Output Length: {len(hash_result)} characters")

            except Exception as e:
                self.append_text(f"   Error analyzing {algo_name}: {str(e)}")
                memory_results.append({
                    'algorithm': algo_name,
                    'measured_kb': 0,
                    'complexity': "Error",
                    'theoretical': "N/A",
                    'hash_length': 0
                })

        # Memory comparison analysis
        self.append_text("\n📊 Comparative Memory Analysis:")
        self.append_text("-" * 50)

        # Big O complexity summary
        self.append_text("\n🔢 Space Complexity Summary:")
        complexity_info = {
            "MD5": "O(1) - Uses fixed 64-byte internal buffer",
            "SHA-256": "O(1) - Uses fixed 64-byte internal buffer",
            "bcrypt": "O(1) - Constant space + salt storage",
            "Argon2": "O(m) - Memory-hard function, m = memory parameter"
        }

        for algo, info in complexity_info.items():
            self.append_text(f"   {algo:10}: {info}")

        # Security vs Memory trade-off
        self.append_text("\n⚖️ Security vs Memory Trade-off:")
        self.append_text("   MD5/SHA-256: Fast, low memory, but vulnerable to attacks")
        self.append_text("   bcrypt:      Moderate memory, good against brute force")
        self.append_text("   Argon2:      High memory usage, best protection against")
        self.append_text("                specialized hardware attacks (ASICs/GPUs)")

        # Memory efficiency recommendations
        self.append_text("\n💡 Memory Efficiency Recommendations:")
        self.append_text("   • Embedded systems: Use bcrypt with low rounds")
        self.append_text("   • Server applications: Use Argon2 with adequate memory")
        self.append_text("   • Mobile devices: Balance security vs battery life")
        self.append_text("   • High-security: Argon2 with maximum feasible memory")

        # Create memory usage visualization
        self.after(0, lambda: self.show_memory_usage_graph(memory_results))

    def show_memory_usage_graph(self, memory_results):
        """Show memory usage visualization"""
        graph_window = tk.Toplevel(self)
        graph_window.title("Hash Algorithm Memory Usage Analysis")
        graph_window.geometry("1000x700")

        # Create matplotlib figure with multiple subplots
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))

        algorithms = [r['algorithm'] for r in memory_results]
        measured_memory = [r['measured_kb'] for r in memory_results]
        hash_lengths = [r['hash_length'] for r in memory_results]

        # Plot 1: Measured memory usage
        colors = ['red', 'blue', 'green', 'orange']
        bars1 = ax1.bar(algorithms, measured_memory, color=colors, alpha=0.7)
        ax1.set_ylabel('Memory Usage (KB)')
        ax1.set_title('Measured Memory Usage During Hashing')
        ax1.tick_params(axis='x', rotation=45)

        # Add value labels on bars
        for bar, value in zip(bars1, measured_memory):
            if value > 0:
                ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                         f'{value:.1f} KB', ha='center', va='bottom')

        # Plot 2: Theoretical memory complexity
        theoretical_values = [1, 1, 4, 64]  # Approximate KB values for visualization
        bars2 = ax2.bar(algorithms, theoretical_values, color=colors, alpha=0.7)
        ax2.set_ylabel('Theoretical Memory (KB)')
        ax2.set_title('Theoretical Memory Requirements')
        ax2.tick_params(axis='x', rotation=45)

        for bar, value in zip(bars2, theoretical_values):
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f'{value} KB', ha='center', va='bottom')

        # Plot 3: Hash output length comparison
        bars3 = ax3.bar(algorithms, hash_lengths, color=colors, alpha=0.7)
        ax3.set_ylabel('Hash Length (characters)')
        ax3.set_title('Hash Output Length Comparison')
        ax3.tick_params(axis='x', rotation=45)

        for bar, value in zip(bars3, hash_lengths):
            if value > 0:
                ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                         f'{value}', ha='center', va='bottom')

        # Plot 4: Security vs Performance matrix
        security_scores = [1, 3, 7, 9]  # Relative security scores
        performance_scores = [10, 9, 6, 4]  # Relative performance scores (inverse of time)

        scatter = ax4.scatter(performance_scores, security_scores,
                              c=colors, s=200, alpha=0.7)
        ax4.set_xlabel('Performance Score (Higher = Faster)')
        ax4.set_ylabel('Security Score (Higher = More Secure)')
        ax4.set_title('Security vs Performance Trade-off')
        ax4.grid(True, alpha=0.3)

        # Add algorithm labels to scatter plot
        for i, algo in enumerate(algorithms):
            ax4.annotate(algo, (performance_scores[i], security_scores[i]),
                         xytext=(5, 5), textcoords='offset points')

        plt.tight_layout()

        # Embed in tkinter window
        canvas = FigureCanvasTkAgg(fig, graph_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Add explanation text
        explanation_frame = tk.Frame(graph_window, bg='lightgray')
        explanation_frame.pack(fill=tk.X, padx=10, pady=5)

        explanation_text = """
        Memory Analysis Explanation:
        • MD5/SHA-256: O(1) space - use fixed internal buffers regardless of input size
        • bcrypt: O(1) space - constant memory with salt, rounds increase time not space  
        • Argon2: O(m) space - memory-hard function, intentionally uses large amounts of RAM
        • Higher memory usage in Argon2 provides better protection against specialized attacks
        """

        explanation_label = tk.Label(explanation_frame, text=explanation_text,
                                     bg='lightgray', justify=tk.LEFT, font=('Consolas', 10))
        explanation_label.pack(anchor=tk.W)

    def identify_hash_type_popup(self):
        """Popup to identify hash type"""
        hash_input = simpledialog.askstring("Hash Identification",
                                            "Enter a hash to identify its type:")
        if not hash_input:
            return

        try:
            hash_type = identify_hash_type(hash_input.strip())
            self.append_text(f"\n🔍 Hash Type Identification:")
            self.append_text(f"Input: {hash_input}")
            self.append_text(f"Likely type: {hash_type}")
        except Exception as e:
            messagebox.showerror("Error", f"Hash identification failed: {str(e)}")

    def length_extension_demo(self):
        """Demonstrate length extension attack"""
        try:
            demo_info = length_extension_attack_demo()
            self.append_text("\n⚠️ Length Extension Attack Demo:")
            self.append_text("=" * 50)
            self.append_text(demo_info)
        except Exception as e:
            messagebox.showerror("Error", f"Length extension demo failed: {str(e)}")

    def clear_output(self):
        """Clear the output text box"""
        self.output_box.delete(1.0, tk.END)

    def save_output(self):
        """Save output to file"""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                with open(file_path, 'w') as f:
                    f.write(self.output_box.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Output saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save output: {str(e)}")


def main():
    """Main function to run the application"""
    try:
        # Validate backend installation
        if not validate_installation():
            messagebox.showerror("Setup Error",
                                 "Backend dependencies not properly installed. "
                                 "Please check hash_backend.py and required libraries.")
            return

        # Run quick test
        if not run_quick_test():
            messagebox.showwarning("Warning",
                                   "Some backend functions may not work properly. "
                                   "Application will start but functionality may be limited.")

        # Create and run the GUI
        app = HashingApp()

        # Add menu bar
        menubar = tk.Menu(app)
        app.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Clear Output", command=app.clear_output)
        file_menu.add_command(label="Save Output", command=app.save_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=app.quit)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About",
                              command=lambda: messagebox.showinfo("About",
                                                                  "Password Hashing & Cracking Simulator\n"
                                                                  "Educational tool for cybersecurity learning\n"
                                                                  "Version 1.0"))

        # Welcome message
        app.append_text("🔐 Welcome to the Password Hashing & Cracking Simulator!")
        app.append_text("=" * 60)
        app.append_text("This educational tool demonstrates various hashing algorithms")
        app.append_text("and attack methods for cybersecurity learning purposes.")
        app.append_text("\nInstructions:")
        app.append_text("1. Start by hashing a password")
        app.append_text("2. Try different attack methods")
        app.append_text("3. Compare security between hash types")
        app.append_text("4. Explore vulnerability demonstrations")
        app.append_text("\n⚠️  For educational purposes only!")
        app.append_text("=" * 60)

        app.mainloop()

    except Exception as e:
        messagebox.showerror("Application Error", f"Failed to start application: {str(e)}")


if __name__ == "__main__":
    main()