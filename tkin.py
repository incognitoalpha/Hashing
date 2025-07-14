import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import statistics
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import queue
import sys


class Argon2TimingSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Argon2 Timing Attack Simulator - Educational Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # Configure colors
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'light': '#ecf0f1',
            'dark': '#34495e'
        }

        # Queue for thread communication
        self.result_queue = queue.Queue()
        self.is_running = False

        self.setup_ui()
        self.setup_styles()

    def setup_styles(self):
        """Configure custom styles for the application"""
        self.style.configure('Title.TLabel',
                             font=('Arial', 16, 'bold'),
                             background='#f0f0f0',
                             foreground=self.colors['primary'])

        self.style.configure('Header.TLabel',
                             font=('Arial', 12, 'bold'),
                             background='#f0f0f0',
                             foreground=self.colors['dark'])

        self.style.configure('Success.TLabel',
                             font=('Arial', 10, 'bold'),
                             foreground=self.colors['success'])

        self.style.configure('Warning.TLabel',
                             font=('Arial', 10, 'bold'),
                             foreground=self.colors['warning'])

        self.style.configure('Danger.TLabel',
                             font=('Arial', 10, 'bold'),
                             foreground=self.colors['danger'])

    def setup_ui(self):
        """Setup the main user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)

        # Title
        title_label = ttk.Label(main_frame,
                                text="🎓 Argon2 Timing Attack Simulator",
                                style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))

        # Subtitle
        subtitle_label = ttk.Label(main_frame,
                                   text="Educational Cryptography Demonstration - For Learning Purposes Only",
                                   font=('Arial', 10, 'italic'),
                                   foreground=self.colors['secondary'])
        subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))

        # Left panel - Configuration
        self.setup_config_panel(main_frame)

        # Right panel - Results
        self.setup_results_panel(main_frame)

        # Bottom panel - Controls
        self.setup_controls_panel(main_frame)

        # Status bar
        self.setup_status_bar()

    def setup_config_panel(self, parent):
        """Setup the configuration panel"""
        config_frame = ttk.LabelFrame(parent, text="Configuration", padding="15")
        config_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        # Target password
        ttk.Label(config_frame, text="Target Password:", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W,
                                                                                     pady=(0, 5))
        self.password_var = tk.StringVar(value="MySecurePassword123!")
        password_entry = ttk.Entry(config_frame, textvariable=self.password_var, width=30, show="*")
        password_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_check = ttk.Checkbutton(config_frame, text="Show password",
                                     variable=self.show_password_var,
                                     command=self.toggle_password_visibility)
        show_check.grid(row=2, column=0, sticky=tk.W, pady=(0, 15))
        self.password_entry = password_entry

        # Argon2 Parameters
        ttk.Label(config_frame, text="Argon2 Parameters:", style='Header.TLabel').grid(row=3, column=0, sticky=tk.W,
                                                                                       pady=(0, 5))

        params_frame = ttk.Frame(config_frame)
        params_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 15))

        # Time cost
        ttk.Label(params_frame, text="Time Cost:").grid(row=0, column=0, sticky=tk.W)
        self.time_cost_var = tk.IntVar(value=2)
        ttk.Spinbox(params_frame, from_=1, to=10, textvariable=self.time_cost_var, width=10).grid(row=0, column=1,
                                                                                                  padx=(5, 0))

        # Memory cost
        ttk.Label(params_frame, text="Memory Cost (KiB):").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.memory_cost_var = tk.IntVar(value=65536)
        ttk.Entry(params_frame, textvariable=self.memory_cost_var, width=10).grid(row=1, column=1, padx=(5, 0),
                                                                                  pady=(5, 0))

        # Number of trials
        ttk.Label(config_frame, text="Trials per Test:", style='Header.TLabel').grid(row=5, column=0, sticky=tk.W,
                                                                                     pady=(0, 5))
        self.trials_var = tk.IntVar(value=10)
        ttk.Spinbox(config_frame, from_=1, to=50, textvariable=self.trials_var, width=10).grid(row=6, column=0,
                                                                                               sticky=tk.W)

        # Test type selection
        ttk.Label(config_frame, text="Test Type:", style='Header.TLabel').grid(row=7, column=0, sticky=tk.W,
                                                                               pady=(15, 5))
        self.test_type_var = tk.StringVar(value="comprehensive")

        test_type_frame = ttk.Frame(config_frame)
        test_type_frame.grid(row=8, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Radiobutton(test_type_frame, text="Comprehensive Analysis",
                        variable=self.test_type_var, value="comprehensive").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(test_type_frame, text="Prefix-Based Attack",
                        variable=self.test_type_var, value="prefix").grid(row=1, column=0, sticky=tk.W)

        config_frame.columnconfigure(0, weight=1)

    def setup_results_panel(self, parent):
        """Setup the results display panel"""
        results_frame = ttk.LabelFrame(parent, text="Results", padding="15")
        results_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame,
                                                      width=60, height=30,
                                                      font=('Consolas', 9),
                                                      wrap=tk.WORD)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure text tags for colored output
        self.results_text.tag_configure("success", foreground=self.colors['success'], font=('Consolas', 9, 'bold'))
        self.results_text.tag_configure("warning", foreground=self.colors['warning'], font=('Consolas', 9, 'bold'))
        self.results_text.tag_configure("danger", foreground=self.colors['danger'], font=('Consolas', 9, 'bold'))
        self.results_text.tag_configure("header", foreground=self.colors['primary'], font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure("info", foreground=self.colors['secondary'])

        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

    def setup_controls_panel(self, parent):
        """Setup the control buttons panel"""
        controls_frame = ttk.Frame(parent)
        controls_frame.grid(row=3, column=0, columnspan=2, pady=(20, 0), sticky=(tk.W, tk.E))

        # Run button
        self.run_button = ttk.Button(controls_frame, text="🚀 Run Simulation",
                                     command=self.run_simulation, style='Accent.TButton')
        self.run_button.grid(row=0, column=0, padx=(0, 10))

        # Stop button
        self.stop_button = ttk.Button(controls_frame, text="⏹ Stop",
                                      command=self.stop_simulation, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=(0, 10))

        # Clear button
        clear_button = ttk.Button(controls_frame, text="🗑 Clear Results",
                                  command=self.clear_results)
        clear_button.grid(row=0, column=2, padx=(0, 10))

        # Export button
        export_button = ttk.Button(controls_frame, text="💾 Export Results",
                                   command=self.export_results)
        export_button.grid(row=0, column=3, padx=(0, 10))

        # Progress bar
        self.progress = ttk.Progressbar(controls_frame, mode='indeterminate')
        self.progress.grid(row=0, column=4, sticky=(tk.W, tk.E), padx=(20, 0))

        controls_frame.columnconfigure(4, weight=1)

    def setup_status_bar(self):
        """Setup the status bar at the bottom"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=20, pady=(0, 10))

        self.status_var = tk.StringVar(value="Ready to run simulation")
        self.status_label = ttk.Label(self.status_frame, textvariable=self.status_var,
                                      font=('Arial', 9), foreground=self.colors['dark'])
        self.status_label.grid(row=0, column=0, sticky=tk.W)

        # Version info
        version_label = ttk.Label(self.status_frame, text="v1.0 | Educational Use Only",
                                  font=('Arial', 8), foreground='gray')
        version_label.grid(row=0, column=1, sticky=tk.E)

        self.status_frame.columnconfigure(0, weight=1)

    def toggle_password_visibility(self):
        """Toggle password visibility in the entry field"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def log_message(self, message, tag=""):
        """Add a message to the results text area"""
        self.results_text.insert(tk.END, message + "\n", tag)
        self.results_text.see(tk.END)
        self.root.update_idletasks()

    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Results cleared")

    def export_results(self):
        """Export results to a text file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Export Results"
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.results_text.get(1.0, tk.END))
                self.status_var.set(f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")

    def update_status(self, message):
        """Update the status bar"""
        self.status_var.set(message)

    def run_simulation(self):
        """Start the simulation in a separate thread"""
        if self.is_running:
            return

        self.is_running = True
        self.run_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress.start()

        # Start simulation thread
        simulation_thread = threading.Thread(target=self.simulation_worker, daemon=True)
        simulation_thread.start()

        # Start result processor
        self.root.after(100, self.process_results)

    def stop_simulation(self):
        """Stop the running simulation"""
        self.is_running = False
        self.run_button.configure(state='normal')
        self.stop_button.configure(state='disabled')
        self.progress.stop()
        self.update_status("Simulation stopped")

    def simulation_worker(self):
        """Worker thread for running the simulation"""
        try:
            if self.test_type_var.get() == "comprehensive":
                self.run_comprehensive_analysis()
            else:
                self.run_prefix_attack()
        except Exception as e:
            self.result_queue.put(("error", str(e)))
        finally:
            self.result_queue.put(("complete", ""))

    def run_comprehensive_analysis(self):
        """Run comprehensive timing analysis"""
        try:
            # Initialize Argon2
            ph = PasswordHasher(
                time_cost=self.time_cost_var.get(),
                memory_cost=self.memory_cost_var.get(),
                parallelism=1,
                hash_len=32,
                salt_len=16
            )

            correct_password = self.password_var.get()
            hashed = ph.hash(correct_password)

            self.result_queue.put(("header", "=" * 80))
            self.result_queue.put(("header", "EDUCATIONAL ARGON2 TIMING LEAK SIMULATION"))
            self.result_queue.put(("header", "=" * 80))
            self.result_queue.put(("info", f"Target password: {correct_password}"))
            self.result_queue.put(("info", f"Argon2 hash: {hashed[:50]}..."))
            self.result_queue.put(("info", ""))

            # Test cases
            test_cases = [
                ("wrong", "Completely incorrect"),
                ("password", "Common weak password"),
                ("12345", "Numeric only"),
                ("M", "Single correct char"),
                ("My", "Two correct chars"),
                ("MyS", "Three correct chars"),
                ("MySecure", "Partial match (8 chars)"),
                ("MySecurePass", "Longer partial match"),
                ("MySecurePassword", "Almost complete"),
                ("MySecurePassword12", "Very close match"),
                ("MySecurePassword123", "Missing final char"),
                (correct_password, "Correct password"),
                ("MySecurePassword123?", "Wrong final char"),
                ("mysecurepassword123!", "Wrong case"),
                ("MySecurePassword 123!", "Extra space")
            ]

            self.result_queue.put(("info", "Testing different password attempts..."))
            self.result_queue.put(("info", "-" * 80))

            results = []
            total_tests = len(test_cases)

            for i, (password_attempt, description) in enumerate(test_cases):
                if not self.is_running:
                    break

                self.result_queue.put(("status", f"Testing {i + 1}/{total_tests}: {description}"))

                # Run multiple trials
                times = []
                for trial in range(self.trials_var.get()):
                    if not self.is_running:
                        break

                    start_time = time.perf_counter()
                    try:
                        ph.verify(hashed, password_attempt)
                        verification_success = True
                    except VerifyMismatchError:
                        verification_success = False
                    except Exception:
                        verification_success = False

                    end_time = time.perf_counter()
                    times.append(end_time - start_time)

                if times:
                    avg_time = statistics.mean(times)
                    std_dev = statistics.stdev(times) if len(times) > 1 else 0

                    results.append({
                        'password': password_attempt,
                        'description': description,
                        'avg_time': avg_time,
                        'std_dev': std_dev,
                        'success': verification_success
                    })

                    status = "✓ SUCCESS" if verification_success else "✗ FAILED"
                    tag = "success" if verification_success else "danger"

                    result_text = (f"Password: {password_attempt:<25} | {description:<20} | "
                                   f"Avg: {avg_time:.6f}s | StdDev: {std_dev:.6f}s | {status}")
                    self.result_queue.put((tag, result_text))

            if self.is_running and results:
                self.analyze_results(results)

        except Exception as e:
            self.result_queue.put(("error", f"Error in comprehensive analysis: {str(e)}"))

    def run_prefix_attack(self):
        """Run prefix-based timing attack simulation"""
        try:
            ph = PasswordHasher(time_cost=1, memory_cost=1024)
            target = self.password_var.get()
            hashed = ph.hash(target)

            self.result_queue.put(("header", "=" * 80))
            self.result_queue.put(("header", "PREFIX-BASED TIMING ATTACK SIMULATION"))
            self.result_queue.put(("header", "=" * 80))
            self.result_queue.put(("info", f"Target: {target}"))
            self.result_queue.put(("info", "Attempting to discover password character by character..."))
            self.result_queue.put(("info", ""))

            discovered = ""
            charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"

            for position in range(min(len(target), 10)):  # Limit to first 10 chars for demo
                if not self.is_running:
                    break

                self.result_queue.put(("info", f"Discovering character at position {position + 1}..."))
                self.result_queue.put(("status", f"Attacking position {position + 1}/{len(target)}"))

                candidates = []

                for char in charset:
                    if not self.is_running:
                        break

                    test_password = discovered + char + "?" * (len(target) - position - 1)

                    times = []
                    for _ in range(3):  # Fewer trials for speed
                        start = time.perf_counter()
                        try:
                            ph.verify(hashed, test_password)
                        except:
                            pass
                        end = time.perf_counter()
                        times.append(end - start)

                    avg_time = statistics.mean(times)
                    candidates.append((char, avg_time))

                if candidates:
                    candidates.sort(key=lambda x: x[1], reverse=True)
                    guessed_char = candidates[0][0]
                    discovered += guessed_char

                    self.result_queue.put(
                        ("info", f"   Best candidate: '{guessed_char}' (time: {candidates[0][1]:.6f}s)"))
                    self.result_queue.put(("info", f"   Current guess: {discovered}"))

                    if guessed_char == target[position]:
                        self.result_queue.put(("success", "   ✓ Correct!"))
                    else:
                        self.result_queue.put(("danger", "   ✗ Incorrect - timing attack failed"))
                        break

                    self.result_queue.put(("info", ""))

            self.result_queue.put(("info", f"Final result: {discovered}"))
            if discovered == target:
                self.result_queue.put(("warning", "🎯 TIMING ATTACK SUCCESSFUL! (In simulation)"))
            else:
                self.result_queue.put(("success", "🛡️  TIMING ATTACK FAILED - Argon2 is resistant!"))

        except Exception as e:
            self.result_queue.put(("error", f"Error in prefix attack: {str(e)}"))

    def analyze_results(self, results):
        """Analyze and display timing results"""
        self.result_queue.put(("header", "\n" + "=" * 80))
        self.result_queue.put(("header", "TIMING ANALYSIS"))
        self.result_queue.put(("header", "=" * 80))

        results_by_time = sorted(results, key=lambda x: x['avg_time'])

        self.result_queue.put(("info", "\nSorted by average verification time:"))
        self.result_queue.put(("info", "-" * 50))

        for result in results_by_time:
            self.result_queue.put(
                ("info", f"{result['avg_time']:.6f}s - {result['password']:<25} ({result['description']})"))

        # Security analysis
        self.result_queue.put(("header", "\n" + "=" * 80))
        self.result_queue.put(("header", "SECURITY ANALYSIS"))
        self.result_queue.put(("header", "=" * 80))

        correct_times = [r['avg_time'] for r in results if r['success']]
        incorrect_times = [r['avg_time'] for r in results if not r['success']]

        if correct_times and incorrect_times:
            correct_time = statistics.mean(correct_times)
            avg_incorrect = statistics.mean(incorrect_times)
            time_difference = abs(correct_time - avg_incorrect)

            self.result_queue.put(("info", f"Average time for correct password: {correct_time:.6f}s"))
            self.result_queue.put(("info", f"Average time for incorrect passwords: {avg_incorrect:.6f}s"))
            self.result_queue.put(("info", f"Time difference: {time_difference:.6f}s"))

            if time_difference > 0.001:  # 1ms threshold
                self.result_queue.put(("warning", "⚠️  WARNING: Significant timing difference detected!"))
                self.result_queue.put(("warning", "   This could potentially be exploited in a timing attack."))
            else:
                self.result_queue.put(("success", "✓ GOOD: Timing differences are minimal."))
                self.result_queue.put(("success", "   Argon2 appears to be resistant to timing attacks."))

    def process_results(self):
        """Process results from the simulation thread"""
        try:
            while True:
                try:
                    result_type, message = self.result_queue.get_nowait()

                    if result_type == "complete":
                        self.is_running = False
                        self.run_button.configure(state='normal')
                        self.stop_button.configure(state='disabled')
                        self.progress.stop()
                        self.update_status("Simulation completed")
                        return
                    elif result_type == "error":
                        self.log_message(f"ERROR: {message}", "danger")
                        self.is_running = False
                        self.run_button.configure(state='normal')
                        self.stop_button.configure(state='disabled')
                        self.progress.stop()
                        self.update_status("Simulation failed")
                        return
                    elif result_type == "status":
                        self.update_status(message)
                    else:
                        self.log_message(message, result_type)

                except queue.Empty:
                    break

        except Exception as e:
            print(f"Error processing results: {e}")

        if self.is_running:
            self.root.after(100, self.process_results)


def main():
    try:
        # Check if argon2 is available
        import argon2

        root = tk.Tk()
        app = Argon2TimingSimulator(root)
        root.mainloop()

    except ImportError:
        # Show error dialog if argon2 is not installed
        root = tk.Tk()
        root.withdraw()  # Hide main window
        messagebox.showerror(
            "Missing Dependency",
            "The argon2-cffi package is required to run this application.\n\n"
            "Please install it using:\npip install argon2-cffi"
        )
        root.destroy()
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Application Error", f"Failed to start application: {str(e)}")


if __name__ == "__main__":
    main()