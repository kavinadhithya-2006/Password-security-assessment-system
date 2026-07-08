"""
Assessment tab: form to submit a username + test password for a full
security assessment (strength, hashing, policy, risk, recommendations).
"""

import tkinter as tk
from tkinter import ttk, messagebox


class AssessmentTab(tk.Frame):

    def __init__(self, parent, db, engine, on_saved=None):
        super().__init__(parent, bg="#ffffff")
        self.db = db
        self.engine = engine
        self.on_saved = on_saved
        self._build()

    def _build(self):
        form = tk.Frame(self, bg="#ffffff")
        form.pack(fill="x", padx=20, pady=15)

        tk.Label(form, text="Password Security Assessment", bg="#ffffff",
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        tk.Label(form, text="Username *", bg="#ffffff").grid(row=1, column=0, sticky="w", pady=4)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=28).grid(row=1, column=1, sticky="w", padx=6)

        tk.Label(form, text="Department", bg="#ffffff").grid(row=1, column=2, sticky="w", pady=4)
        self.department_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.department_var, width=22).grid(row=1, column=3, sticky="w", padx=6)

        tk.Label(form, text="Full Name", bg="#ffffff").grid(row=2, column=0, sticky="w", pady=4)
        self.fullname_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.fullname_var, width=28).grid(row=2, column=1, sticky="w", padx=6)

        tk.Label(form, text="Hashing Algorithm to Simulate", bg="#ffffff").grid(row=2, column=2, sticky="w", pady=4)
        self.algo_var = tk.StringVar(value="SHA256")
        algo_combo = ttk.Combobox(form, textvariable=self.algo_var, state="readonly", width=20,
                                   values=["MD5", "SHA1", "SHA256", "SHA512", "bcrypt"])
        algo_combo.grid(row=2, column=3, sticky="w", padx=6)

        tk.Label(form, text="Test Password *", bg="#ffffff").grid(row=3, column=0, sticky="w", pady=4)
        self.password_var = tk.StringVar()
        pw_entry = ttk.Entry(form, textvariable=self.password_var, width=28, show="•")
        pw_entry.grid(row=3, column=1, sticky="w", padx=6)

        self.show_pw = tk.BooleanVar(value=False)
        def toggle_show():
            pw_entry.config(show="" if self.show_pw.get() else "•")
        ttk.Checkbutton(form, text="Show", variable=self.show_pw, command=toggle_show).grid(
            row=3, column=2, sticky="w")

        note = ("Note: This tool is intended for authorized internal auditing of test/organizational "
                "accounts only. The plaintext password is analyzed in memory and is never stored — "
                "only its computed hash is persisted.")
        tk.Label(form, text=note, bg="#ffffff", fg="#6b7280", wraplength=950,
                 font=("Segoe UI", 8, "italic"), justify="left").grid(
            row=4, column=0, columnspan=4, sticky="w", pady=(6, 0))

        ttk.Button(form, text="Run Assessment", command=self._run_assessment).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=12)

        # Results area
        self.result_frame = tk.Frame(self, bg="#ffffff")
        self.result_frame.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        self.result_text = tk.Text(self.result_frame, wrap="word", height=20,
                                    font=("Consolas", 10), bg="#f9fafb", relief="solid", borderwidth=1)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.insert("1.0", "Assessment results will appear here.")
        self.result_text.config(state="disabled")

    def _run_assessment(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()

        if not username or not password:
            messagebox.showerror("Missing Input", "Username and Test Password are required.")
            return

        if not self.db.is_connected():
            messagebox.showerror("Database Error", "Not connected to the database.")
            return

        try:
            result = self.engine.assess_plaintext_password(
                username=username,
                password=password,
                department=self.department_var.get().strip(),
                full_name=self.fullname_var.get().strip(),
                hash_algorithm=self.algo_var.get(),
            )
        except Exception as e:
            messagebox.showerror("Assessment Error", str(e))
            return

        self._display_result(result)
        self.password_var.set("")
        if self.on_saved:
            self.on_saved()

    def _display_result(self, r):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")

        lines = []
        lines.append(f"USER: {r['username']}")
        lines.append(f"RISK LEVEL: {r['risk_level']}   (Risk Score: {r['risk_score']}/100)")
        lines.append(f"Strength Score: {r['strength_score']}/100   Entropy: {r['entropy_bits']} bits")
        lines.append(f"Hash Algorithm: {r['hash_algorithm']}   Deprecated: {'Yes' if r['hash_deprecated'] else 'No'}")
        lines.append(f"Policy Compliant: {'Yes' if r['policy_compliant'] else 'No'}")
        lines.append("")
        lines.append("Character Composition:")
        lines.append(f"  Uppercase: {r['has_upper']}  Lowercase: {r['has_lower']}  "
                      f"Digit: {r['has_digit']}  Special: {r['has_special']}")
        lines.append("")
        lines.append("Red Flags:")
        lines.append(f"  Common/Breached Password: {r['is_common_password']}")
        lines.append(f"  Dictionary Word Detected: {r['is_dictionary_word']}")
        lines.append(f"  Sequential Pattern Detected: {r['has_sequential_pattern']}")
        lines.append(f"  Repeated Characters Detected: {r['has_repeated_chars']}")
        lines.append(f"  Reused Password: {r['is_reused']}")

        if r["violations"]:
            lines.append("")
            lines.append("Policy Violations:")
            for v in r["violations"]:
                lines.append(f"  • {v['type']}: {v['details']}")

        lines.append("")
        lines.append("Recommendations:")
        for rec in r["recommendations_list"]:
            lines.append(f"  ✓ {rec}")

        self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.config(state="disabled")
