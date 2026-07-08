"""
Hash Analysis tab: allows auditing an already-hashed credential (e.g.
from a credential export) without needing the plaintext password.
"""

import tkinter as tk
from tkinter import ttk, messagebox


class HashTab(tk.Frame):

    def __init__(self, parent, db, engine, on_saved=None):
        super().__init__(parent, bg="#ffffff")
        self.db = db
        self.engine = engine
        self.on_saved = on_saved
        self._build()

    def _build(self):
        form = tk.Frame(self, bg="#ffffff")
        form.pack(fill="x", padx=20, pady=15)

        tk.Label(form, text="Password Hash Analysis", bg="#ffffff",
                 font=("Segoe UI", 14, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 10))

        tk.Label(form, text="Username *", bg="#ffffff").grid(row=1, column=0, sticky="w", pady=4)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=28).grid(row=1, column=1, sticky="w", padx=6)

        tk.Label(form, text="Department", bg="#ffffff").grid(row=1, column=2, sticky="w", pady=4)
        self.department_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.department_var, width=22).grid(row=1, column=3, sticky="w", padx=6)

        tk.Label(form, text="Password Hash *", bg="#ffffff").grid(row=2, column=0, sticky="w", pady=4)
        self.hash_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.hash_var, width=70).grid(
            row=2, column=1, columnspan=3, sticky="w", padx=6)

        ttk.Button(form, text="Analyze Hash", command=self._run_analysis).grid(
            row=3, column=0, sticky="w", pady=12)

        self.result_text = tk.Text(self, wrap="word", height=20, font=("Consolas", 10),
                                    bg="#f9fafb", relief="solid", borderwidth=1)
        self.result_text.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        self.result_text.insert("1.0", "Hash analysis results will appear here.")
        self.result_text.config(state="disabled")

    def _run_analysis(self):
        username = self.username_var.get().strip()
        hash_str = self.hash_var.get().strip()

        if not username or not hash_str:
            messagebox.showerror("Missing Input", "Username and Password Hash are required.")
            return

        if not self.db.is_connected():
            messagebox.showerror("Database Error", "Not connected to the database.")
            return

        try:
            result = self.engine.assess_existing_hash(
                username=username,
                hash_str=hash_str,
                department=self.department_var.get().strip(),
            )
        except Exception as e:
            messagebox.showerror("Analysis Error", str(e))
            return

        self._display_result(result)
        self.hash_var.set("")
        if self.on_saved:
            self.on_saved()

    def _display_result(self, r):
        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")

        lines = [
            f"USER: {r['username']}",
            f"HASH ALGORITHM DETECTED: {r['hash_algorithm']}",
            f"DEPRECATED / INSECURE: {'Yes' if r['hash_deprecated'] else 'No'}",
            f"RISK LEVEL: {r['risk_level']}  (Risk Score: {r['risk_score']}/100)",
            f"Reused Hash (matches history): {r['is_reused']}",
            "",
            "Recommendations:",
        ]
        for rec in r["recommendations_list"]:
            lines.append(f"  ✓ {rec}")

        self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.config(state="disabled")
