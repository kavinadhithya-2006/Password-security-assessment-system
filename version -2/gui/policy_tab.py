"""
Policy Configuration tab: view and update the organization's active
password policy.
"""

import tkinter as tk
from tkinter import ttk, messagebox


class PolicyTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg="#ffffff")
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        tk.Label(self, text="Password Policy Configuration", bg="#ffffff",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=20, pady=(15, 10))

        form = tk.Frame(self, bg="#ffffff")
        form.pack(fill="x", padx=20)

        tk.Label(form, text="Policy Name", bg="#ffffff").grid(row=0, column=0, sticky="w", pady=6)
        self.name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.name_var, width=30).grid(row=0, column=1, sticky="w", padx=10)

        tk.Label(form, text="Minimum Length", bg="#ffffff").grid(row=1, column=0, sticky="w", pady=6)
        self.min_length_var = tk.IntVar(value=12)
        ttk.Spinbox(form, from_=4, to=64, textvariable=self.min_length_var, width=10).grid(
            row=1, column=1, sticky="w", padx=10)

        self.req_upper = tk.BooleanVar(value=True)
        self.req_lower = tk.BooleanVar(value=True)
        self.req_digit = tk.BooleanVar(value=True)
        self.req_special = tk.BooleanVar(value=True)

        ttk.Checkbutton(form, text="Require Uppercase Letter", variable=self.req_upper).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(form, text="Require Lowercase Letter", variable=self.req_lower).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(form, text="Require Numeric Character", variable=self.req_digit).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=3)
        ttk.Checkbutton(form, text="Require Special Character", variable=self.req_special).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=3)

        tk.Label(form, text="Max Password Age (days)", bg="#ffffff").grid(row=6, column=0, sticky="w", pady=6)
        self.max_age_var = tk.IntVar(value=90)
        ttk.Spinbox(form, from_=1, to=365, textvariable=self.max_age_var, width=10).grid(
            row=6, column=1, sticky="w", padx=10)

        tk.Label(form, text="Password History Count", bg="#ffffff").grid(row=7, column=0, sticky="w", pady=6)
        self.history_var = tk.IntVar(value=5)
        ttk.Spinbox(form, from_=0, to=24, textvariable=self.history_var, width=10).grid(
            row=7, column=1, sticky="w", padx=10)

        ttk.Button(form, text="Save Policy", command=self._save_policy).grid(
            row=8, column=0, columnspan=2, sticky="w", pady=16)

        self.status_label = tk.Label(self, text="", bg="#ffffff", fg="#059669", font=("Segoe UI", 10))
        self.status_label.pack(anchor="w", padx=20)

    def refresh(self):
        if not self.db.is_connected():
            return
        try:
            policy = self.db.get_active_policy()
        except Exception:
            return
        self.name_var.set(policy.get("policy_name", "Default Policy"))
        self.min_length_var.set(policy.get("min_length", 12))
        self.req_upper.set(bool(policy.get("require_uppercase", True)))
        self.req_lower.set(bool(policy.get("require_lowercase", True)))
        self.req_digit.set(bool(policy.get("require_digit", True)))
        self.req_special.set(bool(policy.get("require_special", True)))
        self.max_age_var.set(policy.get("max_age_days", 90))
        self.history_var.set(policy.get("history_count", 5))

    def _save_policy(self):
        if not self.db.is_connected():
            messagebox.showerror("Database Error", "Not connected to the database.")
            return
        try:
            self.db.update_policy(
                self.name_var.get().strip() or "Default Policy",
                self.min_length_var.get(),
                self.req_upper.get(),
                self.req_lower.get(),
                self.req_digit.get(),
                self.req_special.get(),
                self.max_age_var.get(),
                self.history_var.get(),
            )
            self.db.log_action("POLICY_UPDATE", "admin", "Password policy updated.")
            self.status_label.config(text="✓ Policy saved successfully.")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
