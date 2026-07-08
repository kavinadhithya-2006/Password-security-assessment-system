"""
Policy Configuration tab: view and update the organization's active
password policy.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme


class PolicyTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        theme.page_header(self, "Password Policy Configuration",
                           "Define the minimum requirements every assessed credential is checked against.")

        form = theme.card(self, pady=20)

        tk.Label(form, text="Policy Name", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=0, sticky="w", pady=8)
        self.name_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.name_var, width=32).grid(row=0, column=1, sticky="w", padx=10)

        tk.Label(form, text="Minimum Length", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=1, column=0, sticky="w", pady=8)
        self.min_length_var = tk.IntVar(value=12)
        ttk.Spinbox(form, from_=4, to=64, textvariable=self.min_length_var, width=10).grid(
            row=1, column=1, sticky="w", padx=10)

        self.req_upper = tk.BooleanVar(value=True)
        self.req_lower = tk.BooleanVar(value=True)
        self.req_digit = tk.BooleanVar(value=True)
        self.req_special = tk.BooleanVar(value=True)

        req_frame = tk.Frame(form, bg=theme.CARD_BG)
        req_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8, 4))
        tk.Label(req_frame, text="Character Requirements", bg=theme.CARD_BG, fg=theme.NAVY,
                 font=theme.FONT_H3).pack(anchor="w", pady=(0, 4))
        ttk.Checkbutton(req_frame, text="Require Uppercase Letter", variable=self.req_upper).pack(anchor="w", pady=2)
        ttk.Checkbutton(req_frame, text="Require Lowercase Letter", variable=self.req_lower).pack(anchor="w", pady=2)
        ttk.Checkbutton(req_frame, text="Require Numeric Character", variable=self.req_digit).pack(anchor="w", pady=2)
        ttk.Checkbutton(req_frame, text="Require Special Character", variable=self.req_special).pack(anchor="w", pady=2)

        tk.Label(form, text="Max Password Age (days)", bg=theme.CARD_BG, fg=theme.SLATE,
                 font=theme.FONT_SMALL).grid(row=3, column=0, sticky="w", pady=8)
        self.max_age_var = tk.IntVar(value=90)
        ttk.Spinbox(form, from_=1, to=365, textvariable=self.max_age_var, width=10).grid(
            row=3, column=1, sticky="w", padx=10)

        tk.Label(form, text="Password History Count", bg=theme.CARD_BG, fg=theme.SLATE,
                 font=theme.FONT_SMALL).grid(row=4, column=0, sticky="w", pady=8)
        self.history_var = tk.IntVar(value=5)
        ttk.Spinbox(form, from_=0, to=24, textvariable=self.history_var, width=10).grid(
            row=4, column=1, sticky="w", padx=10)

        theme.primary_button(form, "Save Policy", self._save_policy).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(18, 4))

        self.status_label = tk.Label(form, text="", bg=theme.CARD_BG, fg=theme.SUCCESS, font=theme.FONT_SMALL)
        self.status_label.grid(row=6, column=0, columnspan=2, sticky="w")

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
            self.status_label.config(text="\u2713 Policy saved successfully.")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))
