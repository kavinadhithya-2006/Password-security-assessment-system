"""
Hash Analysis tab: allows auditing an already-hashed credential (e.g.
from a credential export) without needing the plaintext password.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme


class HashTab(tk.Frame):

    def __init__(self, parent, db, engine, on_saved=None):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self.engine = engine
        self.on_saved = on_saved
        self._build()

    def _build(self):
        theme.page_header(self, "Password Hash Analysis",
                           "Audit an already-hashed credential (e.g. from a credential export) without the plaintext.")

        form = theme.card(self, pady=18)

        tk.Label(form, text="Username *", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=0, sticky="w", pady=6)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=28).grid(row=0, column=1, sticky="w", padx=8)

        tk.Label(form, text="Department", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=2, sticky="w", pady=6, padx=(18, 0))
        self.department_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.department_var, width=22).grid(row=0, column=3, sticky="w", padx=8)

        tk.Label(form, text="Password Hash *", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=1, column=0, sticky="w", pady=6)
        self.hash_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.hash_var, width=72).grid(
            row=1, column=1, columnspan=3, sticky="w", padx=8)

        theme.primary_button(form, "Analyze Hash", self._run_analysis).grid(
            row=2, column=0, sticky="w", pady=(12, 0))

        results_card = theme.card(self, pady=14, fill="both", expand=True)
        theme.section_title(results_card, "Analysis Results")

        self.badge_row = tk.Frame(results_card, bg=theme.CARD_BG)
        self.badge_row.pack(anchor="w", pady=(0, 8))

        self.result_text = tk.Text(results_card, wrap="word", height=17, font=theme.FONT_MONO,
                                    bg="#f9fafb", fg=theme.SLATE, relief="flat", borderwidth=0,
                                    highlightthickness=1, highlightbackground=theme.BORDER,
                                    padx=12, pady=10)
        self.result_text.pack(fill="both", expand=True)
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
        for w in self.badge_row.winfo_children():
            w.destroy()
        theme.risk_badge(self.badge_row, r["risk_level"]).pack(side="left")
        tk.Label(self.badge_row, text=f"Risk Score: {r['risk_score']}/100  \u2022  "
                                       f"Reused Hash: {r['is_reused']}",
                 bg=theme.CARD_BG, fg=theme.MUTED, font=theme.FONT_SMALL).pack(side="left", padx=12)

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")

        lines = [
            f"USER: {r['username']}",
            f"HASH ALGORITHM DETECTED: {r['hash_algorithm']}",
            f"DEPRECATED / INSECURE: {'Yes' if r['hash_deprecated'] else 'No'}",
            "",
            "Recommendations:",
        ]
        for rec in r["recommendations_list"]:
            lines.append(f"  \u2713 {rec}")

        self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.config(state="disabled")
