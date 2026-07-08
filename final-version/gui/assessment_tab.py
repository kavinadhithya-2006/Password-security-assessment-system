"""
Assessment tab: form to submit a username + test password for a full
security assessment (strength, hashing, policy, risk, recommendations).
"""

import tkinter as tk
from tkinter import ttk, messagebox

from gui import theme


class AssessmentTab(tk.Frame):

    def __init__(self, parent, db, engine, on_saved=None):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self.engine = engine
        self.on_saved = on_saved
        self._build()

    def _build(self):
        theme.page_header(self, "Password Security Assessment",
                           "Submit a test credential for a full strength, hashing, and policy audit.")

        form = theme.card(self, pady=18)

        tk.Label(form, text="Username *", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=0, sticky="w", pady=6)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var, width=28).grid(row=0, column=1, sticky="w", padx=8)

        tk.Label(form, text="Department", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=2, sticky="w", pady=6, padx=(18, 0))
        self.department_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.department_var, width=22).grid(row=0, column=3, sticky="w", padx=8)

        tk.Label(form, text="Full Name", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=1, column=0, sticky="w", pady=6)
        self.fullname_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.fullname_var, width=28).grid(row=1, column=1, sticky="w", padx=8)

        tk.Label(form, text="Hashing Algorithm to Simulate", bg=theme.CARD_BG, fg=theme.SLATE,
                 font=theme.FONT_SMALL).grid(row=1, column=2, sticky="w", pady=6, padx=(18, 0))
        self.algo_var = tk.StringVar(value="SHA256")
        algo_combo = ttk.Combobox(form, textvariable=self.algo_var, state="readonly", width=20,
                                   values=["MD5", "SHA1", "SHA256", "SHA512", "bcrypt"])
        algo_combo.grid(row=1, column=3, sticky="w", padx=8)

        tk.Label(form, text="Test Password *", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=2, column=0, sticky="w", pady=6)
        self.password_var = tk.StringVar()
        pw_entry = ttk.Entry(form, textvariable=self.password_var, width=28, show="\u2022")
        pw_entry.grid(row=2, column=1, sticky="w", padx=8)

        self.show_pw = tk.BooleanVar(value=False)
        def toggle_show():
            pw_entry.config(show="" if self.show_pw.get() else "\u2022")
        ttk.Checkbutton(form, text="Show password", variable=self.show_pw, command=toggle_show).grid(
            row=2, column=2, columnspan=2, sticky="w", padx=(18, 0))

        note = ("Note: This tool is intended for authorized internal auditing of test/organizational "
                "accounts only. The plaintext password is analyzed in memory and is never stored — "
                "only its computed hash is persisted.")
        tk.Label(form, text=note, bg=theme.CARD_BG, fg=theme.MUTED, wraplength=980,
                 font=theme.FONT_MUTED_ITALIC, justify="left").grid(
            row=3, column=0, columnspan=4, sticky="w", pady=(10, 4))

        theme.primary_button(form, "Run Assessment", self._run_assessment).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

        # Results area
        results_card = theme.card(self, pady=14, fill="both", expand=True)
        theme.section_title(results_card, "Assessment Results")

        self.badge_row = tk.Frame(results_card, bg=theme.CARD_BG)
        self.badge_row.pack(anchor="w", pady=(0, 8))

        self.result_text = tk.Text(results_card, wrap="word", height=17,
                                    font=theme.FONT_MONO, bg="#f9fafb", fg=theme.SLATE,
                                    relief="flat", borderwidth=0, highlightthickness=1,
                                    highlightbackground=theme.BORDER, padx=12, pady=10)
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
        for w in self.badge_row.winfo_children():
            w.destroy()
        theme.risk_badge(self.badge_row, r["risk_level"]).pack(side="left")
        tk.Label(self.badge_row, text=f"Risk Score: {r['risk_score']}/100  \u2022  "
                                       f"Strength: {r['strength_score']}/100  \u2022  "
                                       f"Entropy: {r['entropy_bits']} bits",
                 bg=theme.CARD_BG, fg=theme.MUTED, font=theme.FONT_SMALL).pack(side="left", padx=12)

        self.result_text.config(state="normal")
        self.result_text.delete("1.0", "end")

        lines = []
        lines.append(f"USER: {r['username']}")
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
                lines.append(f"  \u2022 {v['type']}: {v['details']}")

        lines.append("")
        lines.append("Recommendations:")
        for rec in r["recommendations_list"]:
            lines.append(f"  \u2713 {rec}")

        self.result_text.insert("1.0", "\n".join(lines))
        self.result_text.config(state="disabled")
