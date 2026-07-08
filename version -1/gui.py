#!/usr/bin/env python3
"""
gui.py

Desktop GUI for the Password Security Assessment System, styled in a
soft "neumorphic" (soft UI) design — rounded cards with subtle embossed
shadows on a muted light background. Built with tkinter (included with
standard Python) plus a small custom widget toolkit in src/neumorphic.py
(tkinter/ttk cannot draw soft shadows natively, so those widgets are
hand-drawn on a Canvas).

Run with:
    python gui.py

Two views, switched via soft pill buttons in the sidebar:
    1. Single Password Check - type a password, see its analysis instantly,
       optionally save a one-account PDF/Excel report. The password itself
       is never written to disk in any form.
    2. Batch CSV Assessment  - pick a CSV of accounts (+ optional policy
       JSON), run the full assessment, see a summary, and open the
       generated PDF/Excel reports directly from the app.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.assessment_engine import AssessmentEngine, AccountRecord, AccountAssessment
from src.policy_validator import PasswordPolicy
from src.report_generator import ReportGenerator
from src.risk_scorer import RiskLevel
from src.neumorphic import (
    NeuCard, NeuButton, NeuEntryWell, NeuBadge,
    BG, TEXT, MUTED_TEXT,
)


APP_TITLE = "Password Security Assessment System"

RISK_COLORS = {
    "Low Risk": "#3AA76D",
    "Medium Risk": "#E3A008",
    "High Risk": "#E8730B",
    "Critical Risk": "#D6483F",
}


def open_file(path: str) -> None:
    """Open a file with the OS default application, cross-platform."""
    system = platform.system()
    try:
        if system == "Windows":
            os.startfile(path)  # type: ignore[attr-defined]
        elif system == "Darwin":
            subprocess.call(["open", path])
        else:
            subprocess.call(["xdg-open", path])
    except Exception as exc:
        messagebox.showerror("Could not open file", f"{path}\n\n{exc}")


def load_policy_from_json(path: Optional[str]) -> PasswordPolicy:
    if not path:
        return PasswordPolicy()
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return PasswordPolicy.from_dict(data)


def load_accounts_from_csv(path: str) -> List[AccountRecord]:
    records = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            last_changed = None
            raw_date = (row.get("password_last_changed") or "").strip()
            if raw_date:
                try:
                    last_changed = datetime.strptime(raw_date, "%Y-%m-%d").date()
                except ValueError:
                    pass
            records.append(AccountRecord(
                account_identifier=(row.get("account_id") or "").strip(),
                username=(row.get("username") or "").strip() or None,
                plaintext_password=(row.get("password") or "").strip() or None,
                password_hash=(row.get("password_hash") or "").strip() or None,
                password_last_changed=last_changed,
            ))
    return records


def section_label(parent, text, size=11):
    return tk.Label(parent, text=text, bg=BG, fg=TEXT, font=("Segoe UI", size, "bold"))


def muted_label(parent, text, wraplength=560):
    return tk.Label(parent, text=text, bg=BG, fg=MUTED_TEXT, font=("Segoe UI", 9),
                     wraplength=wraplength, justify="left")


class ScrollableLogPanel(tk.Frame):
    """A soft inset panel containing a read-only, scrollable text log."""

    def __init__(self, parent, height=18, **kwargs):
        super().__init__(parent, bg=BG, **kwargs)
        outer = NeuCard(self, width=10, height=10, radius=16, depth=5, bg=BG)
        outer.pack(fill="both", expand=True)

        text_holder = tk.Frame(outer.inner, bg="#EDF1F6")
        text_holder.pack(fill="both", expand=True, padx=2, pady=2)

        self.text = tk.Text(
            text_holder, wrap="word", height=height, bg="#EDF1F6", fg=TEXT,
            font=("Consolas", 10), bd=0, highlightthickness=0, padx=12, pady=10,
            state="disabled",
        )
        scrollbar = tk.Scrollbar(text_holder, command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        self.text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def set_text(self, content: str):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.configure(state="disabled")


class PasswordAssessmentApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("960x680")
        self.minsize(820, 600)
        self.configure(bg=BG)

        # --- Sidebar ---
        sidebar = tk.Frame(self, bg=BG, width=200)
        sidebar.pack(side="left", fill="y", padx=(18, 8), pady=18)
        sidebar.pack_propagate(False)

        title_lbl = tk.Label(
            sidebar, text="Password\nSecurity\nAssessment", bg=BG, fg=TEXT,
            font=("Segoe UI", 15, "bold"), justify="left",
        )
        title_lbl.pack(anchor="w", pady=(4, 24))

        self.single_btn = NeuButton(
            sidebar, text="Single Password", command=lambda: self.show_view("single"),
            width=176, height=48, accent=True,
        )
        self.single_btn.pack(pady=(0, 12))

        self.batch_btn = NeuButton(
            sidebar, text="Batch CSV", command=lambda: self.show_view("batch"),
            width=176, height=48,
        )
        self.batch_btn.pack(pady=(0, 12))

        footer = tk.Label(
            sidebar, text="Passwords are analyzed\nin memory only and are\nnever written to disk.",
            bg=BG, fg=MUTED_TEXT, font=("Segoe UI", 8), justify="left",
        )
        footer.pack(side="bottom", anchor="w")

        # --- Content area ---
        content = tk.Frame(self, bg=BG)
        content.pack(side="left", fill="both", expand=True, padx=(8, 18), pady=18)

        self.single_view = SinglePasswordView(content)
        self.batch_view = BatchAssessmentView(content)

        self.views = {"single": self.single_view, "batch": self.batch_view}
        self.show_view("single")

    def show_view(self, name: str):
        for view in self.views.values():
            view.pack_forget()
        self.views[name].pack(fill="both", expand=True)
        self.single_btn.accent = (name == "single")
        self.batch_btn.accent = (name == "batch")
        self.single_btn._render()
        self.batch_btn._render()


class SinglePasswordView(tk.Frame):
    """View for checking one password interactively."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.last_assessment: Optional[AccountAssessment] = None
        self._build_ui()

    def _build_ui(self):
        card = NeuCard(self, width=10, height=170, radius=20, depth=6, bg=BG)
        card.pack(fill="x", pady=(0, 16))

        inner = card.inner
        section_label(inner, "Enter a password to assess").pack(anchor="w", pady=(4, 8))

        entry_row = tk.Frame(inner, bg=BG)
        entry_row.pack(fill="x", pady=(0, 6))

        self.password_var = tk.StringVar()
        self.entry_well = NeuEntryWell(
            entry_row, textvariable=self.password_var, width=420, height=44,
            radius=14, show="\u2022",
        )
        self.entry_well.pack(side="left", fill="x", expand=True)
        self.entry_well.entry.bind("<Return>", lambda e: self.analyze())

        self.show_var = tk.BooleanVar(value=False)
        show_toggle = tk.Checkbutton(
            entry_row, text="Show", variable=self.show_var, command=self._toggle_visibility,
            bg=BG, fg=MUTED_TEXT, activebackground=BG, selectcolor=BG,
            font=("Segoe UI", 9), bd=0, highlightthickness=0,
        )
        show_toggle.pack(side="left", padx=(10, 0))

        muted_label(
            inner,
            "This password is analyzed in memory only. It is never written to disk, "
            "logged, or included in any report.",
        ).pack(anchor="w", pady=(2, 12))

        btn_row = tk.Frame(inner, bg=BG)
        btn_row.pack(anchor="w")
        NeuButton(btn_row, text="Analyze Password", command=self.analyze,
                  width=170, height=42, accent=True).pack(side="left")
        self.save_report_btn = NeuButton(
            btn_row, text="Save Report...", command=self.save_report,
            width=150, height=42, state="disabled",
        )
        self.save_report_btn.pack(side="left", padx=(10, 0))
        NeuButton(btn_row, text="Clear", command=self.clear,
                  width=100, height=42).pack(side="left", padx=(10, 0))

        # Risk badge
        self.risk_badge = NeuBadge(self, text="Awaiting analysis...", fill="#C7CDD8",
                                    text_color=TEXT, width=10, height=48, font=("Segoe UI", 12, "bold"))
        self.risk_badge.pack(fill="x", pady=(0, 14))
        self._current_risk_label = "Awaiting analysis..."
        self._current_risk_color = "#C7CDD8"

        # Results panel
        self.results_panel = ScrollableLogPanel(self, height=16)
        self.results_panel.pack(fill="both", expand=True)

    def _toggle_visibility(self):
        self.entry_well.entry.configure(show="" if self.show_var.get() else "\u2022")

    def analyze(self):
        password = self.password_var.get()
        if password == "":
            messagebox.showwarning("No password", "Please type a password to analyze first.")
            return

        engine = AssessmentEngine(enable_audit_log=False)
        record = AccountRecord(account_identifier="INTERACTIVE-CHECK", plaintext_password=password)
        assessment = engine.assess_account(record)
        self.last_assessment = assessment

        self._render_assessment(assessment)
        self.save_report_btn.configure_state("normal")

    def _render_assessment(self, assessment: AccountAssessment):
        risk = assessment.risk_result
        color = RISK_COLORS.get(risk.risk_level.value, "#C7CDD8")
        label = f"{risk.risk_level.value}   \u2022   score {risk.risk_score}/100"
        self._current_risk_label = label
        self._current_risk_color = color
        self.risk_badge.set_text(label, color, "#FFFFFF")

        lines = []
        if assessment.password_result:
            pr = assessment.password_result
            lines.append(f"STRENGTH: {pr.strength_label}  ({pr.strength_score}/100)")
            lines.append(f"Length: {pr.length}   Entropy: {pr.entropy_bits} bits   "
                          f"Character classes used: {pr.class_count}/4")
            lines.append("")
            lines.append("Findings:")
            for f in pr.findings:
                lines.append(f"  - {f}")

        if assessment.policy_result:
            pol = assessment.policy_result
            lines.append("")
            lines.append(f"POLICY COMPLIANT: {'Yes' if pol.is_compliant else 'No'}")
            for v in pol.violations:
                lines.append(f"  ! {v}")

        if assessment.recommendations:
            lines.append("")
            lines.append("RECOMMENDATIONS:")
            for r in assessment.recommendations:
                lines.append(f"  [{r.priority}] ({r.category}) {r.recommendation}")

        self.results_panel.set_text("\n".join(lines))

    def save_report(self):
        if not self.last_assessment:
            return
        directory = filedialog.askdirectory(title="Choose a folder to save the report in")
        if not directory:
            return
        try:
            report_gen = ReportGenerator(output_dir=directory)
            pdf_path = report_gen.generate_pdf_report(
                [self.last_assessment], filename="single_password_check_report.pdf"
            )
            xlsx_path = report_gen.generate_excel_report(
                [self.last_assessment], filename="single_password_check_report.xlsx"
            )
        except Exception as exc:
            messagebox.showerror("Report generation failed", str(exc))
            return

        answer = messagebox.askyesno(
            "Report saved",
            f"Saved:\n{pdf_path}\n{xlsx_path}\n\nOpen the PDF now?",
        )
        if answer:
            open_file(pdf_path)

    def clear(self):
        self.password_var.set("")
        self.last_assessment = None
        self.save_report_btn.configure_state("disabled")
        self._current_risk_label = "Awaiting analysis..."
        self._current_risk_color = "#C7CDD8"
        self.risk_badge.set_text(self._current_risk_label, self._current_risk_color, TEXT)
        self.results_panel.set_text("")


class BatchAssessmentView(tk.Frame):
    """View for running a full CSV-based batch assessment."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.assessments: List[AccountAssessment] = []
        self.last_pdf_path: Optional[str] = None
        self.last_xlsx_path: Optional[str] = None
        self._build_ui()

    def _build_ui(self):
        card = NeuCard(self, width=10, height=230, radius=20, depth=6, bg=BG)
        card.pack(fill="x", pady=(0, 16))
        inner = card.inner

        section_label(inner, "Batch Assessment Setup").pack(anchor="w", pady=(4, 10))

        self.csv_var = tk.StringVar()
        self._picker_row(inner, "Accounts CSV file", self.csv_var, self._browse_csv)

        self.policy_var = tk.StringVar()
        self._picker_row(inner, "Policy JSON (optional)", self.policy_var, self._browse_policy)

        self.output_var = tk.StringVar(value=os.path.join(os.getcwd(), "reports"))
        self._picker_row(inner, "Report output folder", self.output_var, self._browse_output)

        btn_row = tk.Frame(inner, bg=BG)
        btn_row.pack(anchor="w", pady=(10, 0))
        self.run_btn = NeuButton(btn_row, text="Run Assessment", command=self._run_assessment_threaded,
                                  width=160, height=42, accent=True)
        self.run_btn.pack(side="left")
        self.open_pdf_btn = NeuButton(btn_row, text="Open PDF", command=self._open_pdf,
                                      width=120, height=42, state="disabled")
        self.open_pdf_btn.pack(side="left", padx=(10, 0))
        self.open_xlsx_btn = NeuButton(btn_row, text="Open Excel", command=self._open_xlsx,
                                       width=120, height=42, state="disabled")
        self.open_xlsx_btn.pack(side="left", padx=(10, 0))

        self.status_label = tk.Label(inner, text="", bg=BG, fg=MUTED_TEXT, font=("Segoe UI", 9))
        self.status_label.pack(anchor="w", pady=(10, 0))

        self.summary_panel = ScrollableLogPanel(self, height=18)
        self.summary_panel.pack(fill="both", expand=True)

    def _picker_row(self, parent, label_text, var, browse_cmd):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=5)
        tk.Label(row, text=label_text, bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold"),
                 width=20, anchor="w").pack(side="left")
        well = NeuEntryWell(row, textvariable=var, width=380, height=36, radius=12)
        well.pack(side="left", padx=(4, 8), fill="x", expand=True)
        NeuButton(row, text="Browse...", command=browse_cmd, width=100, height=36).pack(side="left")

    def _browse_csv(self):
        path = filedialog.askopenfilename(title="Select accounts CSV", filetypes=[("CSV files", "*.csv")])
        if path:
            self.csv_var.set(path)

    def _browse_policy(self):
        path = filedialog.askopenfilename(title="Select policy JSON", filetypes=[("JSON files", "*.json")])
        if path:
            self.policy_var.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select report output folder")
        if path:
            self.output_var.set(path)

    def _run_assessment_threaded(self):
        csv_path = self.csv_var.get().strip()
        if not csv_path or not os.path.isfile(csv_path):
            messagebox.showwarning("Missing CSV", "Please choose a valid accounts CSV file first.")
            return

        self.run_btn.configure_state("disabled")
        self.open_pdf_btn.configure_state("disabled")
        self.open_xlsx_btn.configure_state("disabled")
        self.status_label.configure(text="Running assessment, please wait...")
        self.summary_panel.set_text("Running assessment, please wait...")

        thread = threading.Thread(target=self._run_assessment, daemon=True)
        thread.start()

    def _run_assessment(self):
        try:
            csv_path = self.csv_var.get().strip()
            policy_path = self.policy_var.get().strip() or None
            output_dir = self.output_var.get().strip() or "reports"

            policy = load_policy_from_json(policy_path)
            engine = AssessmentEngine(policy=policy, enable_audit_log=True)
            records = load_accounts_from_csv(csv_path)

            if not records:
                self.after(0, lambda: self._on_error("No account records found in the CSV file."))
                return

            assessments = engine.assess_batch(records)
            report_gen = ReportGenerator(output_dir=output_dir)
            pdf_path = report_gen.generate_pdf_report(assessments)
            xlsx_path = report_gen.generate_excel_report(assessments)

            self.after(0, lambda: self._on_success(assessments, pdf_path, xlsx_path))
        except Exception as exc:
            self.after(0, lambda: self._on_error(str(exc)))

    def _on_success(self, assessments, pdf_path, xlsx_path):
        self.assessments = assessments
        self.last_pdf_path = pdf_path
        self.last_xlsx_path = xlsx_path
        self.run_btn.configure_state("normal")
        self.open_pdf_btn.configure_state("normal")
        self.open_xlsx_btn.configure_state("normal")
        self.status_label.configure(text="Assessment complete.")
        self.summary_panel.set_text(self._build_summary_text(assessments, pdf_path, xlsx_path))

    def _on_error(self, message: str):
        self.run_btn.configure_state("normal")
        self.status_label.configure(text="Assessment failed.")
        self.summary_panel.set_text(f"ERROR: {message}")
        messagebox.showerror("Assessment failed", message)

    def _build_summary_text(self, assessments: List[AccountAssessment], pdf_path: str, xlsx_path: str) -> str:
        total = len(assessments)
        risk_counts = {level.value: 0 for level in RiskLevel}
        strength_scores = []
        non_compliant = 0
        weak_hashes = 0
        common_passwords = 0

        for a in assessments:
            risk_counts[a.risk_result.risk_level.value] += 1
            if a.password_result:
                strength_scores.append(a.password_result.strength_score)
                if a.password_result.is_common_password:
                    common_passwords += 1
            if a.policy_result and not a.policy_result.is_compliant:
                non_compliant += 1
            if a.hash_result and a.hash_result.security_level.value in ("Deprecated", "Weak"):
                weak_hashes += 1

        avg_strength = round(sum(strength_scores) / len(strength_scores), 1) if strength_scores else 0.0

        lines = [
            "=" * 60,
            "ASSESSMENT SUMMARY",
            "=" * 60,
            f"Total accounts assessed:            {total}",
            f"Average password strength score:    {avg_strength}/100",
            f"Accounts using common passwords:    {common_passwords}",
            f"Accounts with policy violations:    {non_compliant}",
            f"Accounts with weak/deprecated hash: {weak_hashes}",
            "",
            "Risk Distribution:",
        ]
        for level in RiskLevel:
            lines.append(f"  {level.value:<15} {risk_counts[level.value]}")

        critical_or_high = [
            a for a in assessments
            if a.risk_result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        ]
        if critical_or_high:
            lines.append("")
            lines.append("Accounts Requiring Immediate Attention:")
            for a in sorted(critical_or_high, key=lambda x: x.risk_result.risk_score, reverse=True)[:15]:
                lines.append(
                    f"  - {a.account_identifier:<15} {a.risk_result.risk_level.value:<15} "
                    f"score={a.risk_result.risk_score}"
                )

        lines.append("")
        lines.append("=" * 60)
        lines.append(f"PDF report:   {pdf_path}")
        lines.append(f"Excel report: {xlsx_path}")
        lines.append("=" * 60)

        return "\n".join(lines)

    def _open_pdf(self):
        if self.last_pdf_path:
            open_file(self.last_pdf_path)

    def _open_xlsx(self):
        if self.last_xlsx_path:
            open_file(self.last_xlsx_path)


def main():
    app = PasswordAssessmentApp()
    app.mainloop()


if __name__ == "__main__":
    main()
