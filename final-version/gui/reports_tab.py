"""
Reports tab: generate PDF / Excel exports of assessments, compliance,
risk, and executive summary reports.
"""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox

from reports.pdf_generator import PDFReportGenerator
from reports.excel_generator import ExcelReportGenerator
from gui import theme


class ReportsTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self.pdf_gen = PDFReportGenerator()
        self.excel_gen = ExcelReportGenerator()
        self._build()

    def _build(self):
        theme.page_header(self, "Reporting",
                           "Generate branded PDF or Excel exports of assessment, compliance, and risk data.")

        options = theme.card(self, pady=18)

        tk.Label(options, text="Report Type", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=0, sticky="w")
        self.report_type_var = tk.StringVar(value="Password Security Report")
        ttk.Combobox(options, textvariable=self.report_type_var, state="readonly", width=35, values=[
            "Password Security Report",
            "Password Policy Compliance Report",
            "Risk Assessment Report",
            "Executive Summary Report",
        ]).grid(row=0, column=1, padx=10)

        tk.Label(options, text="Format", bg=theme.CARD_BG, fg=theme.SLATE, font=theme.FONT_SMALL).grid(
            row=0, column=2, sticky="w", padx=(20, 0))
        self.format_var = tk.StringVar(value="PDF")
        ttk.Combobox(options, textvariable=self.format_var, state="readonly", width=10,
                     values=["PDF", "Excel"]).grid(row=0, column=3, padx=10)

        theme.primary_button(options, "Generate Report", self._generate).grid(row=0, column=4, padx=10)

        descriptions = {
            "Password Security Report": "Full detail table of every assessed credential with a risk-level chart.",
            "Password Policy Compliance Report": "Compliance rate, violation-type breakdown, and non-compliant accounts.",
            "Risk Assessment Report": "Risk distribution, top risk factors, and prioritized remediation list.",
            "Executive Summary Report": "Leadership-facing KPIs, risk chart, and recommended next steps.",
        }
        self.desc_label = tk.Label(options, text=descriptions[self.report_type_var.get()],
                                    bg=theme.CARD_BG, fg=theme.MUTED, font=theme.FONT_MUTED_ITALIC)
        self.desc_label.grid(row=1, column=0, columnspan=5, sticky="w", pady=(10, 0))

        def on_type_change(event=None):
            self.desc_label.config(text=descriptions.get(self.report_type_var.get(), ""))
        self.report_type_var.trace_add("write", lambda *a: on_type_change())

        list_card = theme.card(self, pady=14, fill="both", expand=True)
        theme.section_title(list_card, "Generated Reports")

        list_wrap = tk.Frame(list_card, bg="white", highlightbackground=theme.BORDER, highlightthickness=1)
        list_wrap.pack(fill="both", expand=True)
        self.output_list = tk.Listbox(list_wrap, height=14, font=theme.FONT_MONO, bg="white",
                                       fg=theme.SLATE, relief="flat", borderwidth=0,
                                       selectbackground=theme.ACCENT_SOFT, selectforeground=theme.NAVY,
                                       highlightthickness=0)
        self.output_list.pack(fill="both", expand=True, padx=1, pady=1)
        self.output_list.bind("<Double-Button-1>", self._open_selected)

        tk.Label(list_card, text="Double-click a generated report to open it.", bg=theme.CARD_BG,
                 fg=theme.MUTED, font=theme.FONT_MUTED_ITALIC).pack(anchor="w", pady=(8, 0))

    def _generate(self):
        if not self.db.is_connected():
            messagebox.showerror("Database Error", "Not connected to the database.")
            return

        report_type = self.report_type_var.get()
        fmt = self.format_var.get()

        try:
            assessments = self.db.get_assessments()
            if report_type == "Executive Summary Report":
                stats = self.db.get_dashboard_stats()
                distribution = {row["risk_level"]: row["cnt"] for row in self.db.get_risk_distribution()}
                if fmt == "PDF":
                    path = self.pdf_gen.generate_executive_summary(stats, distribution)
                else:
                    path = self.excel_gen.generate_assessment_report(assessments, "Executive_Summary")
            elif report_type == "Password Policy Compliance Report":
                violations = self.db.get_all_violations()
                if fmt == "PDF":
                    path = self.pdf_gen.generate_policy_compliance_report(assessments, violations)
                else:
                    violations_map = {}
                    for v in violations:
                        violations_map.setdefault(v["assessment_id"], []).append(
                            {"type": v["violation_type"], "details": v.get("details", "")})
                    path = self.excel_gen.generate_policy_compliance_report(assessments, violations_map)
            elif report_type == "Risk Assessment Report":
                if fmt == "PDF":
                    path = self.pdf_gen.generate_risk_assessment_report(assessments)
                else:
                    path = self.excel_gen.generate_assessment_report(assessments, "Risk_Assessment_Report")
            else:
                title = report_type.replace(" ", "_")
                if fmt == "PDF":
                    path = self.pdf_gen.generate_assessment_report(assessments, report_type)
                else:
                    path = self.excel_gen.generate_assessment_report(assessments, title)

            self.db.save_report_record(report_type, fmt, path, "admin")
            self.db.log_action("REPORT_GENERATED", "admin", f"{report_type} ({fmt}) -> {path}")

            self.output_list.insert(0, path)
            messagebox.showinfo("Report Generated", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Report Error", str(e))

    def _open_selected(self, event):
        selection = self.output_list.curselection()
        if not selection:
            return
        path = self.output_list.get(selection[0])
        if not os.path.exists(path):
            messagebox.showerror("File Not Found", "The report file no longer exists.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Open Error", str(e))
