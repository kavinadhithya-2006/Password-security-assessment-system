"""
Reports tab: generate PDF / Excel exports of assessments, compliance,
and executive summary reports.
"""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import ttk, messagebox

from reports.pdf_generator import PDFReportGenerator
from reports.excel_generator import ExcelReportGenerator


class ReportsTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg="#ffffff")
        self.db = db
        self.pdf_gen = PDFReportGenerator()
        self.excel_gen = ExcelReportGenerator()
        self._build()

    def _build(self):
        tk.Label(self, text="Reporting", bg="#ffffff",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=20, pady=(15, 10))

        options = tk.Frame(self, bg="#ffffff")
        options.pack(fill="x", padx=20)

        tk.Label(options, text="Report Type", bg="#ffffff").grid(row=0, column=0, sticky="w")
        self.report_type_var = tk.StringVar(value="Password Security Report")
        ttk.Combobox(options, textvariable=self.report_type_var, state="readonly", width=35, values=[
            "Password Security Report",
            "Password Policy Compliance Report",
            "Risk Assessment Report",
            "Executive Summary Report",
        ]).grid(row=0, column=1, padx=10)

        tk.Label(options, text="Format", bg="#ffffff").grid(row=0, column=2, sticky="w", padx=(20, 0))
        self.format_var = tk.StringVar(value="PDF")
        ttk.Combobox(options, textvariable=self.format_var, state="readonly", width=10,
                     values=["PDF", "Excel"]).grid(row=0, column=3, padx=10)

        ttk.Button(options, text="Generate Report", command=self._generate).grid(row=0, column=4, padx=10)

        self.output_list = tk.Listbox(self, height=14, font=("Consolas", 9))
        self.output_list.pack(fill="both", expand=True, padx=20, pady=15)
        self.output_list.bind("<Double-Button-1>", self._open_selected)

        tk.Label(self, text="Double-click a generated report to open it.", bg="#ffffff",
                 fg="#6b7280", font=("Segoe UI", 8, "italic")).pack(anchor="w", padx=20, pady=(0, 10))

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
                if fmt == "PDF":
                    path = self.pdf_gen.generate_executive_summary(stats)
                else:
                    path = self.excel_gen.generate_assessment_report(assessments, "Executive_Summary")
            elif report_type == "Password Policy Compliance Report":
                violations_map = {}  # simplified — could be extended to fetch per-assessment violations
                if fmt == "PDF":
                    path = self.pdf_gen.generate_assessment_report(assessments, "Policy_Compliance_Report")
                else:
                    path = self.excel_gen.generate_policy_compliance_report(assessments, violations_map)
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
