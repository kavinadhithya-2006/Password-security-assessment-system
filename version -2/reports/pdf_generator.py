"""
PDFReportGenerator
==================
Generates PDF reports (Security Assessment, Policy Compliance,
Risk Assessment, Executive Summary) using reportlab.
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)


class PDFReportGenerator:

    def __init__(self, output_dir="generated_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(name="TitleCenter", parent=self.styles["Title"], alignment=1))

    def generate_assessment_report(self, assessments: list, report_title="Password Security Report") -> str:
        filename = f"{report_title.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                 topMargin=0.7 * inch, bottomMargin=0.7 * inch)
        elements = []

        elements.append(Paragraph(report_title, self.styles["TitleCenter"]))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                                   self.styles["Normal"]))
        elements.append(Spacer(1, 0.3 * inch))

        # Summary section
        total = len(assessments)
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for a in assessments:
            risk_counts[a.get("risk_level", "Low")] = risk_counts.get(a.get("risk_level", "Low"), 0) + 1

        summary_data = [["Total Assessed", "Low Risk", "Medium Risk", "High Risk", "Critical Risk"],
                         [str(total), str(risk_counts["Low"]), str(risk_counts["Medium"]),
                          str(risk_counts["High"]), str(risk_counts["Critical"])]]
        summary_table = Table(summary_data, hAlign="LEFT")
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.4 * inch))

        # Detail table
        elements.append(Paragraph("Detailed Findings", self.styles["Heading2"]))
        table_data = [["User", "Dept", "Risk", "Score", "Hash Algo", "Deprecated", "Compliant"]]
        for a in assessments:
            table_data.append([
                a.get("username", ""),
                a.get("department", "") or "-",
                a.get("risk_level", ""),
                str(a.get("risk_score", "")),
                a.get("hash_algorithm", ""),
                "Yes" if a.get("hash_deprecated") else "No",
                "Yes" if a.get("policy_compliant") else "No",
            ])

        detail_table = Table(table_data, repeatRows=1, hAlign="LEFT")
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (2, 1), (-1, -1), "CENTER"),
        ]
        for i, a in enumerate(assessments, start=1):
            color = {
                "Low": colors.HexColor("#d1fae5"),
                "Medium": colors.HexColor("#fef3c7"),
                "High": colors.HexColor("#fed7aa"),
                "Critical": colors.HexColor("#fecaca"),
            }.get(a.get("risk_level"), colors.white)
            style_cmds.append(("BACKGROUND", (2, i), (2, i), color))

        detail_table.setStyle(TableStyle(style_cmds))
        elements.append(detail_table)

        doc.build(elements)
        return filepath

    def generate_executive_summary(self, stats: dict) -> str:
        filename = f"Executive_Summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(filepath, pagesize=letter)
        elements = [
            Paragraph("Executive Summary — Password Security Assessment", self.styles["TitleCenter"]),
            Spacer(1, 0.3 * inch),
            Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]),
            Spacer(1, 0.3 * inch),
        ]

        rows = [["Metric", "Value"]]
        labels = {
            "total_users": "Total Users Assessed",
            "total_assessments": "Total Assessments Performed",
            "weak_passwords": "Weak/Common Passwords Found",
            "deprecated_hashes": "Deprecated Hash Algorithms Found",
            "policy_violations": "Policy Violations",
            "high_risk": "High/Critical Risk Accounts",
        }
        for key, label in labels.items():
            rows.append([label, str(stats.get(key, 0))])

        t = Table(rows, hAlign="LEFT", colWidths=[3.2 * inch, 1.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
        ]))
        elements.append(t)
        doc.build(elements)
        return filepath
