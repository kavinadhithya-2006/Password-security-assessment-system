"""
PDFReportGenerator
==================
Generates polished, branded PDF reports (Security Assessment, Policy
Compliance, Risk Assessment, Executive Summary) using reportlab, with
embedded matplotlib charts and a consistent visual identity.
"""

import io
import os
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, HRFlowable
)

# ----------------------------------------------------------------------
# Brand palette — kept in sync with the desktop app's theme (gui/theme.py)
# ----------------------------------------------------------------------
NAVY = colors.HexColor("#111827")
SLATE = colors.HexColor("#374151")
MUTED = colors.HexColor("#6b7280")
LIGHT_BG = colors.HexColor("#f3f4f6")
BORDER = colors.HexColor("#e5e7eb")
ACCENT = colors.HexColor("#2563eb")
WHITE = colors.white

RISK_COLORS = {
    "Low": colors.HexColor("#16a34a"),
    "Medium": colors.HexColor("#d97706"),
    "High": colors.HexColor("#ea580c"),
    "Critical": colors.HexColor("#dc2626"),
}
RISK_FILL = {
    "Low": colors.HexColor("#dcfce7"),
    "Medium": colors.HexColor("#fef3c7"),
    "High": colors.HexColor("#ffedd5"),
    "Critical": colors.HexColor("#fee2e2"),
}

PAGE_W, PAGE_H = letter
MARGIN = 0.65 * inch


def _hexcolor(c):
    """reportlab Color -> '#rrggbb' string, for use with matplotlib."""
    r, g, b = [int(round(x * 255)) for x in (c.red, c.green, c.blue)]
    return f"#{r:02x}{g:02x}{b:02x}"


class PDFReportGenerator:

    def __init__(self, output_dir="generated_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = self._build_styles()

    # ------------------------------------------------------------------
    # Style / layout helpers
    # ------------------------------------------------------------------
    def _build_styles(self):
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="ReportTitle", fontName="Helvetica-Bold", fontSize=22,
            leading=26, textColor=NAVY, spaceAfter=4, alignment=TA_LEFT))
        styles.add(ParagraphStyle(
            name="ReportSubtitle", fontName="Helvetica", fontSize=10.5,
            leading=14, textColor=MUTED, alignment=TA_LEFT))
        styles.add(ParagraphStyle(
            name="SectionHeading", fontName="Helvetica-Bold", fontSize=13,
            leading=16, textColor=NAVY, spaceBefore=18, spaceAfter=8))
        styles.add(ParagraphStyle(
            name="Body", parent=styles["Normal"], fontName="Helvetica",
            fontSize=9.5, leading=14, textColor=SLATE))
        styles.add(ParagraphStyle(
            name="BodyMuted", parent=styles["Body"], textColor=MUTED, fontSize=8.5))
        styles.add(ParagraphStyle(
            name="TakeawayBullet", parent=styles["Body"], leftIndent=14, bulletIndent=2,
            spaceAfter=4))
        styles.add(ParagraphStyle(
            name="KpiValue", fontName="Helvetica-Bold", fontSize=20,
            leading=22, textColor=WHITE, alignment=TA_CENTER))
        styles.add(ParagraphStyle(
            name="KpiLabel", fontName="Helvetica", fontSize=7.6,
            leading=10, textColor=WHITE, alignment=TA_CENTER))
        styles.add(ParagraphStyle(
            name="CellText", fontName="Helvetica", fontSize=8, leading=10,
            textColor=SLATE))
        return styles

    def _doc(self, filepath, report_title):
        return SimpleDocTemplate(
            filepath, pagesize=letter,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=1.05 * inch, bottomMargin=0.75 * inch,
            title=report_title, author="Password Security Assessment System",
        )

    def _page_decoration(self, report_title):
        """Returns an onPage callback that draws a header band + footer with
        page numbers on every page of the document."""

        def _draw(canvas, doc):
            canvas.saveState()

            # Header band
            canvas.setFillColor(NAVY)
            canvas.rect(0, PAGE_H - 0.62 * inch, PAGE_W, 0.62 * inch, stroke=0, fill=1)
            canvas.setFillColor(ACCENT)
            canvas.rect(0, PAGE_H - 0.66 * inch, PAGE_W, 0.04 * inch, stroke=0, fill=1)

            canvas.setFillColor(WHITE)
            canvas.setFont("Helvetica-Bold", 12)
            canvas.drawString(MARGIN, PAGE_H - 0.41 * inch, "Password Security Assessment System")
            canvas.setFont("Helvetica", 8.5)
            canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.41 * inch, report_title)

            # Footer
            canvas.setFillColor(MUTED)
            canvas.setFont("Helvetica", 7.5)
            canvas.drawString(MARGIN, 0.5 * inch,
                               f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}  \u2022  "
                               "CONFIDENTIAL \u2014 Internal Security Use Only")
            canvas.drawRightString(PAGE_W - MARGIN, 0.5 * inch, f"Page {doc.page}")
            canvas.setStrokeColor(BORDER)
            canvas.line(MARGIN, 0.62 * inch, PAGE_W - MARGIN, 0.62 * inch)

            canvas.restoreState()

        return _draw

    def _cover(self, title, subtitle):
        return [
            Paragraph(title, self.styles["ReportTitle"]),
            Paragraph(subtitle, self.styles["ReportSubtitle"]),
            Spacer(1, 6),
            HRFlowable(width="100%", thickness=1.2, color=ACCENT, spaceAfter=14),
        ]

    def _kpi_row(self, items):
        """items: list of (label, value, hex_color_str)."""
        cell_tables = []
        for label, value, hexcolor in items:
            inner = Table(
                [[Paragraph(str(value), self.styles["KpiValue"])],
                 [Paragraph(label.upper(), self.styles["KpiLabel"])]],
                style=TableStyle([
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]))
            cell_tables.append(inner)

        col_w = (PAGE_W - 2 * MARGIN) / len(items)
        t = Table([cell_tables], colWidths=[col_w] * len(items), rowHeights=[0.85 * inch])
        style_cmds = [
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, (_, _, hexcolor) in enumerate(items):
            style_cmds.append(("BACKGROUND", (i, 0), (i, 0), colors.HexColor(hexcolor)))
        t.setStyle(TableStyle(style_cmds))
        return t

    def _chart_image(self, fig, width=5.6 * inch):
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", transparent=True)
        plt.close(fig)
        buf.seek(0)
        img = Image(buf)
        ratio = img.imageHeight / float(img.imageWidth)
        img.drawWidth = width
        img.drawHeight = width * ratio
        return img

    def _risk_bar_chart(self, counts):
        levels = ["Low", "Medium", "High", "Critical"]
        values = [counts.get(l, 0) for l in levels]
        bar_colors = [_hexcolor(RISK_COLORS[l]) for l in levels]

        fig, ax = plt.subplots(figsize=(6, 3))
        bars = ax.bar(levels, values, color=bar_colors, width=0.55, zorder=3)
        for spine in ("top", "right", "left"):
            ax.spines[spine].set_visible(False)
        ax.spines["bottom"].set_color("#9ca3af")
        ax.tick_params(axis="both", labelsize=9, colors="#374151")
        ax.set_ylabel("Assessments", fontsize=9, color="#374151")
        ax.grid(axis="y", linestyle="--", linewidth=0.6, color="#e5e7eb", zorder=0)
        for b, v in zip(bars, values):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height(), str(v),
                    ha="center", va="bottom", fontsize=9, color="#111827", fontweight="bold")
        fig.tight_layout()
        return self._chart_image(fig)

    def _donut_chart(self, counts, title=""):
        levels = ["Low", "Medium", "High", "Critical"]
        values = [counts.get(l, 0) for l in levels]
        chart_colors = [_hexcolor(RISK_COLORS[l]) for l in levels]
        if sum(values) == 0:
            values, levels, chart_colors = [1], ["No Data"], ["#d1d5db"]

        fig, ax = plt.subplots(figsize=(4.4, 4.4))
        wedges, _ = ax.pie(values, colors=chart_colors, startangle=90,
                            wedgeprops=dict(width=0.42, edgecolor="white", linewidth=2))
        ax.legend(wedges, [f"{l} ({v})" for l, v in zip(levels, values)],
                  loc="center", frameon=False, fontsize=9)
        if title:
            ax.set_title(title, fontsize=10, color="#111827", pad=10)
        fig.tight_layout()
        return self._chart_image(fig, width=3.6 * inch)

    def _horizontal_bar_chart(self, labels, values, color="#2563eb"):
        fig, ax = plt.subplots(figsize=(6, max(1.8, 0.42 * len(labels))))
        y_pos = range(len(labels))
        bars = ax.barh(list(y_pos), values, color=color, zorder=3)
        ax.set_yticks(list(y_pos))
        ax.set_yticklabels(labels, fontsize=9, color="#374151")
        ax.invert_yaxis()
        for spine in ("top", "right", "left"):
            ax.spines[spine].set_visible(False)
        ax.tick_params(axis="x", labelsize=8, colors="#374151")
        ax.grid(axis="x", linestyle="--", linewidth=0.6, color="#e5e7eb", zorder=0)
        for b, v in zip(bars, values):
            ax.text(b.get_width(), b.get_y() + b.get_height() / 2, f"  {v}",
                    va="center", ha="left", fontsize=8.5, color="#111827")
        fig.tight_layout()
        return self._chart_image(fig)

    def _risk_badge(self, level):
        color = RISK_COLORS.get(level, MUTED)
        fill = RISK_FILL.get(level, LIGHT_BG)
        t = Table([[level or "-"]], colWidths=[0.85 * inch], rowHeights=[0.2 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), fill),
            ("TEXTCOLOR", (0, 0), (-1, -1), color),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.6, color),
        ]))
        return t

    def _summary_counts(self, assessments):
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for a in assessments:
            lvl = a.get("risk_level", "Low")
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
        return risk_counts

    def _timestamp(self):
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _styled_table(self, table_data, col_widths, header_dark=False):
        widths = [w * inch for w in col_widths]
        wrapped = [table_data[0]]
        for row in table_data[1:]:
            new_row = []
            for cell in row:
                new_row.append(Paragraph(cell, self.styles["CellText"]) if isinstance(cell, str) else cell)
            wrapped.append(new_row)

        t = Table(wrapped, colWidths=widths, repeatRows=1, hAlign="LEFT")
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, 0), 1, NAVY),
            ("LINEBELOW", (0, 1), (-1, -2), 0.4, BORDER),
        ]
        for i in range(1, len(wrapped)):
            if i % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, i), (-1, i), LIGHT_BG))
        t.setStyle(TableStyle(style_cmds))
        return t

    # ------------------------------------------------------------------
    # Report 1: Password Security Assessment Report
    # ------------------------------------------------------------------
    def generate_assessment_report(self, assessments: list, report_title="Password Security Report") -> str:
        filename = f"{report_title.replace(' ', '_')}_{self._timestamp()}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        doc = self._doc(filepath, report_title)
        elements = []

        elements += self._cover(
            report_title,
            "Consolidated findings across all password security assessments performed to date.")

        risk_counts = self._summary_counts(assessments)
        total = len(assessments)
        compliant = sum(1 for a in assessments if a.get("policy_compliant"))
        deprecated = sum(1 for a in assessments if a.get("hash_deprecated"))

        elements.append(self._kpi_row([
            ("Total Assessed", total, "#1f2937"),
            ("Compliant", compliant, "#16a34a"),
            ("Deprecated Hashes", deprecated, "#dc2626"),
            ("High/Critical Risk", risk_counts["High"] + risk_counts["Critical"], "#ea580c"),
        ]))

        elements.append(Paragraph("Risk Level Distribution", self.styles["SectionHeading"]))
        if total:
            elements.append(self._risk_bar_chart(risk_counts))
        else:
            elements.append(Paragraph("No assessments have been recorded yet.", self.styles["BodyMuted"]))

        elements.append(Paragraph("Detailed Findings", self.styles["SectionHeading"]))
        header = ["User", "Dept", "Risk", "Score", "Hash Algo", "Deprecated", "Compliant"]
        table_data = [header]
        for a in assessments:
            table_data.append([
                a.get("username", ""),
                a.get("department", "") or "-",
                self._risk_badge(a.get("risk_level")),
                str(a.get("risk_score", "-")),
                a.get("hash_algorithm", "-"),
                "Yes" if a.get("hash_deprecated") else "No",
                "Yes" if a.get("policy_compliant") else "No",
            ])
        elements.append(self._styled_table(table_data, col_widths=[1.15, 0.95, 0.85, 0.55, 0.85, 0.85, 0.85]))

        doc.build(elements, onFirstPage=self._page_decoration(report_title),
                   onLaterPages=self._page_decoration(report_title))
        return filepath

    # ------------------------------------------------------------------
    # Report 2: Password Policy Compliance Report
    # ------------------------------------------------------------------
    def generate_policy_compliance_report(self, assessments: list, violations: list = None) -> str:
        report_title = "Password Policy Compliance Report"
        filename = f"Policy_Compliance_Report_{self._timestamp()}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        doc = self._doc(filepath, report_title)
        elements = []
        violations = violations or []

        elements += self._cover(
            report_title,
            "Evaluates how assessed credentials measure up against the organization's active password policy.")

        total = len(assessments)
        compliant = sum(1 for a in assessments if a.get("policy_compliant"))
        non_compliant = total - compliant
        rate = round((compliant / total) * 100, 1) if total else 0.0

        elements.append(self._kpi_row([
            ("Total Assessed", total, "#1f2937"),
            ("Compliant", compliant, "#16a34a"),
            ("Non-Compliant", non_compliant, "#dc2626"),
            ("Compliance Rate", f"{rate}%", "#2563eb"),
        ]))

        type_counts = {}
        for v in violations:
            key = v.get("violation_type", "Unknown")
            type_counts[key] = type_counts.get(key, 0) + 1

        elements.append(Paragraph("Violation Types Observed", self.styles["SectionHeading"]))
        if type_counts:
            labels = list(type_counts.keys())
            values = [type_counts[l] for l in labels]
            elements.append(self._horizontal_bar_chart(labels, values, color="#dc2626"))
        else:
            elements.append(Paragraph("No policy violations were recorded.", self.styles["BodyMuted"]))

        elements.append(Paragraph("Non-Compliant Accounts", self.styles["SectionHeading"]))
        by_assessment = {}
        for v in violations:
            by_assessment.setdefault(v.get("assessment_id"), []).append(v.get("violation_type", ""))

        flagged = [a for a in assessments if not a.get("policy_compliant")]
        if flagged:
            header = ["User", "Dept", "Risk", "Violation(s)"]
            table_data = [header]
            for a in flagged:
                vtypes = by_assessment.get(a.get("assessment_id"), [])
                detail = ", ".join(vtypes) if vtypes else "See assessment detail"
                table_data.append([
                    a.get("username", ""),
                    a.get("department", "") or "-",
                    self._risk_badge(a.get("risk_level")),
                    detail,
                ])
            elements.append(self._styled_table(table_data, col_widths=[1.2, 1.0, 0.85, 3.3]))
        else:
            elements.append(Paragraph("Every assessed account currently complies with the active password policy.",
                                       self.styles["Body"]))

        doc.build(elements, onFirstPage=self._page_decoration(report_title),
                   onLaterPages=self._page_decoration(report_title))
        return filepath

    # ------------------------------------------------------------------
    # Report 3: Risk Assessment Report
    # ------------------------------------------------------------------
    def generate_risk_assessment_report(self, assessments: list) -> str:
        report_title = "Risk Assessment Report"
        filename = f"Risk_Assessment_Report_{self._timestamp()}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        doc = self._doc(filepath, report_title)
        elements = []

        elements += self._cover(
            report_title,
            "Prioritized view of accounts posing the greatest password-related risk to the organization.")

        risk_counts = self._summary_counts(assessments)
        total = len(assessments)

        elements.append(self._kpi_row([
            ("Total Assessed", total, "#1f2937"),
            ("Low Risk", risk_counts["Low"], "#16a34a"),
            ("Medium Risk", risk_counts["Medium"], "#d97706"),
            ("High Risk", risk_counts["High"], "#ea580c"),
            ("Critical Risk", risk_counts["Critical"], "#dc2626"),
        ]))

        elements.append(Paragraph("Risk Level Breakdown", self.styles["SectionHeading"]))
        if total:
            elements.append(self._donut_chart(risk_counts))
        else:
            elements.append(Paragraph("No assessments have been recorded yet.", self.styles["BodyMuted"]))

        flag_labels = {
            "is_common_password": "Common / Breached Password",
            "is_dictionary_word": "Dictionary Word",
            "has_sequential_pattern": "Sequential Pattern",
            "has_repeated_chars": "Repeated Characters",
            "is_reused": "Password Reuse",
            "hash_deprecated": "Deprecated Hash Algorithm",
        }
        flag_counts = {label: 0 for label in flag_labels.values()}
        for a in assessments:
            for key, label in flag_labels.items():
                if a.get(key):
                    flag_counts[label] += 1

        elements.append(Paragraph("Most Common Risk Factors", self.styles["SectionHeading"]))
        nonzero = {k: v for k, v in flag_counts.items() if v > 0}
        if nonzero:
            elements.append(self._horizontal_bar_chart(list(nonzero.keys()), list(nonzero.values()), color="#ea580c"))
        else:
            elements.append(Paragraph("No red flags were identified across assessed accounts.",
                                       self.styles["BodyMuted"]))

        elements.append(Paragraph("High & Critical Risk Accounts (Priority Remediation)", self.styles["SectionHeading"]))
        priority = sorted(
            [a for a in assessments if a.get("risk_level") in ("High", "Critical")],
            key=lambda a: a.get("risk_score", 0), reverse=True,
        )
        if priority:
            header = ["User", "Dept", "Risk", "Score", "Hash Algo", "Key Issue"]
            table_data = [header]
            for a in priority:
                if a.get("is_common_password"):
                    issue = "Common/breached password"
                elif a.get("hash_deprecated"):
                    issue = "Deprecated hash algorithm"
                elif not a.get("policy_compliant"):
                    issue = "Policy non-compliant"
                elif a.get("is_reused"):
                    issue = "Password reuse detected"
                else:
                    issue = "Weak composition"
                table_data.append([
                    a.get("username", ""),
                    a.get("department", "") or "-",
                    self._risk_badge(a.get("risk_level")),
                    str(a.get("risk_score", "-")),
                    a.get("hash_algorithm", "-"),
                    issue,
                ])
            elements.append(self._styled_table(table_data, col_widths=[1.1, 0.9, 0.75, 0.55, 0.95, 2.1]))
        else:
            elements.append(Paragraph("No accounts currently fall into the High or Critical risk category.",
                                       self.styles["Body"]))

        doc.build(elements, onFirstPage=self._page_decoration(report_title),
                   onLaterPages=self._page_decoration(report_title))
        return filepath

    # ------------------------------------------------------------------
    # Report 4: Executive Summary
    # ------------------------------------------------------------------
    def generate_executive_summary(self, stats: dict, distribution: dict = None) -> str:
        report_title = "Executive Summary"
        filename = f"Executive_Summary_{self._timestamp()}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        doc = self._doc(filepath, report_title)
        elements = []

        elements += self._cover(
            report_title,
            "A high-level overview of the organization's password security posture, intended for leadership review.")

        elements.append(self._kpi_row([
            ("Total Users", stats.get("total_users", 0), "#1f2937"),
            ("Assessments", stats.get("total_assessments", 0), "#2563eb"),
            ("Weak Passwords", stats.get("weak_passwords", 0), "#d97706"),
            ("High/Critical Risk", stats.get("high_risk", 0), "#dc2626"),
        ]))

        elements.append(Paragraph("Key Findings", self.styles["SectionHeading"]))
        rows = [["Metric", "Value"]]
        labels = {
            "total_users": "Total Users Assessed",
            "total_assessments": "Total Assessments Performed",
            "weak_passwords": "Weak / Common Passwords Found",
            "deprecated_hashes": "Deprecated Hash Algorithms Found",
            "policy_violations": "Policy Violations",
            "high_risk": "High / Critical Risk Accounts",
        }
        for key, label in labels.items():
            rows.append([label, str(stats.get(key, 0))])
        elements.append(self._styled_table(rows, col_widths=[3.6, 1.6]))

        if distribution:
            elements.append(Paragraph("Risk Distribution", self.styles["SectionHeading"]))
            elements.append(self._donut_chart(distribution))

        elements.append(Paragraph("Recommended Next Steps", self.styles["SectionHeading"]))
        takeaways = [
            "Enforce immediate resets for accounts using common or breached passwords.",
            "Migrate any deprecated hashing algorithms (MD5, SHA1) to a modern adaptive "
            "algorithm such as bcrypt, scrypt, or Argon2.",
            "Bring non-compliant accounts in line with the active password policy and "
            "re-assess after remediation.",
            "Roll out Multi-Factor Authentication (MFA) organization-wide, prioritizing "
            "High and Critical risk accounts.",
            "Encourage adoption of a password manager to reduce reuse and weak, "
            "human-generated passwords.",
        ]
        for t in takeaways:
            elements.append(Paragraph(f"\u2022 {t}", self.styles["TakeawayBullet"]))

        doc.build(elements, onFirstPage=self._page_decoration(report_title),
                   onLaterPages=self._page_decoration(report_title))
        return filepath
