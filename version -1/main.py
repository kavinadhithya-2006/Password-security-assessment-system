#!/usr/bin/env python3
"""
main.py

Command-line entry point for the Password Security Assessment System.

Usage:
    # Run a full assessment on a CSV of accounts and generate reports
    python main.py --input data/sample_accounts.csv --policy data/policy_config.json --output reports/

    # Assess a single password interactively (never logged/stored in plaintext)
    python main.py --check-password

    # Same, but also generate a one-account PDF/Excel report
    python main.py --check-password --generate-report --output reports/

    # View a text summary dashboard of the last assessment run
    python main.py --input data/sample_accounts.csv --dashboard-only

CSV input format (headers required):
    account_id, username, password, password_hash, password_last_changed

    - `password` and `password_hash` are both optional per-row, but at
      least one should be present for a meaningful assessment.
    - `password_last_changed` should be an ISO date (YYYY-MM-DD).
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import sys
from datetime import datetime
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.assessment_engine import AssessmentEngine, AccountRecord, AccountAssessment
from src.policy_validator import PasswordPolicy
from src.report_generator import ReportGenerator
from src.dashboard import render_text_dashboard
import json


def load_policy(policy_path: Optional[str]) -> PasswordPolicy:
    if not policy_path:
        return PasswordPolicy()
    with open(policy_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return PasswordPolicy.from_dict(data)


def load_accounts_from_csv(csv_path: str) -> List[AccountRecord]:
    records = []
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
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


def run_single_password_check(engine: AssessmentEngine, output_dir: Optional[str] = None) -> None:
    """Interactive single-password check; password is never written to disk."""
    password = getpass.getpass("Enter password to assess (input hidden): ")
    record = AccountRecord(account_identifier="INTERACTIVE-CHECK", plaintext_password=password)
    assessment = engine.assess_account(record)
    print_assessment_summary(assessment)

    if output_dir:
        report_gen = ReportGenerator(output_dir=output_dir)
        pdf_path = report_gen.generate_pdf_report(
            [assessment], filename="single_password_check_report.pdf"
        )
        xlsx_path = report_gen.generate_excel_report(
            [assessment], filename="single_password_check_report.xlsx"
        )
        print(f"PDF report generated:   {pdf_path}")
        print(f"Excel report generated: {xlsx_path}\n")


def print_assessment_summary(assessment: AccountAssessment) -> None:
    print("\n" + "=" * 60)
    print(f"Account: {assessment.account_identifier}")
    print("=" * 60)
    if assessment.password_result:
        pr = assessment.password_result
        print(f"Strength: {pr.strength_label} ({pr.strength_score}/100)")
        print(f"Entropy: {pr.entropy_bits} bits | Length: {pr.length} | Classes used: {pr.class_count}/4")
        for f in pr.findings:
            print(f"  - {f}")
    if assessment.hash_result:
        hr = assessment.hash_result
        print(f"Hash Algorithm: {hr.algorithm} ({hr.security_level.value})")
        for f in hr.findings:
            print(f"  - {f}")
    if assessment.policy_result:
        pol = assessment.policy_result
        print(f"Policy Compliant: {'Yes' if pol.is_compliant else 'No'}")
        for v in pol.violations:
            print(f"  ! {v}")
    print(f"Overall Risk: {assessment.risk_result.risk_level.value} (score {assessment.risk_result.risk_score}/100)")
    if assessment.recommendations:
        print("Top Recommendations:")
        for r in assessment.recommendations[:5]:
            print(f"  [{r.priority}] ({r.category}) {r.recommendation}")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Password Security Assessment System - evaluate password strength, "
                     "hash security, and policy compliance across an organization."
    )
    parser.add_argument("--input", "-i", help="Path to CSV file of accounts to assess.")
    parser.add_argument("--policy", "-p", help="Path to JSON password policy configuration file.")
    parser.add_argument("--output", "-o", default="reports", help="Directory to write generated reports to.")
    parser.add_argument("--check-password", action="store_true",
                         help="Interactively assess a single password (not written to disk). "
                              "Combine with --output to also generate a one-account PDF/Excel report.")
    parser.add_argument("--dashboard-only", action="store_true",
                         help="Print a text dashboard summary without generating PDF/Excel reports.")
    parser.add_argument("--generate-report", action="store_true",
                         help="Used with --check-password: also generate a one-account PDF/Excel "
                              "report (into --output). Off by default so a quick check leaves no files.")
    parser.add_argument("--no-audit-log", action="store_true", help="Disable audit logging for this run.")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    engine = AssessmentEngine(policy=policy, enable_audit_log=not args.no_audit_log)

    if args.check_password:
        # Only pass an output dir if the user explicitly wants a report;
        # otherwise the check stays purely in-terminal with nothing written to disk.
        output_dir = args.output if args.generate_report else None
        run_single_password_check(engine, output_dir=output_dir)
        return

    if not args.input:
        parser.error("Provide --input <accounts.csv> or use --check-password for a single check.")

    records = load_accounts_from_csv(args.input)
    if not records:
        print("No account records found in input file.", file=sys.stderr)
        sys.exit(1)

    assessments = engine.assess_batch(records)

    render_text_dashboard(assessments)

    if not args.dashboard_only:
        report_gen = ReportGenerator(output_dir=args.output)
        pdf_path = report_gen.generate_pdf_report(assessments)
        xlsx_path = report_gen.generate_excel_report(assessments)
        print(f"\nPDF report generated:   {pdf_path}")
        print(f"Excel report generated: {xlsx_path}")


if __name__ == "__main__":
    main()
