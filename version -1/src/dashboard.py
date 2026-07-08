"""
dashboard.py

Renders a text-based (terminal-friendly) security dashboard summarizing
a batch of account assessments. Intended to give at-a-glance visibility
before drilling into the full PDF/Excel reports.
"""

from __future__ import annotations

from collections import Counter
from typing import List

from .assessment_engine import AccountAssessment
from .risk_scorer import RiskLevel


def _bar(count: int, total: int, width: int = 30) -> str:
    if total == 0:
        return ""
    filled = round((count / total) * width)
    return "#" * filled + "-" * (width - filled)


def render_text_dashboard(assessments: List[AccountAssessment]) -> None:
    total = len(assessments)
    risk_counts = Counter(a.risk_result.risk_level.value for a in assessments)
    strength_scores = [a.password_result.strength_score for a in assessments if a.password_result]
    avg_strength = round(sum(strength_scores) / len(strength_scores), 1) if strength_scores else 0.0
    non_compliant = sum(1 for a in assessments if a.policy_result and not a.policy_result.is_compliant)
    weak_hashes = sum(
        1 for a in assessments
        if a.hash_result and a.hash_result.security_level.value in ("Deprecated", "Weak")
    )
    common_passwords = sum(1 for a in assessments if a.password_result and a.password_result.is_common_password)

    print("\n" + "#" * 64)
    print("  PASSWORD SECURITY ASSESSMENT - SUMMARY DASHBOARD")
    print("#" * 64)
    print(f"  Total accounts assessed:            {total}")
    print(f"  Average password strength score:    {avg_strength}/100")
    print(f"  Accounts using common passwords:    {common_passwords}")
    print(f"  Accounts with policy violations:    {non_compliant}")
    print(f"  Accounts with weak/deprecated hash: {weak_hashes}")
    print("-" * 64)
    print("  Risk Distribution:")
    for level in RiskLevel:
        count = risk_counts.get(level.value, 0)
        print(f"    {level.value:<15} [{_bar(count, total)}] {count}")
    print("-" * 64)

    critical_or_high = [
        a for a in assessments
        if a.risk_result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
    ]
    if critical_or_high:
        print("  Accounts Requiring Immediate Attention:")
        for a in sorted(critical_or_high, key=lambda x: x.risk_result.risk_score, reverse=True)[:10]:
            print(f"    - {a.account_identifier:<15} {a.risk_result.risk_level.value:<15} score={a.risk_result.risk_score}")
    print("#" * 64 + "\n")
