"""
recommendation_engine.py

Generates prioritized, actionable security recommendations based on
password analysis, hash analysis, policy validation, and overall risk
classification results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .password_analyzer import PasswordAnalysisResult
from .hash_analyzer import HashAnalysisResult, HashSecurityLevel
from .policy_validator import PolicyValidationResult
from .risk_scorer import RiskAssessmentResult, RiskLevel


@dataclass
class Recommendation:
    priority: str  # "Critical", "High", "Medium", "Low"
    category: str
    recommendation: str


class RecommendationEngine:
    """Produces prioritized remediation guidance for an assessed account."""

    def generate(
        self,
        password_result: Optional[PasswordAnalysisResult] = None,
        hash_result: Optional[HashAnalysisResult] = None,
        policy_result: Optional[PolicyValidationResult] = None,
        risk_result: Optional[RiskAssessmentResult] = None,
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []

        if password_result is not None:
            if password_result.is_common_password:
                recs.append(Recommendation(
                    "Critical", "Password Strength",
                    "Immediately force a password reset; this password appears in known "
                    "common/breached password lists."
                ))
            if password_result.strength_score < 40:
                recs.append(Recommendation(
                    "High", "Password Strength",
                    "Require the user to create a stronger password with a minimum of 12-16 "
                    "characters mixing uppercase, lowercase, digits, and special characters."
                ))
            if password_result.has_sequential_pattern or password_result.is_keyboard_pattern:
                recs.append(Recommendation(
                    "Medium", "Password Strength",
                    "Educate the user to avoid sequential or keyboard-walk patterns (e.g. "
                    "'1234', 'qwerty') as these are among the first patterns attackers try."
                ))
            if password_result.entropy_bits < 40:
                recs.append(Recommendation(
                    "Medium", "Password Strength",
                    "Encourage use of a passphrase (multiple random words) to increase entropy "
                    "without sacrificing memorability."
                ))
            recs.append(Recommendation(
                "Low", "Password Strength",
                "Promote adoption of a password manager to enable long, unique, random passwords "
                "per system."
            ))

        if hash_result is not None:
            if hash_result.security_level in (HashSecurityLevel.DEPRECATED, HashSecurityLevel.WEAK):
                recs.append(Recommendation(
                    "Critical", "Hash Security",
                    f"Migrate password storage from {hash_result.algorithm} to a modern adaptive "
                    "algorithm such as bcrypt, scrypt, or Argon2id."
                ))
            if not hash_result.is_salted:
                recs.append(Recommendation(
                    "Critical", "Hash Security",
                    "Introduce a unique, cryptographically random salt per password to prevent "
                    "rainbow-table attacks."
                ))
            if not hash_result.is_adaptive:
                recs.append(Recommendation(
                    "High", "Hash Security",
                    "Adopt an adaptive, tunable-cost hashing algorithm to slow down brute-force "
                    "and GPU/ASIC-based cracking attempts."
                ))

        if policy_result is not None and not policy_result.is_compliant:
            for violation in policy_result.violations:
                recs.append(Recommendation("Medium", "Policy Compliance", f"Remediate: {violation}"))

        recs.append(Recommendation(
            "Low", "Authentication", "Enable Multi-Factor Authentication (MFA) for all accounts, "
            "particularly those with elevated privileges."
        ))

        if risk_result is not None and risk_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recs.append(Recommendation(
                "High", "Governance",
                "Prioritize this account for immediate remediation and include it in the next "
                "security audit cycle given its elevated risk classification."
            ))

        # Deduplicate while preserving order
        seen = set()
        unique_recs = []
        for r in recs:
            key = (r.priority, r.category, r.recommendation)
            if key not in seen:
                seen.add(key)
                unique_recs.append(r)

        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        unique_recs.sort(key=lambda r: priority_order.get(r.priority, 4))
        return unique_recs
