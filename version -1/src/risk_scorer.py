"""
risk_scorer.py

Combines password strength analysis, hash analysis, and policy
validation results into a single organizational risk classification:
Low, Medium, High, or Critical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .password_analyzer import PasswordAnalysisResult
from .hash_analyzer import HashAnalysisResult, HashSecurityLevel
from .policy_validator import PolicyValidationResult


class RiskLevel(str, Enum):
    LOW = "Low Risk"
    MEDIUM = "Medium Risk"
    HIGH = "High Risk"
    CRITICAL = "Critical Risk"


@dataclass
class RiskAssessmentResult:
    account_identifier: str
    risk_level: RiskLevel
    risk_score: int  # 0-100, higher = riskier
    contributing_factors: List[str] = field(default_factory=list)


class RiskScorer:
    """Aggregates sub-assessments into an overall account risk rating."""

    # Weighting applied to each dimension when computing the composite risk score
    WEIGHT_PASSWORD_STRENGTH = 0.45
    WEIGHT_HASH_SECURITY = 0.30
    WEIGHT_POLICY_COMPLIANCE = 0.25

    _HASH_LEVEL_RISK = {
        HashSecurityLevel.DEPRECATED: 100,
        HashSecurityLevel.WEAK: 70,
        HashSecurityLevel.UNKNOWN: 60,
        HashSecurityLevel.ACCEPTABLE: 30,
        HashSecurityLevel.STRONG: 5,
    }

    def score(
        self,
        account_identifier: str,
        password_result: Optional[PasswordAnalysisResult] = None,
        hash_result: Optional[HashAnalysisResult] = None,
        policy_result: Optional[PolicyValidationResult] = None,
    ) -> RiskAssessmentResult:
        factors: List[str] = []
        components = []

        if password_result is not None:
            # Invert strength score (0-100 strength -> risk contribution)
            pw_risk = 100 - password_result.strength_score
            components.append((pw_risk, self.WEIGHT_PASSWORD_STRENGTH))
            if password_result.strength_score < 40:
                factors.append(f"Weak password strength score ({password_result.strength_score}/100).")
            if password_result.is_common_password:
                factors.append("Password found in common/breached password list.")

        if hash_result is not None:
            hash_risk = self._HASH_LEVEL_RISK.get(hash_result.security_level, 60)
            components.append((hash_risk, self.WEIGHT_HASH_SECURITY))
            if hash_result.security_level in (HashSecurityLevel.DEPRECATED, HashSecurityLevel.WEAK):
                factors.append(f"Insecure hashing algorithm in use: {hash_result.algorithm}.")
            if not hash_result.is_salted:
                factors.append("Password hash is unsalted.")

        if policy_result is not None:
            policy_risk = min(100, len(policy_result.violations) * 25)
            components.append((policy_risk, self.WEIGHT_POLICY_COMPLIANCE))
            if not policy_result.is_compliant:
                factors.append(
                    f"{len(policy_result.violations)} password policy violation(s) detected."
                )

        if not components:
            composite = 0
        else:
            total_weight = sum(w for _, w in components)
            composite = round(sum(v * w for v, w in components) / total_weight)

        risk_level = self._classify(composite)

        if not factors:
            factors.append("No significant risk factors identified.")

        return RiskAssessmentResult(
            account_identifier=account_identifier,
            risk_level=risk_level,
            risk_score=composite,
            contributing_factors=factors,
        )

    @staticmethod
    def _classify(composite_score: int) -> RiskLevel:
        if composite_score >= 75:
            return RiskLevel.CRITICAL
        if composite_score >= 50:
            return RiskLevel.HIGH
        if composite_score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
