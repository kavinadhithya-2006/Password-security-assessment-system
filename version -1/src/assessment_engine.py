"""
assessment_engine.py

Top-level orchestrator that runs a full password security assessment
for one or more accounts, combining strength analysis, hash analysis,
policy validation, risk scoring, and recommendation generation into a
single structured result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import List, Optional

from .password_analyzer import PasswordAnalyzer, PasswordAnalysisResult
from .hash_analyzer import HashAnalyzer, HashAnalysisResult
from .policy_validator import PolicyValidator, PasswordPolicy, PolicyValidationResult
from .risk_scorer import RiskScorer, RiskAssessmentResult
from .recommendation_engine import RecommendationEngine, Recommendation
from .audit_logger import AuditLogger


@dataclass
class AccountRecord:
    """Input record describing a single account to assess."""
    account_identifier: str
    username: Optional[str] = None
    plaintext_password: Optional[str] = None
    password_hash: Optional[str] = None
    password_last_changed: Optional[date] = None
    password_history: Optional[List[str]] = None


@dataclass
class AccountAssessment:
    """Full assessment output for a single account."""
    account_identifier: str
    assessed_at: str
    password_result: Optional[PasswordAnalysisResult]
    hash_result: Optional[HashAnalysisResult]
    policy_result: Optional[PolicyValidationResult]
    risk_result: Optional[RiskAssessmentResult]
    recommendations: List[Recommendation] = field(default_factory=list)


class AssessmentEngine:
    """Coordinates all analysis modules to produce a per-account assessment."""

    def __init__(
        self,
        policy: Optional[PasswordPolicy] = None,
        enable_audit_log: bool = True,
        log_path: Optional[str] = None,
    ):
        self.password_analyzer = PasswordAnalyzer()
        self.hash_analyzer = HashAnalyzer()
        self.policy_validator = PolicyValidator(policy)
        self.risk_scorer = RiskScorer()
        self.recommendation_engine = RecommendationEngine()
        self.audit_logger = AuditLogger(log_path) if enable_audit_log else None

    def assess_account(self, record: AccountRecord) -> AccountAssessment:
        password_result = None
        hash_result = None
        policy_result = None

        if record.plaintext_password is not None:
            password_result = self.password_analyzer.analyze(record.plaintext_password)
            policy_result = self.policy_validator.validate(
                password=record.plaintext_password,
                username=record.username,
                password_last_changed=record.password_last_changed,
                password_history=record.password_history,
            )

        if record.password_hash:
            hash_result = self.hash_analyzer.analyze(record.password_hash)

        risk_result = self.risk_scorer.score(
            account_identifier=record.account_identifier,
            password_result=password_result,
            hash_result=hash_result,
            policy_result=policy_result,
        )

        recommendations = self.recommendation_engine.generate(
            password_result=password_result,
            hash_result=hash_result,
            policy_result=policy_result,
            risk_result=risk_result,
        )

        assessment = AccountAssessment(
            account_identifier=record.account_identifier,
            assessed_at=datetime.now(timezone.utc).isoformat(),
            password_result=password_result,
            hash_result=hash_result,
            policy_result=policy_result,
            risk_result=risk_result,
            recommendations=recommendations,
        )

        if self.audit_logger:
            self.audit_logger.log_event(
                event_type="PASSWORD_ASSESSMENT_COMPLETED",
                account_identifier=record.account_identifier,
                details={
                    "strength_score": password_result.strength_score if password_result else None,
                    "strength_label": password_result.strength_label if password_result else None,
                    "hash_algorithm": hash_result.algorithm if hash_result else None,
                    "hash_security_level": hash_result.security_level.value if hash_result else None,
                    "policy_compliant": policy_result.is_compliant if policy_result else None,
                    "risk_level": risk_result.risk_level.value,
                    "risk_score": risk_result.risk_score,
                },
            )

        return assessment

    def assess_batch(self, records: List[AccountRecord]) -> List[AccountAssessment]:
        return [self.assess_account(r) for r in records]
