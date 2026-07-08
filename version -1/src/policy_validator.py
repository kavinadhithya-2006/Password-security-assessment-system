"""
policy_validator.py

Validates passwords and password metadata against a configurable
organizational password policy, aligned with NIST SP 800-63B / OWASP
authentication guidance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from typing import List, Optional


@dataclass
class PasswordPolicy:
    """Configurable organizational password policy."""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    max_password_age_days: int = 90
    password_history_count: int = 5  # number of prior passwords that cannot be reused
    disallow_username_in_password: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "PasswordPolicy":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class PolicyValidationResult:
    is_compliant: bool
    violations: List[str] = field(default_factory=list)
    checks_passed: List[str] = field(default_factory=list)


class PolicyValidator:
    """Validates a password (and optional account metadata) against a PasswordPolicy."""

    def __init__(self, policy: Optional[PasswordPolicy] = None):
        self.policy = policy or PasswordPolicy()

    def validate(
        self,
        password: str,
        username: Optional[str] = None,
        password_last_changed: Optional[date] = None,
        password_history: Optional[List[str]] = None,
    ) -> PolicyValidationResult:
        violations: List[str] = []
        checks_passed: List[str] = []
        p = self.policy
        password = password or ""

        # Length checks
        if len(password) < p.min_length:
            violations.append(
                f"Password length ({len(password)}) is below the minimum required length ({p.min_length})."
            )
        else:
            checks_passed.append("Minimum length requirement met.")

        if len(password) > p.max_length:
            violations.append(
                f"Password length ({len(password)}) exceeds the maximum allowed length ({p.max_length})."
            )

        # Character class checks
        if p.require_uppercase and not re.search(r"[A-Z]", password):
            violations.append("Password must contain at least one uppercase letter.")
        elif p.require_uppercase:
            checks_passed.append("Uppercase letter requirement met.")

        if p.require_lowercase and not re.search(r"[a-z]", password):
            violations.append("Password must contain at least one lowercase letter.")
        elif p.require_lowercase:
            checks_passed.append("Lowercase letter requirement met.")

        if p.require_digit and not re.search(r"[0-9]", password):
            violations.append("Password must contain at least one numeric character.")
        elif p.require_digit:
            checks_passed.append("Numeric character requirement met.")

        if p.require_special and not re.search(r"[^a-zA-Z0-9]", password):
            violations.append("Password must contain at least one special character.")
        elif p.require_special:
            checks_passed.append("Special character requirement met.")

        # Username inclusion check
        if p.disallow_username_in_password and username:
            if username.lower() in password.lower() and len(username) >= 3:
                violations.append("Password must not contain the account username.")
            else:
                checks_passed.append("Password does not contain the username.")

        # Expiration check
        if password_last_changed and p.max_password_age_days:
            age_days = (date.today() - password_last_changed).days
            if age_days > p.max_password_age_days:
                violations.append(
                    f"Password age ({age_days} days) exceeds the maximum allowed age "
                    f"({p.max_password_age_days} days); rotation required."
                )
            else:
                checks_passed.append("Password age is within the allowed policy window.")

        # History / reuse check
        if password_history:
            recent = password_history[-p.password_history_count:]
            if password in recent:
                violations.append(
                    f"Password matches one of the last {p.password_history_count} passwords used "
                    "(password reuse policy violation)."
                )
            else:
                checks_passed.append("Password does not match recent password history.")

        return PolicyValidationResult(
            is_compliant=(len(violations) == 0),
            violations=violations,
            checks_passed=checks_passed,
        )
