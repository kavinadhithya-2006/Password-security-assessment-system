"""
password_analyzer.py

Core password strength assessment engine for the Password Security
Assessment System.

Provides:
    - Shannon entropy calculation
    - Character-class complexity evaluation
    - Common / dictionary password detection
    - Sequential and repeated character pattern detection
    - Overall password strength scoring (0-100)

This module never transmits or stores plaintext passwords; callers are
responsible for ensuring passwords are handled in memory only and are
discarded (or hashed) as soon as analysis is complete.
"""

from __future__ import annotations

import math
import os
import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List


COMMON_PASSWORDS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "common_passwords.txt",
)

# Keyboard rows used for sequential/adjacency pattern detection
_KEYBOARD_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]


@lru_cache(maxsize=1)
def _load_common_passwords() -> frozenset:
    """Load the common/weak password dictionary (cached)."""
    try:
        with open(COMMON_PASSWORDS_PATH, "r", encoding="utf-8") as fh:
            return frozenset(line.strip().lower() for line in fh if line.strip())
    except FileNotFoundError:
        return frozenset()


@dataclass
class PasswordAnalysisResult:
    """Structured result of a single password strength analysis."""

    length: int
    entropy_bits: float
    character_pool_size: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    class_count: int
    is_common_password: bool
    has_sequential_pattern: bool
    has_repeated_pattern: bool
    is_keyboard_pattern: bool
    strength_score: int  # 0-100
    strength_label: str  # Very Weak / Weak / Moderate / Strong / Very Strong
    findings: List[str] = field(default_factory=list)


class PasswordAnalyzer:
    """Evaluates the strength, entropy, and composition of passwords."""

    def __init__(self, common_password_list: frozenset = None):
        self.common_passwords = common_password_list or _load_common_passwords()

    # ------------------------------------------------------------------
    # Character pool / entropy
    # ------------------------------------------------------------------
    @staticmethod
    def _character_pool_size(password: str) -> int:
        pool = 0
        if re.search(r"[a-z]", password):
            pool += 26
        if re.search(r"[A-Z]", password):
            pool += 26
        if re.search(r"[0-9]", password):
            pool += 10
        if re.search(r"[^a-zA-Z0-9]", password):
            pool += 33  # approximate printable special character set
        return pool or 1

    def calculate_entropy(self, password: str) -> float:
        """Calculate Shannon-style entropy in bits: length * log2(pool size)."""
        if not password:
            return 0.0
        pool_size = self._character_pool_size(password)
        return round(len(password) * math.log2(pool_size), 2)

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------
    @staticmethod
    def has_repeated_characters(password: str, threshold: int = 3) -> bool:
        """Detect runs of the same character repeated >= threshold times."""
        pattern = r"(.)\1{" + str(threshold - 1) + ",}"
        return bool(re.search(pattern, password))

    @staticmethod
    def has_sequential_characters(password: str, run_length: int = 3) -> bool:
        """Detect ascending/descending numeric or alphabetic sequences."""
        lowered = password.lower()
        for i in range(len(lowered) - run_length + 1):
            window = lowered[i:i + run_length]
            codes = [ord(c) for c in window]
            ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
            descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
            if ascending or descending:
                return True
        return False

    @staticmethod
    def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
        """Detect adjacent-key keyboard walks, e.g. 'qwerty', 'asdf'."""
        lowered = password.lower()
        for row in _KEYBOARD_ROWS:
            for i in range(len(row) - run_length + 1):
                fragment = row[i:i + run_length]
                if fragment in lowered or fragment[::-1] in lowered:
                    return True
        return False

    def is_common_password(self, password: str) -> bool:
        return password.lower() in self.common_passwords

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------
    def _score_password(
        self,
        length: int,
        entropy: float,
        class_count: int,
        is_common: bool,
        has_sequential: bool,
        has_repeated: bool,
        is_keyboard: bool,
    ) -> int:
        """Combine signals into a single 0-100 strength score."""
        score = 0

        # Length contribution (up to 35 points)
        score += min(length * 3, 35)

        # Entropy contribution (up to 35 points), ~90 bits considered excellent
        score += min(int(entropy / 90 * 35), 35)

        # Character class diversity (up to 20 points)
        score += class_count * 5

        # Penalties
        if is_common:
            score -= 60
        if has_sequential:
            score -= 15
        if has_repeated:
            score -= 15
        if is_keyboard:
            score -= 15
        if length < 8:
            score -= 20

        return max(0, min(100, score))

    @staticmethod
    def _label_for_score(score: int) -> str:
        if score >= 80:
            return "Very Strong"
        if score >= 60:
            return "Strong"
        if score >= 40:
            return "Moderate"
        if score >= 20:
            return "Weak"
        return "Very Weak"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def analyze(self, password: str) -> PasswordAnalysisResult:
        """Run a full strength assessment on a single plaintext password."""
        if password is None:
            password = ""

        findings: List[str] = []

        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
        class_count = sum([has_upper, has_lower, has_digit, has_special])

        entropy = self.calculate_entropy(password)
        pool_size = self._character_pool_size(password)
        is_common = self.is_common_password(password)
        has_sequential = self.has_sequential_characters(password)
        has_repeated = self.has_repeated_characters(password)
        is_keyboard = self.has_keyboard_pattern(password)

        if len(password) < 8:
            findings.append("Password length is below the recommended minimum of 8 characters.")
        if class_count < 3:
            findings.append("Password does not use at least 3 character classes "
                             "(uppercase, lowercase, digit, special character).")
        if is_common:
            findings.append("Password matches a known common/breached password list.")
        if has_sequential:
            findings.append("Password contains a sequential character pattern (e.g. 'abcd', '1234').")
        if has_repeated:
            findings.append("Password contains repeated character runs (e.g. 'aaa').")
        if is_keyboard:
            findings.append("Password contains a keyboard-walk pattern (e.g. 'qwerty', 'asdf').")
        if entropy < 40:
            findings.append(f"Password entropy ({entropy} bits) is below the 40-bit minimum guideline.")

        score = self._score_password(
            length=len(password),
            entropy=entropy,
            class_count=class_count,
            is_common=is_common,
            has_sequential=has_sequential,
            has_repeated=has_repeated,
            is_keyboard=is_keyboard,
        )

        if not findings:
            findings.append("No significant weaknesses detected.")

        return PasswordAnalysisResult(
            length=len(password),
            entropy_bits=entropy,
            character_pool_size=pool_size,
            has_upper=has_upper,
            has_lower=has_lower,
            has_digit=has_digit,
            has_special=has_special,
            class_count=class_count,
            is_common_password=is_common,
            has_sequential_pattern=has_sequential,
            has_repeated_pattern=has_repeated,
            is_keyboard_pattern=is_keyboard,
            strength_score=score,
            strength_label=self._label_for_score(score),
            findings=findings,
        )
