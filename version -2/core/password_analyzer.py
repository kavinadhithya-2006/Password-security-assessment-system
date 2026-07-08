"""
PasswordAnalyzer
=================
Evaluates raw password strength: entropy, complexity, common/dictionary
matches, sequential patterns, repeated characters.

NOTE: The plaintext password is only ever held in memory for the
duration of this analysis and is never persisted to the database or disk.
"""

import math
import re

from core.common_passwords import COMMON_PASSWORDS, DICTIONARY_WORDS


class PasswordAnalyzer:

    SEQUENTIAL_RUNS = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    def analyze(self, password: str) -> dict:
        result = {}

        result["length"] = len(password)
        result["has_upper"] = bool(re.search(r"[A-Z]", password))
        result["has_lower"] = bool(re.search(r"[a-z]", password))
        result["has_digit"] = bool(re.search(r"\d", password))
        result["has_special"] = bool(re.search(r"[^A-Za-z0-9]", password))

        result["entropy_bits"] = round(self._calculate_entropy(password), 2)
        result["is_common_password"] = password.lower() in COMMON_PASSWORDS
        result["is_dictionary_word"] = self._contains_dictionary_word(password)
        result["has_sequential_pattern"] = self._has_sequential_pattern(password)
        result["has_repeated_chars"] = self._has_repeated_chars(password)

        result["strength_score"] = self._score(result)
        return result

    # ------------------------------------------------------------------
    def _charset_size(self, password: str) -> int:
        size = 0
        if re.search(r"[a-z]", password):
            size += 26
        if re.search(r"[A-Z]", password):
            size += 26
        if re.search(r"\d", password):
            size += 10
        if re.search(r"[^A-Za-z0-9]", password):
            size += 33
        return max(size, 1)

    def _calculate_entropy(self, password: str) -> float:
        if not password:
            return 0.0
        charset = self._charset_size(password)
        return len(password) * math.log2(charset)

    def _contains_dictionary_word(self, password: str) -> bool:
        lowered = password.lower()
        return any(word in lowered for word in DICTIONARY_WORDS)

    def _has_sequential_pattern(self, password: str, run_length=4) -> bool:
        lowered = password.lower()
        for run in self.SEQUENTIAL_RUNS:
            for i in range(len(run) - run_length + 1):
                chunk = run[i:i + run_length]
                if chunk in lowered or chunk[::-1] in lowered:
                    return True
        return False

    def _has_repeated_chars(self, password: str, threshold=3) -> bool:
        return bool(re.search(r"(.)\1{" + str(threshold - 1) + r",}", password))

    def _score(self, r: dict) -> int:
        """0-100 composite strength score."""
        score = 0
        # Entropy contributes up to 50 points (capped at 100 bits)
        score += min(r["entropy_bits"], 100) / 100 * 50

        # Length contributes up to 20 points
        score += min(r["length"], 20) / 20 * 20

        # Character variety contributes up to 20 points
        variety = sum([r["has_upper"], r["has_lower"], r["has_digit"], r["has_special"]])
        score += variety / 4 * 20

        # Penalties
        if r["is_common_password"]:
            score -= 40
        if r["is_dictionary_word"]:
            score -= 15
        if r["has_sequential_pattern"]:
            score -= 15
        if r["has_repeated_chars"]:
            score -= 10

        # Bonus for length compliance
        if r["length"] >= 12:
            score += 10

        return max(0, min(100, round(score)))
