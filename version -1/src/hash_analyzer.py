"""
hash_analyzer.py

Analyzes password hash strings to identify the likely hashing algorithm,
flag deprecated/broken algorithms, and evaluate whether the storage
scheme follows modern best practice (salting, adaptive work factor).

NOTE: This module performs pattern-based *identification* of hash
formats for security auditing purposes only (e.g., "this looks like
unsalted MD5, which is deprecated"). It does not perform password
cracking, brute forcing, or hash reversal of any kind.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class HashSecurityLevel(str, Enum):
    DEPRECATED = "Deprecated"
    WEAK = "Weak"
    ACCEPTABLE = "Acceptable"
    STRONG = "Strong"
    UNKNOWN = "Unknown"


@dataclass
class HashAnalysisResult:
    algorithm: str
    security_level: HashSecurityLevel
    is_salted: bool
    is_adaptive: bool  # uses a tunable work factor (bcrypt/scrypt/argon2/PBKDF2)
    cost_factor: Optional[str]
    findings: List[str] = field(default_factory=list)


# Ordered so more specific / prefixed formats are checked before generic
# fixed-length hex hashes.
_HASH_SIGNATURES = [
    {
        "name": "Argon2",
        "pattern": re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$"),
        "salted": True,
        "adaptive": True,
        "level": HashSecurityLevel.STRONG,
    },
    {
        "name": "bcrypt",
        "pattern": re.compile(r"^\$2[aby]?\$\d{2}\$"),
        "salted": True,
        "adaptive": True,
        "level": HashSecurityLevel.STRONG,
    },
    {
        "name": "scrypt",
        "pattern": re.compile(r"^\$scrypt\$|^\$7\$"),
        "salted": True,
        "adaptive": True,
        "level": HashSecurityLevel.STRONG,
    },
    {
        "name": "PBKDF2",
        "pattern": re.compile(r"^\$pbkdf2(-sha\d+)?\$"),
        "salted": True,
        "adaptive": True,
        "level": HashSecurityLevel.ACCEPTABLE,
    },
    {
        "name": "MD5-crypt",
        "pattern": re.compile(r"^\$1\$"),
        "salted": True,
        "adaptive": False,
        "level": HashSecurityLevel.WEAK,
    },
    {
        "name": "SHA-256-crypt",
        "pattern": re.compile(r"^\$5\$"),
        "salted": True,
        "adaptive": False,
        "level": HashSecurityLevel.ACCEPTABLE,
    },
    {
        "name": "SHA-512-crypt",
        "pattern": re.compile(r"^\$6\$"),
        "salted": True,
        "adaptive": False,
        "level": HashSecurityLevel.ACCEPTABLE,
    },
]

# Fixed-length raw hex digests (checked after prefix-based formats).
# These are inherently unsalted/non-adaptive when stored as bare hex.
_HEX_LENGTH_MAP = {
    32: {"name": "MD5", "level": HashSecurityLevel.DEPRECATED},
    40: {"name": "SHA-1", "level": HashSecurityLevel.DEPRECATED},
    56: {"name": "SHA-224", "level": HashSecurityLevel.WEAK},
    64: {"name": "SHA-256", "level": HashSecurityLevel.WEAK},
    96: {"name": "SHA-384", "level": HashSecurityLevel.WEAK},
    128: {"name": "SHA-512", "level": HashSecurityLevel.WEAK},
}

DEPRECATED_ALGORITHMS = {"MD5", "SHA-1", "NTLM", "LM"}


class HashAnalyzer:
    """Identifies password hash formats and evaluates their security posture."""

    def identify_algorithm(self, hash_value: str) -> str:
        """Return the best-guess algorithm name for a given hash string."""
        hash_value = hash_value.strip()

        for sig in _HASH_SIGNATURES:
            if sig["pattern"].match(hash_value):
                return sig["name"]

        if re.fullmatch(r"[a-fA-F0-9]+", hash_value):
            info = _HEX_LENGTH_MAP.get(len(hash_value))
            if info:
                return info["name"]

        return "Unknown"

    def _lookup_signature(self, algorithm: str) -> Optional[dict]:
        for sig in _HASH_SIGNATURES:
            if sig["name"] == algorithm:
                return sig
        return None

    def analyze(self, hash_value: str) -> HashAnalysisResult:
        """Run a full analysis of a stored password hash."""
        hash_value = (hash_value or "").strip()
        findings: List[str] = []

        algorithm = self.identify_algorithm(hash_value)
        sig = self._lookup_signature(algorithm)

        is_salted = sig["salted"] if sig else False
        is_adaptive = sig["adaptive"] if sig else False

        if sig:
            level = sig["level"]
        else:
            level = HashSecurityLevel.UNKNOWN
            for _length, info in _HEX_LENGTH_MAP.items():
                if info["name"] == algorithm:
                    level = info["level"]
                    break

        cost_factor = None
        bcrypt_match = re.match(r"^\$2[aby]?\$(\d{2})\$", hash_value)
        pbkdf2_match = re.match(r"^\$pbkdf2(?:-sha\d+)?\$(\d+)\$", hash_value)
        argon2_match = re.match(
            r"^\$argon2(?:id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$", hash_value
        )

        if bcrypt_match:
            cost_factor = f"work factor {bcrypt_match.group(1)}"
            if int(bcrypt_match.group(1)) < 10:
                findings.append("bcrypt work factor is below the recommended minimum of 10.")
        elif pbkdf2_match:
            cost_factor = f"{pbkdf2_match.group(1)} iterations"
            if int(pbkdf2_match.group(1)) < 100_000:
                findings.append("PBKDF2 iteration count is below the recommended minimum of 100,000.")
        elif argon2_match:
            cost_factor = (
                f"memory={argon2_match.group(1)}KB, time={argon2_match.group(2)}, "
                f"parallelism={argon2_match.group(3)}"
            )

        if algorithm in DEPRECATED_ALGORITHMS:
            findings.append(
                f"{algorithm} is cryptographically broken/deprecated and unsuitable for password storage."
            )
        if not is_salted:
            findings.append(
                "No salt detected; identical passwords will produce identical hashes, "
                "enabling rainbow-table attacks."
            )
        if not is_adaptive:
            findings.append(
                "Algorithm has no configurable work factor, making it fast to brute-force "
                "with modern hardware (GPU/ASIC)."
            )
        if algorithm == "Unknown":
            findings.append("Hash format could not be positively identified from its structure/length.")

        if not findings:
            findings.append(
                "Hash uses a modern, salted, adaptive algorithm with no immediate concerns detected."
            )

        return HashAnalysisResult(
            algorithm=algorithm,
            security_level=level,
            is_salted=is_salted,
            is_adaptive=is_adaptive,
            cost_factor=cost_factor,
            findings=findings,
        )

    @staticmethod
    def compare_strength(result_a: HashAnalysisResult, result_b: HashAnalysisResult) -> str:
        """Return which of two hash results represents the stronger storage scheme."""
        order = {
            HashSecurityLevel.DEPRECATED: 0,
            HashSecurityLevel.WEAK: 1,
            HashSecurityLevel.UNKNOWN: 1,
            HashSecurityLevel.ACCEPTABLE: 2,
            HashSecurityLevel.STRONG: 3,
        }
        score_a = order[result_a.security_level] + (1 if result_a.is_adaptive else 0)
        score_b = order[result_b.security_level] + (1 if result_b.is_adaptive else 0)
        if score_a == score_b:
            return "Equal"
        return "A" if score_a > score_b else "B"
