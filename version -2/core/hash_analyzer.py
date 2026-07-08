"""
HashAnalyzer
============
Identifies the likely hashing algorithm used to produce a given hash
string (based on prefix / length / character-set heuristics), and
flags algorithms considered deprecated or insecure for password storage.
"""

import re


DEPRECATED_ALGORITHMS = {"MD5", "SHA1", "Plaintext", "MD5-Crypt", "DES-Crypt"}

# Relative strength ranking used for comparisons / reporting (higher = stronger)
ALGORITHM_STRENGTH = {
    "Plaintext": 0,
    "MD5": 5,
    "SHA1": 10,
    "DES-Crypt": 5,
    "MD5-Crypt": 15,
    "SHA256": 30,
    "SHA512": 35,
    "SHA256-Crypt": 55,
    "SHA512-Crypt": 60,
    "bcrypt": 80,
    "scrypt": 85,
    "Argon2": 95,
    "PBKDF2": 70,
    "Unknown": 0,
}


class HashAnalyzer:

    def identify(self, hash_str: str) -> dict:
        hash_str = hash_str.strip()
        algorithm = self._identify_algorithm(hash_str)
        deprecated = algorithm in DEPRECATED_ALGORITHMS
        strength = ALGORITHM_STRENGTH.get(algorithm, 0)

        return {
            "hash_algorithm": algorithm,
            "hash_length": len(hash_str),
            "hash_deprecated": deprecated,
            "hash_strength_score": strength,
            "salted": self._appears_salted(hash_str, algorithm),
        }

    def _identify_algorithm(self, h: str) -> str:
        if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            return "bcrypt"
        if h.startswith("$argon2"):
            return "Argon2"
        if h.startswith("$1$"):
            return "MD5-Crypt"
        if h.startswith("$5$"):
            return "SHA256-Crypt"
        if h.startswith("$6$"):
            return "SHA512-Crypt"
        if h.startswith("$s$") or h.startswith("$7$"):
            return "scrypt"
        if h.startswith("pbkdf2:") or h.lower().startswith("pbkdf2_sha256"):
            return "PBKDF2"

        if re.fullmatch(r"[a-fA-F0-9]{32}", h):
            return "MD5"
        if re.fullmatch(r"[a-fA-F0-9]{40}", h):
            return "SHA1"
        if re.fullmatch(r"[a-fA-F0-9]{64}", h):
            return "SHA256"
        if re.fullmatch(r"[a-fA-F0-9]{128}", h):
            return "SHA512"
        if re.fullmatch(r"[a-fA-F0-9]{16}", h):
            return "DES-Crypt"

        if len(h) > 0 and not re.fullmatch(r"[a-fA-F0-9$./A-Za-z0-9]+", h):
            return "Unknown"

        # Fallback: if it doesn't look like any known hash pattern and
        # is short/human-readable, treat as plaintext storage (very bad).
        if 1 <= len(h) <= 30 and re.search(r"[A-Za-z]", h) and not re.fullmatch(r"[a-fA-F0-9]+", h):
            return "Plaintext"

        return "Unknown"

    def _appears_salted(self, h: str, algorithm: str) -> bool:
        # Modern KDFs embed the salt in the encoded hash itself.
        return algorithm in {"bcrypt", "Argon2", "scrypt", "SHA256-Crypt", "SHA512-Crypt", "PBKDF2"}

    def compare(self, algo_a: str, algo_b: str) -> str:
        """Return which algorithm is stronger."""
        sa, sb = ALGORITHM_STRENGTH.get(algo_a, 0), ALGORITHM_STRENGTH.get(algo_b, 0)
        if sa == sb:
            return "Equal strength"
        return algo_a if sa > sb else algo_b
