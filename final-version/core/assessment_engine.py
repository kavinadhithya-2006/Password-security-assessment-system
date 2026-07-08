"""
AssessmentEngine
=================
Orchestrates a full password security assessment: strength analysis,
hash analysis, policy validation, risk scoring, and recommendations.
Persists the results via DatabaseManager.
"""

import hashlib

from core.password_analyzer import PasswordAnalyzer
from core.hash_analyzer import HashAnalyzer
from core.policy_validator import PolicyValidator
from core.risk_assessor import RiskAssessor
from core.recommender import Recommender


class AssessmentEngine:

    def __init__(self, db_manager):
        self.db = db_manager
        self.pwd_analyzer = PasswordAnalyzer()
        self.hash_analyzer = HashAnalyzer()
        self.policy_validator = PolicyValidator()
        self.risk_assessor = RiskAssessor()
        self.recommender = Recommender()

    def assess_plaintext_password(self, username: str, password: str,
                                   department: str = "", full_name: str = "",
                                   hash_algorithm: str = "SHA256") -> dict:
        """
        Full workflow when a plaintext password is supplied for testing
        (e.g. by an admin auditing a test account). The plaintext is
        analyzed in memory; only a hash of it is ever stored.
        """
        user_id = self.db.get_or_create_user(username, full_name, department)

        password_analysis = self.pwd_analyzer.analyze(password)

        computed_hash = self._compute_hash(password, hash_algorithm)
        hash_analysis = self.hash_analyzer.identify(computed_hash)
        # Force the algorithm label to what was requested, since we generated it ourselves
        hash_analysis["hash_algorithm"] = hash_algorithm
        from core.hash_analyzer import ALGORITHM_STRENGTH, DEPRECATED_ALGORITHMS
        hash_analysis["hash_strength_score"] = ALGORITHM_STRENGTH.get(hash_algorithm, 0)
        hash_analysis["hash_deprecated"] = hash_algorithm in DEPRECATED_ALGORITHMS

        is_reused = self._check_reuse(user_id, computed_hash)
        policy = self.db.get_active_policy()
        policy_result = self.policy_validator.validate(password, password_analysis, policy, is_reused)
        risk_result = self.risk_assessor.assess(password_analysis, hash_analysis, policy_result, is_reused)
        recommendations = self.recommender.generate(password_analysis, hash_analysis, policy_result, is_reused)

        record_id = self.db.add_password_record(user_id, computed_hash, hash_algorithm,
                                                 salted=hash_analysis.get("salted", False))

        assessment_data = {
            "record_id": record_id,
            "user_id": user_id,
            "strength_score": password_analysis["strength_score"],
            "entropy_bits": password_analysis["entropy_bits"],
            "length_ok": password_analysis["length"] >= policy.get("min_length", 12),
            "has_upper": password_analysis["has_upper"],
            "has_lower": password_analysis["has_lower"],
            "has_digit": password_analysis["has_digit"],
            "has_special": password_analysis["has_special"],
            "is_common_password": password_analysis["is_common_password"],
            "is_dictionary_word": password_analysis["is_dictionary_word"],
            "has_sequential_pattern": password_analysis["has_sequential_pattern"],
            "has_repeated_chars": password_analysis["has_repeated_chars"],
            "is_reused": is_reused,
            "hash_algorithm": hash_analysis["hash_algorithm"],
            "hash_deprecated": hash_analysis["hash_deprecated"],
            "policy_compliant": policy_result["policy_compliant"],
            "risk_level": risk_result["risk_level"],
            "risk_score": risk_result["risk_score"],
            "recommendations": "\n".join(recommendations),
        }

        assessment_id = self.db.save_assessment(assessment_data)
        self.db.save_violations(assessment_id, policy_result["violations"])
        self.db.log_action("PASSWORD_ASSESSMENT", username,
                            f"Assessed password for user '{username}', risk={risk_result['risk_level']}")

        assessment_data["assessment_id"] = assessment_id
        assessment_data["violations"] = policy_result["violations"]
        assessment_data["recommendations_list"] = recommendations
        assessment_data["username"] = username
        return assessment_data

    def assess_existing_hash(self, username: str, hash_str: str,
                              department: str = "", full_name: str = "") -> dict:
        """
        Workflow for analyzing an already-hashed password (no plaintext
        available) — used for auditing stored credential dumps / exports.
        """
        user_id = self.db.get_or_create_user(username, full_name, department)
        hash_analysis = self.hash_analyzer.identify(hash_str)

        is_reused = self._check_reuse(user_id, hash_str)
        policy = self.db.get_active_policy()

        # Without plaintext we can't measure entropy/complexity directly;
        # populate conservative placeholders and rely on hash + policy signals.
        password_analysis = {
            "length": 0, "has_upper": False, "has_lower": False, "has_digit": False,
            "has_special": False, "entropy_bits": 0, "is_common_password": False,
            "is_dictionary_word": False, "has_sequential_pattern": False,
            "has_repeated_chars": False, "strength_score": 50,
        }

        policy_result = self.policy_validator.validate("", password_analysis, policy, is_reused)
        # Length/complexity checks aren't meaningful without plaintext — drop them
        policy_result["violations"] = [
            v for v in policy_result["violations"]
            if v["type"] == "Password Reuse"
        ]
        policy_result["policy_compliant"] = len(policy_result["violations"]) == 0

        risk_result = self.risk_assessor.assess(password_analysis, hash_analysis, policy_result, is_reused)
        recommendations = self.recommender.generate(password_analysis, hash_analysis, policy_result, is_reused)

        record_id = self.db.add_password_record(user_id, hash_str, hash_analysis["hash_algorithm"],
                                                  salted=hash_analysis.get("salted", False))

        assessment_data = {
            "record_id": record_id,
            "user_id": user_id,
            "strength_score": None,
            "entropy_bits": 0,
            "length_ok": None,
            "has_upper": None, "has_lower": None, "has_digit": None, "has_special": None,
            "is_common_password": False,
            "is_dictionary_word": False,
            "has_sequential_pattern": False,
            "has_repeated_chars": False,
            "is_reused": is_reused,
            "hash_algorithm": hash_analysis["hash_algorithm"],
            "hash_deprecated": hash_analysis["hash_deprecated"],
            "policy_compliant": policy_result["policy_compliant"],
            "risk_level": risk_result["risk_level"],
            "risk_score": risk_result["risk_score"],
            "recommendations": "\n".join(recommendations),
        }

        assessment_id = self.db.save_assessment(assessment_data)
        self.db.save_violations(assessment_id, policy_result["violations"])
        self.db.log_action("HASH_ANALYSIS", username,
                            f"Analyzed stored hash for user '{username}', algorithm={hash_analysis['hash_algorithm']}")

        assessment_data["assessment_id"] = assessment_id
        assessment_data["violations"] = policy_result["violations"]
        assessment_data["recommendations_list"] = recommendations
        assessment_data["username"] = username
        return assessment_data

    # ------------------------------------------------------------------
    def _compute_hash(self, password: str, algorithm: str) -> str:
        algo_map = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
        }
        if algorithm in algo_map:
            return algo_map[algorithm](password.encode("utf-8")).hexdigest()
        if algorithm == "bcrypt":
            try:
                import bcrypt
                return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            except ImportError:
                return hashlib.sha256(password.encode("utf-8")).hexdigest()
        # default fallback
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _check_reuse(self, user_id: int, new_hash: str) -> bool:
        history = self.db.get_password_history(user_id, limit=10)
        return any(h["password_hash"] == new_hash for h in history)
