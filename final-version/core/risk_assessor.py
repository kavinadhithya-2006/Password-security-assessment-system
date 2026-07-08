"""
RiskAssessor
============
Combines password-strength analysis, hash analysis, and policy
compliance results into an overall risk score (0-100) and a
Low / Medium / High / Critical classification.
"""


class RiskAssessor:

    def assess(self, password_analysis: dict, hash_analysis: dict, policy_result: dict, is_reused: bool) -> dict:
        risk_score = 0

        # Weak strength -> higher risk
        risk_score += (100 - password_analysis["strength_score"]) * 0.4

        # Deprecated / weak hashing algorithm -> higher risk
        risk_score += (100 - hash_analysis["hash_strength_score"]) * 0.3

        # Policy non-compliance
        if not policy_result["policy_compliant"]:
            risk_score += 10 + (len(policy_result["violations"]) * 3)

        # Specific red flags
        if password_analysis["is_common_password"]:
            risk_score += 20
        if password_analysis["is_dictionary_word"]:
            risk_score += 8
        if password_analysis["has_sequential_pattern"]:
            risk_score += 8
        if password_analysis["has_repeated_chars"]:
            risk_score += 6
        if is_reused:
            risk_score += 10

        risk_score = max(0, min(100, round(risk_score)))
        risk_level = self._classify(risk_score)

        return {"risk_score": risk_score, "risk_level": risk_level}

    def _classify(self, score: int) -> str:
        if score >= 75:
            return "Critical"
        if score >= 50:
            return "High"
        if score >= 25:
            return "Medium"
        return "Low"
