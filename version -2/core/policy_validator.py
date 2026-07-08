"""
PolicyValidator
================
Checks a password (and its analysis results) against an organizational
password policy, returning a compliance flag and a list of violations.
"""


class PolicyValidator:

    def validate(self, password: str, analysis: dict, policy: dict, is_reused: bool = False) -> dict:
        violations = []

        min_length = policy.get("min_length", 12)
        if analysis["length"] < min_length:
            violations.append({
                "type": "Minimum Length",
                "details": f"Password length {analysis['length']} is below required {min_length}."
            })

        if policy.get("require_uppercase") and not analysis["has_upper"]:
            violations.append({"type": "Uppercase Required", "details": "Missing uppercase letter."})

        if policy.get("require_lowercase") and not analysis["has_lower"]:
            violations.append({"type": "Lowercase Required", "details": "Missing lowercase letter."})

        if policy.get("require_digit") and not analysis["has_digit"]:
            violations.append({"type": "Numeric Character Required", "details": "Missing numeric digit."})

        if policy.get("require_special") and not analysis["has_special"]:
            violations.append({"type": "Special Character Required", "details": "Missing special character."})

        if is_reused:
            violations.append({
                "type": "Password Reuse",
                "details": f"Password matches one of the last {policy.get('history_count', 5)} used passwords."
            })

        compliant = len(violations) == 0
        return {"policy_compliant": compliant, "violations": violations}
