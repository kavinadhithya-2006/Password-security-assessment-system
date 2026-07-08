"""
Recommender
===========
Generates plain-language security recommendations based on assessment
findings, aligned with OWASP / NIST guidance.
"""


class Recommender:

    def generate(self, password_analysis: dict, hash_analysis: dict,
                 policy_result: dict, is_reused: bool) -> list:
        recs = []

        if password_analysis["strength_score"] < 60:
            recs.append("Encourage the user to create a longer, higher-entropy password "
                        "(consider a passphrase of 4+ random words).")

        if password_analysis["is_common_password"]:
            recs.append("This password appears on known breach/common-password lists — "
                         "force an immediate reset.")

        if password_analysis["is_dictionary_word"]:
            recs.append("Avoid dictionary words; combine unrelated words, numbers, and symbols.")

        if password_analysis["has_sequential_pattern"]:
            recs.append("Avoid sequential keyboard or alphanumeric patterns (e.g. 'abcd', '1234').")

        if password_analysis["has_repeated_chars"]:
            recs.append("Avoid repeating the same character multiple times in a row.")

        if hash_analysis["hash_deprecated"]:
            recs.append(f"Migrate password storage from {hash_analysis['hash_algorithm']} to a modern, "
                        "adaptive hashing algorithm such as bcrypt, scrypt, or Argon2.")

        if not hash_analysis.get("salted", False):
            recs.append("Ensure passwords are salted before hashing to defend against rainbow-table attacks.")

        if is_reused:
            recs.append("Prevent password reuse by enforcing password history checks.")

        if not policy_result["policy_compliant"]:
            recs.append("Bring this credential into compliance with the organization's password policy.")

        # Always-applicable best practices
        recs.append("Enable Multi-Factor Authentication (MFA) for this account.")
        recs.append("Recommend the use of a password manager to generate and store unique passwords.")
        recs.append("Enforce periodic password rotation in line with organizational policy and NIST guidance.")

        return recs
