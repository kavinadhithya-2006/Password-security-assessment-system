import os
import sys
import unittest
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.policy_validator import PolicyValidator, PasswordPolicy


class TestPolicyValidator(unittest.TestCase):
    def setUp(self):
        self.policy = PasswordPolicy(min_length=12, max_password_age_days=90)
        self.validator = PolicyValidator(self.policy)

    def test_short_password_violates_length(self):
        result = self.validator.validate("Short1!")
        self.assertFalse(result.is_compliant)
        self.assertTrue(any("minimum required length" in v for v in result.violations))

    def test_compliant_password(self):
        result = self.validator.validate("Str0ngP@ssword2026!")
        self.assertTrue(result.is_compliant)

    def test_username_in_password_violation(self):
        result = self.validator.validate("jsmith12345!Aa", username="jsmith")
        self.assertFalse(result.is_compliant)
        self.assertTrue(any("username" in v for v in result.violations))

    def test_expired_password(self):
        old_date = date.today() - timedelta(days=120)
        result = self.validator.validate("Str0ngP@ssword2026!", password_last_changed=old_date)
        self.assertTrue(any("exceeds the maximum allowed age" in v for v in result.violations))

    def test_password_reuse(self):
        history = ["OldPassw0rd!1", "OldPassw0rd!2", "Str0ngP@ssword2026!"]
        result = self.validator.validate("Str0ngP@ssword2026!", password_history=history)
        self.assertTrue(any("reuse" in v for v in result.violations))


if __name__ == "__main__":
    unittest.main()
