import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.password_analyzer import PasswordAnalyzer


class TestPasswordAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PasswordAnalyzer()

    def test_common_password_detected(self):
        result = self.analyzer.analyze("password")
        self.assertTrue(result.is_common_password)
        self.assertEqual(result.strength_label, "Very Weak")

    def test_strong_password(self):
        result = self.analyzer.analyze("Xk9!mQ2#vR7$pL4w")
        self.assertGreaterEqual(result.strength_score, 60)
        self.assertFalse(result.is_common_password)

    def test_sequential_pattern_detected(self):
        result = self.analyzer.analyze("abcd1234")
        self.assertTrue(result.has_sequential_pattern)

    def test_repeated_pattern_detected(self):
        result = self.analyzer.analyze("aaa11111")
        self.assertTrue(result.has_repeated_pattern)

    def test_keyboard_pattern_detected(self):
        result = self.analyzer.analyze("qwerty12")
        self.assertTrue(result.is_keyboard_pattern)

    def test_entropy_increases_with_length_and_charset(self):
        short = self.analyzer.calculate_entropy("abc")
        long_mixed = self.analyzer.calculate_entropy("aB3$aB3$aB3$")
        self.assertGreater(long_mixed, short)

    def test_empty_password(self):
        result = self.analyzer.analyze("")
        self.assertEqual(result.strength_score, 0)
        self.assertEqual(result.strength_label, "Very Weak")


if __name__ == "__main__":
    unittest.main()
