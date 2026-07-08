import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.hash_analyzer import HashAnalyzer, HashSecurityLevel


class TestHashAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = HashAnalyzer()

    def test_identify_md5(self):
        result = self.analyzer.analyze("5f4dcc3b5aa765d61d8327deb882cf99")  # 32 hex chars
        self.assertEqual(result.algorithm, "MD5")
        self.assertEqual(result.security_level, HashSecurityLevel.DEPRECATED)
        self.assertFalse(result.is_salted)

    def test_identify_sha1(self):
        result = self.analyzer.analyze("a" * 40)
        self.assertEqual(result.algorithm, "SHA-1")
        self.assertEqual(result.security_level, HashSecurityLevel.DEPRECATED)

    def test_identify_bcrypt(self):
        result = self.analyzer.analyze("$2b$12$KIXQ8w6z5j9Q0y7v1z2b3.eYQwF4nQwYQwF4nQwYQwF4nQwYQwF4")
        self.assertEqual(result.algorithm, "bcrypt")
        self.assertEqual(result.security_level, HashSecurityLevel.STRONG)
        self.assertTrue(result.is_salted)
        self.assertTrue(result.is_adaptive)

    def test_identify_argon2(self):
        result = self.analyzer.analyze("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash")
        self.assertEqual(result.algorithm, "Argon2")
        self.assertEqual(result.security_level, HashSecurityLevel.STRONG)

    def test_unknown_hash(self):
        result = self.analyzer.analyze("not-a-real-hash-format")
        self.assertEqual(result.algorithm, "Unknown")

    def test_low_bcrypt_cost_flagged(self):
        result = self.analyzer.analyze("$2b$04$KIXQ8w6z5j9Q0y7v1z2b3.eYQwF4nQwYQwF4nQwYQwF4nQwYQwF4")
        self.assertTrue(any("work factor" in f for f in result.findings))


if __name__ == "__main__":
    unittest.main()
