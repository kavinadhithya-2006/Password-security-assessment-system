"""
DatabaseManager
================
Central place for every MySQL interaction used by the application.
Uses mysql-connector-python.
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime

from database.db_config import DB_CONFIG


class DatabaseManager:
    def __init__(self):
        self.connection = None

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------
    def connect(self):
        try:
            self.connection = mysql.connector.connect(**DB_CONFIG)
            return True, "Connected successfully."
        except Error as e:
            return False, str(e)

    def is_connected(self):
        return self.connection is not None and self.connection.is_connected()

    def close(self):
        if self.is_connected():
            self.connection.close()

    def _cursor(self, dictionary=True):
        if not self.is_connected():
            self.connect()
        return self.connection.cursor(dictionary=dictionary)

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------
    def add_user(self, username, full_name="", department="", email=""):
        cur = self._cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, full_name, department, email) VALUES (%s,%s,%s,%s)",
                (username, full_name, department, email),
            )
            self.connection.commit()
            return cur.lastrowid
        finally:
            cur.close()

    def get_users(self):
        cur = self._cursor()
        try:
            cur.execute("SELECT * FROM users ORDER BY created_at DESC")
            return cur.fetchall()
        finally:
            cur.close()

    def find_user_by_username(self, username):
        cur = self._cursor()
        try:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()
        finally:
            cur.close()

    def get_or_create_user(self, username, full_name="", department="", email=""):
        user = self.find_user_by_username(username)
        if user:
            return user["user_id"]
        return self.add_user(username, full_name, department, email)

    # ------------------------------------------------------------------
    # Password policy
    # ------------------------------------------------------------------
    def get_active_policy(self):
        cur = self._cursor()
        try:
            cur.execute("SELECT * FROM password_policy WHERE is_active=TRUE ORDER BY policy_id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                return row
            # fallback default
            return {
                "min_length": 12, "require_uppercase": 1, "require_lowercase": 1,
                "require_digit": 1, "require_special": 1, "max_age_days": 90,
                "history_count": 5,
            }
        finally:
            cur.close()

    def update_policy(self, policy_name, min_length, req_upper, req_lower,
                       req_digit, req_special, max_age_days, history_count):
        cur = self._cursor()
        try:
            cur.execute("UPDATE password_policy SET is_active=FALSE WHERE is_active=TRUE")
            cur.execute(
                """INSERT INTO password_policy
                   (policy_name, min_length, require_uppercase, require_lowercase,
                    require_digit, require_special, max_age_days, history_count, is_active)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,TRUE)""",
                (policy_name, min_length, req_upper, req_lower, req_digit,
                 req_special, max_age_days, history_count),
            )
            self.connection.commit()
            return cur.lastrowid
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # Password records + history
    # ------------------------------------------------------------------
    def add_password_record(self, user_id, password_hash, hash_algorithm, salted=False):
        cur = self._cursor()
        try:
            cur.execute(
                """INSERT INTO password_records (user_id, password_hash, hash_algorithm, hash_length, salted)
                   VALUES (%s,%s,%s,%s,%s)""",
                (user_id, password_hash, hash_algorithm, len(password_hash), salted),
            )
            self.connection.commit()
            record_id = cur.lastrowid
            cur.execute(
                "INSERT INTO password_history (user_id, password_hash) VALUES (%s,%s)",
                (user_id, password_hash),
            )
            self.connection.commit()
            return record_id
        finally:
            cur.close()

    def get_password_history(self, user_id, limit=10):
        cur = self._cursor()
        try:
            cur.execute(
                "SELECT * FROM password_history WHERE user_id=%s ORDER BY changed_at DESC LIMIT %s",
                (user_id, limit),
            )
            return cur.fetchall()
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------
    def save_assessment(self, data):
        """data is a dict matching the assessments table columns (minus assessment_id)."""
        cur = self._cursor()
        try:
            columns = ", ".join(data.keys())
            placeholders = ", ".join(["%s"] * len(data))
            cur.execute(
                f"INSERT INTO assessments ({columns}) VALUES ({placeholders})",
                tuple(data.values()),
            )
            self.connection.commit()
            return cur.lastrowid
        finally:
            cur.close()

    def save_violations(self, assessment_id, violations):
        if not violations:
            return
        cur = self._cursor()
        try:
            cur.executemany(
                "INSERT INTO policy_violations (assessment_id, violation_type, details) VALUES (%s,%s,%s)",
                [(assessment_id, v["type"], v.get("details", "")) for v in violations],
            )
            self.connection.commit()
        finally:
            cur.close()

    def get_assessments(self, limit=200):
        cur = self._cursor()
        try:
            cur.execute(
                """SELECT a.*, u.username, u.department
                   FROM assessments a JOIN users u ON a.user_id = u.user_id
                   ORDER BY a.assessed_at DESC LIMIT %s""",
                (limit,),
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_risk_distribution(self):
        cur = self._cursor()
        try:
            cur.execute(
                "SELECT risk_level, COUNT(*) as cnt FROM assessments GROUP BY risk_level"
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_violations_for_assessment(self, assessment_id):
        cur = self._cursor()
        try:
            cur.execute(
                "SELECT * FROM policy_violations WHERE assessment_id=%s", (assessment_id,)
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_all_violations(self, limit=1000):
        """All policy violations joined with the user/assessment they belong to.
        Used to build the Policy Compliance report."""
        cur = self._cursor()
        try:
            cur.execute(
                """SELECT v.violation_id, v.violation_type, v.details, v.assessment_id,
                          a.risk_level, a.assessed_at, u.username, u.department
                   FROM policy_violations v
                   JOIN assessments a ON v.assessment_id = a.assessment_id
                   JOIN users u ON a.user_id = u.user_id
                   ORDER BY a.assessed_at DESC LIMIT %s""",
                (limit,),
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_violation_type_counts(self):
        cur = self._cursor()
        try:
            cur.execute(
                """SELECT violation_type, COUNT(*) as cnt FROM policy_violations
                   GROUP BY violation_type ORDER BY cnt DESC"""
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_hash_algorithm_distribution(self):
        cur = self._cursor()
        try:
            cur.execute(
                """SELECT hash_algorithm, COUNT(*) as cnt,
                          SUM(CASE WHEN hash_deprecated THEN 1 ELSE 0 END) as deprecated_cnt
                   FROM assessments GROUP BY hash_algorithm"""
            )
            return cur.fetchall()
        finally:
            cur.close()

    def get_dashboard_stats(self):
        cur = self._cursor()
        try:
            stats = {}
            cur.execute("SELECT COUNT(*) as c FROM users")
            stats["total_users"] = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM assessments")
            stats["total_assessments"] = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM assessments WHERE is_common_password=TRUE")
            stats["weak_passwords"] = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM assessments WHERE hash_deprecated=TRUE")
            stats["deprecated_hashes"] = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM assessments WHERE policy_compliant=FALSE")
            stats["policy_violations"] = cur.fetchone()["c"]

            cur.execute("SELECT COUNT(*) as c FROM assessments WHERE risk_level IN ('High','Critical')")
            stats["high_risk"] = cur.fetchone()["c"]
            return stats
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------
    def log_action(self, action_type, performed_by="system", details=""):
        cur = self._cursor()
        try:
            cur.execute(
                "INSERT INTO audit_log (action_type, performed_by, details) VALUES (%s,%s,%s)",
                (action_type, performed_by, details),
            )
            self.connection.commit()
        finally:
            cur.close()

    def get_audit_log(self, limit=300):
        cur = self._cursor()
        try:
            cur.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT %s", (limit,))
            return cur.fetchall()
        finally:
            cur.close()

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def save_report_record(self, report_type, file_format, file_path, generated_by="system"):
        cur = self._cursor()
        try:
            cur.execute(
                """INSERT INTO reports (report_type, file_format, file_path, generated_by)
                   VALUES (%s,%s,%s,%s)""",
                (report_type, file_format, file_path, generated_by),
            )
            self.connection.commit()
            return cur.lastrowid
        finally:
            cur.close()
