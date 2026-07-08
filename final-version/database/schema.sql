-- ============================================================
-- Password Security Assessment System - Database Schema
-- MySQL 8.0+
-- ============================================================

CREATE DATABASE IF NOT EXISTS password_security_db
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE password_security_db;

-- ------------------------------------------------------------
-- Organizational users whose credentials are being assessed
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id        INT AUTO_INCREMENT PRIMARY KEY,
    username       VARCHAR(100) NOT NULL UNIQUE,
    full_name      VARCHAR(150),
    department     VARCHAR(100),
    email          VARCHAR(150),
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Password policy configuration (one active row per org, but
-- history of policies is kept for auditing)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_policy (
    policy_id           INT AUTO_INCREMENT PRIMARY KEY,
    policy_name         VARCHAR(100) NOT NULL DEFAULT 'Default Policy',
    min_length          INT NOT NULL DEFAULT 12,
    require_uppercase   BOOLEAN NOT NULL DEFAULT TRUE,
    require_lowercase   BOOLEAN NOT NULL DEFAULT TRUE,
    require_digit       BOOLEAN NOT NULL DEFAULT TRUE,
    require_special     BOOLEAN NOT NULL DEFAULT TRUE,
    max_age_days        INT NOT NULL DEFAULT 90,
    history_count       INT NOT NULL DEFAULT 5,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Password records submitted for assessment.
-- Only salted hashes / hash metadata are persisted; the
-- plaintext (if entered for testing) is analyzed in-memory
-- and never stored.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_records (
    record_id        INT AUTO_INCREMENT PRIMARY KEY,
    user_id           INT NOT NULL,
    password_hash     VARCHAR(255) NOT NULL,
    hash_algorithm    VARCHAR(50)  NOT NULL,
    hash_length       INT,
    salted            BOOLEAN DEFAULT FALSE,
    created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Password history (hashes only) used for reuse detection
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_history (
    history_id      INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,
    changed_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Assessment results for a given password record
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id       INT AUTO_INCREMENT PRIMARY KEY,
    record_id           INT NOT NULL,
    user_id             INT NOT NULL,
    strength_score       INT,              -- 0-100
    entropy_bits          DECIMAL(6,2),
    length_ok             BOOLEAN,
    has_upper              BOOLEAN,
    has_lower              BOOLEAN,
    has_digit               BOOLEAN,
    has_special              BOOLEAN,
    is_common_password        BOOLEAN,
    is_dictionary_word         BOOLEAN,
    has_sequential_pattern       BOOLEAN,
    has_repeated_chars             BOOLEAN,
    is_reused                        BOOLEAN,
    hash_algorithm                    VARCHAR(50),
    hash_deprecated                     BOOLEAN,
    policy_compliant                      BOOLEAN,
    risk_level                              ENUM('Low','Medium','High','Critical') NOT NULL,
    risk_score                               INT,               -- 0-100
    recommendations                            TEXT,
    assessed_at                                 DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (record_id) REFERENCES password_records(record_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)   REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Policy violations detected during assessment
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS policy_violations (
    violation_id     INT AUTO_INCREMENT PRIMARY KEY,
    assessment_id     INT NOT NULL,
    violation_type     VARCHAR(100) NOT NULL,
    details              VARCHAR(255),
    FOREIGN KEY (assessment_id) REFERENCES assessments(assessment_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Audit log of actions performed within the application
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    log_id        INT AUTO_INCREMENT PRIMARY KEY,
    action_type    VARCHAR(100) NOT NULL,
    performed_by    VARCHAR(100),
    details          TEXT,
    ip_address        VARCHAR(45),
    timestamp          DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Generated reports metadata
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    report_id     INT AUTO_INCREMENT PRIMARY KEY,
    report_type    VARCHAR(100) NOT NULL,
    file_format     VARCHAR(10)  NOT NULL,
    file_path         VARCHAR(500),
    generated_by       VARCHAR(100),
    generated_at         DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- Seed a default active policy
-- ------------------------------------------------------------
INSERT INTO password_policy
    (policy_name, min_length, require_uppercase, require_lowercase, require_digit, require_special, max_age_days, history_count, is_active)
SELECT * FROM (SELECT 'Default Policy' AS a, 12 AS b, TRUE AS c, TRUE AS d, TRUE AS e, TRUE AS f, 90 AS g, 5 AS h, TRUE AS i) AS tmp
WHERE NOT EXISTS (SELECT 1 FROM password_policy);
