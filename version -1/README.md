# Password Security Assessment System

A cybersecurity solution that evaluates the strength and security of user
passwords and password hashes across an organization's IT infrastructure.
It identifies weak passwords, insecure hashing algorithms, and password
policy violations, then generates risk-scored reports with actionable
security recommendations.

This project implements the requirements defined in
`Project Requirements - Password Security Assessment System`, covering
password strength assessment, hash analysis, policy validation, risk
scoring, reporting, and compliance alignment (OWASP / NIST / ISO 27001 / CIS).

## Features

| Requirement Area | Implementation |
|---|---|
| Password strength assessment | `src/password_analyzer.py` — entropy, complexity, common-password, sequential/repeated/keyboard pattern detection |
| Password hash analysis | `src/hash_analyzer.py` — identifies MD5, SHA-1/256/384/512, crypt formats, bcrypt, scrypt, PBKDF2, Argon2; flags deprecated/unsalted/non-adaptive hashing |
| Password policy validation | `src/policy_validator.py` — configurable length, character class, expiration, history/reuse, username-in-password checks |
| Security risk assessment | `src/risk_scorer.py` — Low / Medium / High / Critical classification from weighted sub-scores |
| Security recommendations | `src/recommendation_engine.py` — prioritized remediation guidance |
| Reporting | `src/report_generator.py` — PDF (reportlab) and Excel (openpyxl) exports: Executive Summary, Password Security, Hash Analysis, Policy Compliance, Risk Assessment, Recommendations |
| Audit logging | `src/audit_logger.py` — JSON-lines append-only log (never stores plaintext passwords) |
| Security dashboard | `src/dashboard.py` — terminal summary dashboard |
| Orchestration | `src/assessment_engine.py` — combines all modules per account |

## Project Structure

```
password_security_assessment/
├── main.py                      # CLI entry point
├── requirements.txt
├── data/
│   ├── common_passwords.txt     # Dictionary of known weak/breached passwords
│   ├── sample_accounts.csv      # Example input dataset
│   └── policy_config.json       # Example password policy configuration
├── src/
│   ├── password_analyzer.py
│   ├── hash_analyzer.py
│   ├── policy_validator.py
│   ├── risk_scorer.py
│   ├── recommendation_engine.py
│   ├── audit_logger.py
│   ├── assessment_engine.py
│   ├── report_generator.py
│   └── dashboard.py
├── tests/
│   ├── test_password_analyzer.py
│   ├── test_hash_analyzer.py
│   └── test_policy_validator.py
├── reports/                      # Generated PDF/Excel reports land here
└── logs/                         # Audit log output
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Run a full batch assessment (generates PDF + Excel reports)

```bash
python main.py --input data/sample_accounts.csv --policy data/policy_config.json --output reports/
```

This prints a text dashboard to the terminal and writes:
- `reports/password_security_report.pdf`
- `reports/password_security_report.xlsx`

### 2. Dashboard-only run (no report files)

```bash
python main.py --input data/sample_accounts.csv --dashboard-only
```

### 3. Interactively check a single password

```bash
python main.py --check-password
```

The password is entered via hidden input (`getpass`) and is never written
to disk in plaintext — only derived metrics (score, entropy, findings) are
displayed and, optionally, logged.

### CSV Input Format

```csv
account_id,username,password,password_hash,password_last_changed
ACC-1001,jsmith,password123,5f4dcc3b5aa765d61d8327deb882cf99,2025-01-15
```

- `password` and/or `password_hash` may be supplied per row.
- `password_last_changed` is an ISO date (`YYYY-MM-DD`), used for
  expiration-policy checks.

### Password Policy Configuration

Edit `data/policy_config.json` to match your organization's requirements:

```json
{
  "min_length": 12,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_digit": true,
  "require_special": true,
  "max_password_age_days": 90,
  "password_history_count": 5,
  "disallow_username_in_password": true
}
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Security & Handling Notes

- Plaintext passwords are held in memory only for the duration of analysis
  and are never written to the audit log, reports, or any file by this
  system.
- Hash analysis is purely pattern/format based (algorithm identification
  and configuration review). It does not attempt to crack, brute-force,
  or reverse any hash.
- The bundled `common_passwords.txt` is a small illustrative sample: in
  production, integrate a comprehensive breached-password corpus (e.g. via
  a k-anonymity API lookup) for stronger coverage.
- Sample bcrypt/Argon2/crypt hash values in `data/sample_accounts.csv` are
  illustrative placeholders for demonstrating format identification, not
  real credential hashes.

## Compliance Alignment

The scoring and recommendation logic reflects guidance from:
- OWASP Password Storage & Authentication Cheat Sheets
- NIST SP 800-63B Digital Identity Guidelines
- ISO/IEC 27001 Annex A authentication controls
- CIS Critical Security Controls

## Extending the System

- **New hash formats**: add a signature to `_HASH_SIGNATURES` in `hash_analyzer.py`.
- **Custom risk weighting**: adjust `WEIGHT_*` constants in `risk_scorer.py`.
- **Additional report formats**: extend `report_generator.py` (e.g. add a JSON/HTML exporter).
- **Web dashboard**: `src/dashboard.py` currently renders text output; it can be
  swapped for a Flask/FastAPI front end that reuses `AssessmentEngine` directly.
