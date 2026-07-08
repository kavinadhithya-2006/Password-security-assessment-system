# Password Security Assessment System

A desktop cybersecurity application (Python + Tkinter GUI + MySQL) that evaluates
password strength, analyzes password hashes, validates organizational password
policy compliance, scores risk, and generates security reports — built from the
provided project requirements document.

## Features

- **Password Security Assessment** — entropy, complexity, common/dictionary word
  detection, sequential-pattern and repeated-character detection, reuse detection.
- **Password Hash Analysis** — identifies hash algorithm (MD5, SHA1, SHA256, SHA512,
  bcrypt, Argon2, crypt formats, plaintext), flags deprecated algorithms, compares
  algorithm strength.
- **Password Policy Validation** — configurable minimum length, character
  requirements, expiration, and history rules.
- **Risk Scoring** — classifies each assessed credential as Low / Medium / High /
  Critical risk.
- **Recommendations Engine** — OWASP/NIST-aligned remediation guidance.
- **Reporting** — PDF and Excel export (Security Report, Policy Compliance Report,
  Risk Assessment Report, Executive Summary).
- **Audit Log** — every assessment, policy change, and report generation is logged.
- **Dashboard** — live KPI cards and a risk-distribution chart.

> **Note on data handling:** Plaintext test passwords are analyzed only in memory
> and are never written to disk or the database — only the resulting hash is
> stored. This tool is meant for authorized internal auditing of your own
> organization's accounts/test credentials.

## Project Structure

```
password_security_app/
├── main.py                     # Entry point
├── requirements.txt
├── database/
│   ├── schema.sql               # MySQL schema (run this first)
│   ├── db_config.py              # Your MySQL connection settings
│   └── db_manager.py              # All SQL queries
├── core/
│   ├── password_analyzer.py       # Strength / entropy / pattern checks
│   ├── hash_analyzer.py            # Hash algorithm identification
│   ├── policy_validator.py          # Policy compliance checks
│   ├── risk_assessor.py              # Risk scoring
│   ├── recommender.py                 # Recommendation generator
│   ├── assessment_engine.py            # Orchestrates the full workflow
│   └── common_passwords.py              # Weak/dictionary word lists
├── gui/
│   ├── app.py                      # Main window
│   ├── dashboard_tab.py
│   ├── assessment_tab.py
│   ├── hash_tab.py
│   ├── policy_tab.py
│   ├── reports_tab.py
│   └── audit_tab.py
└── reports/
    ├── pdf_generator.py
    └── excel_generator.py
```

## Setup (VS Code)

### 1. Prerequisites
- Python 3.10+ installed
- MySQL Server 8.0+ installed and running
- VS Code with the **Python** extension

### 2. Install MySQL schema
Open a terminal (or MySQL Workbench) and run:
```bash
mysql -u root -p < database/schema.sql
```
This creates the `password_security_db` database and all required tables, and
seeds a default password policy.

### 3. Open the project in VS Code
```bash
cd password_security_app
code .
```

### 4. Create a virtual environment (recommended)
In the VS Code integrated terminal:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

### 5. Install dependencies
```bash
pip install -r requirements.txt
```

### 6. Configure your database credentials
Edit `database/db_config.py`:
```python
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "YOUR_MYSQL_PASSWORD",
    "database": "password_security_db",
}
```
(Alternatively set the `PSAS_DB_HOST`, `PSAS_DB_USER`, `PSAS_DB_PASSWORD`,
`PSAS_DB_NAME`, `PSAS_DB_PORT` environment variables.)

### 7. Run the application
- Press **F5** in VS Code (uses the included `.vscode/launch.json`), or
- Run from the terminal:
```bash
python main.py
```

## Using the Application

1. **Password Assessment tab** — enter a username and a test password, choose a
   hashing algorithm to simulate, and click **Run Assessment** to get a full
   strength/risk/compliance report.
2. **Hash Analysis tab** — paste an already-hashed credential (e.g. from a
   credential export you are authorized to audit) to identify its algorithm and
   flag deprecated hashing.
3. **Policy Configuration tab** — set your organization's password policy
   (length, complexity, expiration, history).
4. **Reports tab** — generate PDF or Excel reports and open them directly from
   the list.
5. **Dashboard tab** — view live KPIs and the risk distribution chart.
6. **Audit Log tab** — review every action taken in the system.

## Troubleshooting

- **"DB Disconnected" banner** — check that MySQL is running and that
  `database/db_config.py` has correct credentials, then restart the app.
- **`ModuleNotFoundError`** — make sure your virtual environment is activated
  and `pip install -r requirements.txt` completed without errors.
- **Matplotlib chart not rendering on Linux** — ensure a Tk-compatible backend
  is available (`sudo apt install python3-tk`).
