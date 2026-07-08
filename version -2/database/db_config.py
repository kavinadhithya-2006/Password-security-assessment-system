"""
Database connection configuration.

Edit the values below (or set the corresponding environment variables)
to match your local MySQL installation before running the application.
"""

import os

DB_CONFIG = {
    "host": os.getenv("PSAS_DB_HOST", "localhost"),
    "port": int(os.getenv("PSAS_DB_PORT", "3306")),
    "user": os.getenv("PSAS_DB_USER", "root"),
    "password": os.getenv("PSAS_DB_PASSWORD", "your_mysql_password"),
    "database": os.getenv("PSAS_DB_NAME", "password_security_db"),
}
