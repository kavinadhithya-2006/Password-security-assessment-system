"""
audit_logger.py

Lightweight audit logging for the Password Security Assessment System.
Records assessment events (never plaintext passwords) to a local
append-only log file for compliance and traceability purposes.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class AuditLogger:
    """Writes structured audit log entries in JSON-lines format."""

    def __init__(self, log_path: Optional[str] = None):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.log_path = log_path or os.path.join(base_dir, "logs", "audit_log.jsonl")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log_event(
        self,
        event_type: str,
        account_identifier: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "system",
    ) -> None:
        """
        Append an audit event.

        IMPORTANT: `details` must never contain plaintext passwords. Only
        derived, non-reversible metadata (scores, labels, counts) should
        be logged.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "actor": actor,
            "account_identifier": account_identifier,
            "details": details or {},
        }
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")

    def read_events(self) -> list:
        """Return all logged events (used for audit report generation)."""
        if not os.path.exists(self.log_path):
            return []
        events = []
        with open(self.log_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        return events
