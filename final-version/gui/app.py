"""
Main application window for the Password Security Assessment System.
Built with Tkinter/ttk. Each functional area lives in its own tab.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from database.db_manager import DatabaseManager
from core.assessment_engine import AssessmentEngine

from gui import theme
from gui.dashboard_tab import DashboardTab
from gui.assessment_tab import AssessmentTab
from gui.hash_tab import HashTab
from gui.policy_tab import PolicyTab
from gui.reports_tab import ReportsTab
from gui.audit_tab import AuditTab


class PasswordSecurityApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Password Security Assessment System")
        self.geometry("1200x760")
        self.minsize(1000, 640)

        theme.apply_global_style(self)

        self.db = DatabaseManager()
        connected, message = self.db.connect()

        self.engine = AssessmentEngine(self.db)

        self._build_header(connected, message)

        body = tk.Frame(self, bg=theme.APP_BG)
        body.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(body)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(10, 14))

        self.dashboard_tab = DashboardTab(self.notebook, self.db)
        self.assessment_tab = AssessmentTab(self.notebook, self.db, self.engine, on_saved=self.refresh_all)
        self.hash_tab = HashTab(self.notebook, self.db, self.engine, on_saved=self.refresh_all)
        self.policy_tab = PolicyTab(self.notebook, self.db)
        self.reports_tab = ReportsTab(self.notebook, self.db)
        self.audit_tab = AuditTab(self.notebook, self.db)

        self.notebook.add(self.dashboard_tab, text="  \U0001F4CA  Dashboard  ")
        self.notebook.add(self.assessment_tab, text="  \U0001F510  Password Assessment  ")
        self.notebook.add(self.hash_tab, text="  \U0001F50D  Hash Analysis  ")
        self.notebook.add(self.policy_tab, text="  \U0001F6E1  Policy Configuration  ")
        self.notebook.add(self.reports_tab, text="  \U0001F4C4  Reports  ")
        self.notebook.add(self.audit_tab, text="  \U0001F4CB  Audit Log  ")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        if not connected:
            messagebox.showwarning(
                "Database Connection",
                f"Could not connect to MySQL:\n{message}\n\n"
                "Update database/db_config.py with your MySQL credentials, "
                "make sure the schema has been imported, then restart the app."
            )

    def _build_header(self, connected, message):
        header = tk.Frame(self, bg=theme.NAVY, height=68)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        # Accent underline
        tk.Frame(self, bg=theme.ACCENT, height=3).pack(fill="x", side="top")

        left = tk.Frame(header, bg=theme.NAVY)
        left.pack(side="left", padx=18, pady=10)

        badge = tk.Label(left, text="\U0001F512", bg=theme.ACCENT, fg="white",
                          font=("Segoe UI", 15), width=2, height=1)
        badge.pack(side="left", padx=(0, 12))

        title_box = tk.Frame(left, bg=theme.NAVY)
        title_box.pack(side="left")
        tk.Label(title_box, text="Password Security Assessment System", bg=theme.NAVY, fg="white",
                 font=("Segoe UI", 15, "bold")).pack(anchor="w")
        tk.Label(title_box, text="Credential strength, hashing, and policy compliance auditing",
                 bg=theme.NAVY, fg="#9ca3af", font=("Segoe UI", 9)).pack(anchor="w")

        right = tk.Frame(header, bg=theme.NAVY)
        right.pack(side="right", padx=18)

        status_text = "Database Connected" if connected else "Database Disconnected"
        pill = theme.status_pill(right, status_text, ok=connected)
        pill.pack(anchor="e")
        self.status_label = pill

    def _on_tab_changed(self, event):
        current = self.notebook.select()
        widget = self.nametowidget(current)
        if hasattr(widget, "refresh"):
            widget.refresh()

    def refresh_all(self):
        for tab in (self.dashboard_tab, self.audit_tab):
            if hasattr(tab, "refresh"):
                tab.refresh()


def run_app():
    app = PasswordSecurityApp()
    app.mainloop()
