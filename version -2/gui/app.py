"""
Main application window for the Password Security Assessment System.
Built with Tkinter/ttk. Each functional area lives in its own tab.
"""

import tkinter as tk
from tkinter import ttk, messagebox

from database.db_manager import DatabaseManager
from core.assessment_engine import AssessmentEngine

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
        self.geometry("1150x720")
        self.minsize(950, 620)

        self._configure_style()

        self.db = DatabaseManager()
        connected, message = self.db.connect()

        self.engine = AssessmentEngine(self.db)

        self._build_header(connected, message)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.dashboard_tab = DashboardTab(self.notebook, self.db)
        self.assessment_tab = AssessmentTab(self.notebook, self.db, self.engine, on_saved=self.refresh_all)
        self.hash_tab = HashTab(self.notebook, self.db, self.engine, on_saved=self.refresh_all)
        self.policy_tab = PolicyTab(self.notebook, self.db)
        self.reports_tab = ReportsTab(self.notebook, self.db)
        self.audit_tab = AuditTab(self.notebook, self.db)

        self.notebook.add(self.dashboard_tab, text="  Dashboard  ")
        self.notebook.add(self.assessment_tab, text="  Password Assessment  ")
        self.notebook.add(self.hash_tab, text="  Hash Analysis  ")
        self.notebook.add(self.policy_tab, text="  Policy Configuration  ")
        self.notebook.add(self.reports_tab, text="  Reports  ")
        self.notebook.add(self.audit_tab, text="  Audit Log  ")

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        if not connected:
            messagebox.showwarning(
                "Database Connection",
                f"Could not connect to MySQL:\n{message}\n\n"
                "Update database/db_config.py with your MySQL credentials, "
                "make sure the schema has been imported, then restart the app."
            )

    def _configure_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI", 10))
        style.configure("TButton", padding=(10, 6), font=("Segoe UI", 10))
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_header(self, connected, message):
        header = tk.Frame(self, bg="#1f2937", height=64)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        tk.Label(header, text="🔒 Password Security Assessment System",
                 bg="#1f2937", fg="white", font=("Segoe UI", 16, "bold")).pack(side="left", padx=16)

        status_text = "● DB Connected" if connected else "● DB Disconnected"
        status_color = "#4ade80" if connected else "#f87171"
        self.status_label = tk.Label(header, text=status_text, bg="#1f2937",
                                      fg=status_color, font=("Segoe UI", 10, "bold"))
        self.status_label.pack(side="right", padx=16)

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
