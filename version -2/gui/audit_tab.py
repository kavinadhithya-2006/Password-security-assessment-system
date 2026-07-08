"""
Audit Log tab: displays a read-only view of all logged actions.
"""

import tkinter as tk
from tkinter import ttk


class AuditTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg="#ffffff")
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        header = tk.Frame(self, bg="#ffffff")
        header.pack(fill="x", padx=20, pady=(15, 5))
        tk.Label(header, text="Audit Log", bg="#ffffff",
                 font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(header, text="Refresh", command=self.refresh).pack(side="right")

        columns = ("timestamp", "action_type", "performed_by", "details")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=22)
        for col, width in zip(columns, (150, 170, 140, 500)):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=20, pady=10)

        scrollbar = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        if not self.db.is_connected():
            return

        try:
            logs = self.db.get_audit_log()
        except Exception:
            return

        for log in logs:
            self.tree.insert("", "end", values=(
                str(log.get("timestamp", "")),
                log.get("action_type", ""),
                log.get("performed_by", ""),
                log.get("details", ""),
            ))
