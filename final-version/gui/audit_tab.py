"""
Audit Log tab: displays a read-only view of all logged actions.
"""

import tkinter as tk
from tkinter import ttk

from gui import theme


class AuditTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        header = tk.Frame(self, bg=theme.APP_BG)
        header.pack(fill="x", padx=20, pady=(18, 4))
        tk.Label(header, text="Audit Log", bg=theme.APP_BG, font=theme.FONT_H1, fg=theme.NAVY).pack(side="left")
        ttk.Button(header, text="\u21BB  Refresh", style="Accent.TButton", command=self.refresh).pack(side="right")
        tk.Label(self, text="Read-only record of every action performed within the application.",
                 bg=theme.APP_BG, fg=theme.MUTED, font=theme.FONT_SMALL).pack(anchor="w", padx=20, pady=(0, 12))

        table_wrap = tk.Frame(self, bg=theme.CARD_BG, highlightbackground=theme.BORDER, highlightthickness=1)
        table_wrap.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        columns = ("timestamp", "action_type", "performed_by", "details")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="headings", height=22)
        for col, width in zip(columns, (150, 180, 140, 520)):
            self.tree.heading(col, text=col.replace("_", " ").title())
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("odd", background="#f9fafb")
        self.tree.tag_configure("even", background="white")
        self.tree.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=1)

        scrollbar = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
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

        for i, log in enumerate(logs):
            tag = "even" if i % 2 == 0 else "odd"
            self.tree.insert("", "end", values=(
                str(log.get("timestamp", "")),
                log.get("action_type", ""),
                log.get("performed_by", ""),
                log.get("details", ""),
            ), tags=(tag,))
