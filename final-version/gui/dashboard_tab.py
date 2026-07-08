"""
Dashboard tab: high-level KPIs and risk distribution chart.
"""

import tkinter as tk
from tkinter import ttk

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from gui import theme


class DashboardTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg=theme.APP_BG)
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        header = tk.Frame(self, bg=theme.APP_BG)
        header.pack(fill="x", padx=20, pady=(18, 4))
        tk.Label(header, text="Security Dashboard", bg=theme.APP_BG,
                 font=theme.FONT_H1, fg=theme.NAVY).pack(side="left")
        ttk.Button(header, text="\u21BB  Refresh", style="Accent.TButton",
                   command=self.refresh).pack(side="right")
        tk.Label(self, text="Live snapshot of organization-wide password security posture.",
                 bg=theme.APP_BG, fg=theme.MUTED, font=theme.FONT_SMALL).pack(anchor="w", padx=20, pady=(0, 12))

        self.cards_frame = tk.Frame(self, bg=theme.APP_BG)
        self.cards_frame.pack(fill="x", padx=20, pady=4)

        self.chart_frame = tk.Frame(self, bg=theme.CARD_BG, highlightbackground=theme.BORDER,
                                     highlightthickness=1)
        self.chart_frame.pack(fill="both", expand=True, padx=20, pady=(14, 20))

    def refresh(self):
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        if not self.db.is_connected():
            tk.Label(self.chart_frame, text="Database not connected.", bg=theme.CARD_BG,
                      fg=theme.DANGER, font=theme.FONT_BODY).pack(pady=40)
            return

        try:
            stats = self.db.get_dashboard_stats()
            distribution = self.db.get_risk_distribution()
        except Exception as e:
            tk.Label(self.chart_frame, text=f"Error loading dashboard: {e}", bg=theme.CARD_BG,
                      fg=theme.DANGER).pack(pady=40)
            return

        cards = [
            ("Total Users", stats.get("total_users", 0), "#3b82f6", "\U0001F465"),
            ("Total Assessments", stats.get("total_assessments", 0), "#6366f1", "\U0001F4CB"),
            ("Weak Passwords", stats.get("weak_passwords", 0), "#f59e0b", "\u26A0"),
            ("Deprecated Hashes", stats.get("deprecated_hashes", 0), "#ef4444", "\U0001F513"),
            ("Policy Violations", stats.get("policy_violations", 0), "#f97316", "\u2717"),
            ("High/Critical Risk", stats.get("high_risk", 0), "#dc2626", "\U0001F6A8"),
        ]

        for i, (label, value, color, icon) in enumerate(cards):
            c = theme.kpi_card(self.cards_frame, label, value, color, icon)
            c.grid(row=0, column=i, padx=6, sticky="nsew")

        for i in range(len(cards)):
            self.cards_frame.grid_columnconfigure(i, weight=1)

        # Risk distribution chart
        levels = ["Low", "Medium", "High", "Critical"]
        counts = {row["risk_level"]: row["cnt"] for row in distribution}
        values = [counts.get(lvl, 0) for lvl in levels]
        colors = [theme.RISK_COLORS[lvl][0] for lvl in levels]

        tk.Label(self.chart_frame, text="Risk Level Distribution", bg=theme.CARD_BG,
                 font=theme.FONT_H2, fg=theme.NAVY).pack(anchor="w", padx=18, pady=(16, 0))

        fig = Figure(figsize=(6, 3.4), dpi=100, facecolor=theme.CARD_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(theme.CARD_BG)
        bars = ax.bar(levels, values, color=colors, width=0.5, zorder=3)
        for spine in ("top", "right", "left"):
            ax.spines[spine].set_visible(False)
        ax.spines["bottom"].set_color("#d1d5db")
        ax.tick_params(colors=theme.SLATE, labelsize=9)
        ax.set_ylabel("Number of Assessments", fontsize=9, color=theme.SLATE)
        ax.grid(axis="y", linestyle="--", linewidth=0.6, color=theme.BORDER, zorder=0)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(val),
                    ha="center", va="bottom", fontsize=9, color=theme.NAVY, fontweight="bold")
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().configure(bg=theme.CARD_BG, highlightthickness=0)
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)
