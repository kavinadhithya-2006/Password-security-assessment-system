"""
Dashboard tab: high-level KPIs and risk distribution chart.
"""

import tkinter as tk
from tkinter import ttk

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class DashboardTab(tk.Frame):

    def __init__(self, parent, db):
        super().__init__(parent, bg="#f3f4f6")
        self.db = db
        self._build()
        self.refresh()

    def _build(self):
        title = tk.Label(self, text="Security Dashboard", bg="#f3f4f6",
                          font=("Segoe UI", 15, "bold"), fg="#111827")
        title.pack(anchor="w", padx=20, pady=(15, 5))

        self.cards_frame = tk.Frame(self, bg="#f3f4f6")
        self.cards_frame.pack(fill="x", padx=20, pady=10)

        self.chart_frame = tk.Frame(self, bg="#f3f4f6")
        self.chart_frame.pack(fill="both", expand=True, padx=20, pady=10)

        refresh_btn = ttk.Button(self, text="Refresh Dashboard", command=self.refresh)
        refresh_btn.pack(anchor="e", padx=20, pady=(0, 10))

    def refresh(self):
        for widget in self.cards_frame.winfo_children():
            widget.destroy()
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        if not self.db.is_connected():
            tk.Label(self.chart_frame, text="Database not connected.", bg="#f3f4f6",
                      fg="#dc2626", font=("Segoe UI", 11)).pack(pady=40)
            return

        try:
            stats = self.db.get_dashboard_stats()
            distribution = self.db.get_risk_distribution()
        except Exception as e:
            tk.Label(self.chart_frame, text=f"Error loading dashboard: {e}", bg="#f3f4f6",
                      fg="#dc2626").pack(pady=40)
            return

        cards = [
            ("Total Users", stats.get("total_users", 0), "#3b82f6"),
            ("Total Assessments", stats.get("total_assessments", 0), "#6366f1"),
            ("Weak Passwords", stats.get("weak_passwords", 0), "#f59e0b"),
            ("Deprecated Hashes", stats.get("deprecated_hashes", 0), "#ef4444"),
            ("Policy Violations", stats.get("policy_violations", 0), "#f97316"),
            ("High/Critical Risk", stats.get("high_risk", 0), "#dc2626"),
        ]

        for i, (label, value, color) in enumerate(cards):
            card = tk.Frame(self.cards_frame, bg=color, width=170, height=90)
            card.grid(row=0, column=i, padx=8, sticky="nsew")
            card.grid_propagate(False)
            tk.Label(card, text=str(value), bg=color, fg="white",
                     font=("Segoe UI", 20, "bold")).pack(pady=(12, 0))
            tk.Label(card, text=label, bg=color, fg="white",
                     font=("Segoe UI", 9)).pack()

        for i in range(len(cards)):
            self.cards_frame.grid_columnconfigure(i, weight=1)

        # Risk distribution chart
        levels = ["Low", "Medium", "High", "Critical"]
        counts = {row["risk_level"]: row["cnt"] for row in distribution}
        values = [counts.get(lvl, 0) for lvl in levels]
        colors = ["#22c55e", "#facc15", "#fb923c", "#ef4444"]

        fig = Figure(figsize=(6, 3.6), dpi=100)
        ax = fig.add_subplot(111)
        bars = ax.bar(levels, values, color=colors)
        ax.set_title("Risk Level Distribution")
        ax.set_ylabel("Number of Assessments")
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(val),
                    ha="center", va="bottom", fontsize=9)

        canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
