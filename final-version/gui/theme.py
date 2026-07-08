"""
theme.py
========
Central design system for the desktop UI: color palette, fonts, ttk
styling, and small reusable widgets (cards, badges, section headers)
so every tab shares a consistent, modern look.
"""

import tkinter as tk
from tkinter import ttk

# ----------------------------------------------------------------------
# Palette
# ----------------------------------------------------------------------
NAVY = "#111827"
NAVY_SOFT = "#1f2937"
SLATE = "#374151"
MUTED = "#6b7280"
BORDER = "#e5e7eb"
APP_BG = "#f3f4f6"
CARD_BG = "#ffffff"
ACCENT = "#2563eb"
ACCENT_DARK = "#1d4ed8"
ACCENT_SOFT = "#eff6ff"

SUCCESS = "#16a34a"
SUCCESS_SOFT = "#dcfce7"
WARNING = "#d97706"
WARNING_SOFT = "#fef3c7"
DANGER = "#dc2626"
DANGER_SOFT = "#fee2e2"
INFO = "#2563eb"

RISK_COLORS = {
    "Low": ("#16a34a", "#dcfce7"),
    "Medium": ("#d97706", "#fef3c7"),
    "High": ("#ea580c", "#ffedd5"),
    "Critical": ("#dc2626", "#fee2e2"),
}

FONT_FAMILY = "Segoe UI"


def f(size, weight="normal", italic=False):
    slant = "italic" if italic else "roman"
    style = weight
    if italic:
        style = f"{weight} {slant}" if weight != "normal" else slant
    return (FONT_FAMILY, size, style) if style != "normal" else (FONT_FAMILY, size)


FONT_H1 = (FONT_FAMILY, 17, "bold")
FONT_H2 = (FONT_FAMILY, 13, "bold")
FONT_H3 = (FONT_FAMILY, 10, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MUTED_ITALIC = (FONT_FAMILY, 8, "italic")
FONT_MONO = ("Consolas", 10)


def apply_global_style(root):
    """Configure ttk styles used across the whole application."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=APP_BG)

    style.configure(".", font=FONT_BODY, background=CARD_BG)

    # Notebook / tabs
    style.configure("TNotebook", background=APP_BG, borderwidth=0, tabmargins=(8, 8, 8, 0))
    style.configure("TNotebook.Tab", padding=(16, 10), font=(FONT_FAMILY, 10, "bold"),
                     background="#e5e7eb", foreground=SLATE, borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", CARD_BG)],
              foreground=[("selected", ACCENT_DARK)])

    # Buttons
    style.configure("TButton", padding=(12, 7), font=(FONT_FAMILY, 10),
                     background="#e5e7eb", foreground=SLATE, borderwidth=0)
    style.map("TButton", background=[("active", "#d1d5db")])

    style.configure("Accent.TButton", padding=(14, 8), font=(FONT_FAMILY, 10, "bold"),
                     background=ACCENT, foreground="white", borderwidth=0)
    style.map("Accent.TButton", background=[("active", ACCENT_DARK), ("pressed", ACCENT_DARK)])

    style.configure("Danger.TButton", padding=(12, 7), font=(FONT_FAMILY, 10, "bold"),
                     background=DANGER, foreground="white", borderwidth=0)
    style.map("Danger.TButton", background=[("active", "#b91c1c")])

    # Entries / combos
    style.configure("TEntry", padding=6, fieldbackground="white", bordercolor=BORDER,
                     lightcolor=BORDER, darkcolor=BORDER, relief="solid", borderwidth=1)
    style.configure("TCombobox", padding=6, fieldbackground="white")
    style.configure("TSpinbox", padding=6, fieldbackground="white")
    style.configure("TCheckbutton", background=CARD_BG, font=FONT_BODY)
    style.configure("TLabel", background=CARD_BG, font=FONT_BODY, foreground=SLATE)

    # Treeview
    style.configure("Treeview", rowheight=26, font=(FONT_FAMILY, 9), background="white",
                     fieldbackground="white", borderwidth=0)
    style.configure("Treeview.Heading", font=(FONT_FAMILY, 9, "bold"),
                     background=NAVY_SOFT, foreground="white", relief="flat")
    style.map("Treeview.Heading", background=[("active", NAVY)])
    style.map("Treeview", background=[("selected", ACCENT_SOFT)], foreground=[("selected", NAVY)])

    # Progressbar (used nowhere yet, but keep consistent if added later)
    style.configure("TProgressbar", troughcolor=BORDER, background=ACCENT, thickness=8)

    return style


# ------------------------------------------------------------------
# Reusable composite widgets
# ------------------------------------------------------------------
def page_header(parent, title, subtitle=None):
    """A consistent page title block used at the top of every tab."""
    wrap = tk.Frame(parent, bg=CARD_BG)
    wrap.pack(fill="x", padx=24, pady=(20, 6))
    tk.Label(wrap, text=title, bg=CARD_BG, fg=NAVY, font=FONT_H1).pack(anchor="w")
    if subtitle:
        tk.Label(wrap, text=subtitle, bg=CARD_BG, fg=MUTED, font=FONT_SMALL).pack(anchor="w", pady=(2, 0))
    sep = tk.Frame(parent, bg=BORDER, height=1)
    sep.pack(fill="x", padx=24, pady=(10, 4))
    return wrap


def card(parent, bg=CARD_BG, padx=18, pady=16, **pack_kwargs):
    """A simple bordered 'card' container frame."""
    outer = tk.Frame(parent, bg=BORDER)
    container = tk.Frame(outer, bg=bg)
    container.pack(fill="both", expand=True, padx=1, pady=1)
    inner = tk.Frame(container, bg=bg)
    inner.pack(fill="both", expand=True, padx=padx, pady=pady)
    defaults = {"fill": "x", "padx": 24, "pady": 10}
    defaults.update(pack_kwargs)
    outer.pack(**defaults)
    return inner


def section_title(parent, text, bg=CARD_BG):
    tk.Label(parent, text=text, bg=bg, fg=NAVY, font=FONT_H2).pack(anchor="w", pady=(0, 8))


def status_pill(parent, text, ok=True):
    color = SUCCESS if ok else DANGER
    soft = SUCCESS_SOFT if ok else DANGER_SOFT
    dot = "\u25CF"
    lbl = tk.Label(parent, text=f"{dot} {text}", bg=soft, fg=color,
                    font=(FONT_FAMILY, 9, "bold"), padx=10, pady=4)
    return lbl


def risk_badge(parent, level):
    color, soft = RISK_COLORS.get(level, (MUTED, "#f3f4f6"))
    lbl = tk.Label(parent, text=(level or "-").upper(), bg=soft, fg=color,
                    font=(FONT_FAMILY, 9, "bold"), padx=10, pady=3)
    return lbl


def kpi_card(parent, label, value, color, icon=""):
    outer = tk.Frame(parent, bg=color, highlightthickness=0)
    inner = tk.Frame(outer, bg=color)
    inner.pack(fill="both", expand=True, padx=14, pady=12)
    top = tk.Frame(inner, bg=color)
    top.pack(fill="x")
    if icon:
        tk.Label(top, text=icon, bg=color, fg="white", font=(FONT_FAMILY, 14)).pack(side="left")
    tk.Label(inner, text=str(value), bg=color, fg="white",
             font=(FONT_FAMILY, 22, "bold")).pack(anchor="w", pady=(4, 0))
    tk.Label(inner, text=label, bg=color, fg="white",
             font=(FONT_FAMILY, 9)).pack(anchor="w")
    return outer


def primary_button(parent, text, command):
    return ttk.Button(parent, text=text, command=command, style="Accent.TButton")
