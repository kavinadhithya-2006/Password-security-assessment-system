"""
neumorphic.py

A small toolkit of hand-drawn "neumorphic" (soft UI) widgets for tkinter.
Native tkinter/ttk widgets cannot draw soft drop-shadows or fully rounded
corners, so these widgets draw everything on a Canvas: a light shadow on
the top-left edge and a darker shadow on the bottom-right edge of a
rounded rectangle, which is what gives neumorphism its soft, embossed
"pressed into the background" look.

Palette is a classic light neumorphic scheme:
    background : #E5E9F0  (soft blue-grey)
    light edge : #FFFFFF
    dark edge  : #B7BEC9
    accent     : #5B6EF5  (indigo)
    text       : #2E3A59  (dark navy)
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Optional


BG = "#E5E9F0"
LIGHT = "#FFFFFF"
DARK = "#B9C1CE"
TEXT = "#2E3A59"
MUTED_TEXT = "#6B7690"
ACCENT = "#5B6EF5"
ACCENT_DARK = "#4557D6"


def _rounded_points(x1, y1, x2, y2, r):
    """Return a point list describing a rounded rectangle for create_polygon(smooth=True)."""
    r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
    return [
        x1 + r, y1,
        x2 - r, y1,
        x2, y1,
        x2, y1 + r,
        x2, y2 - r,
        x2, y2,
        x2 - r, y2,
        x1 + r, y2,
        x1, y2,
        x1, y2 - r,
        x1, y1 + r,
        x1, y1,
    ]


class NeuCard(tk.Canvas):
    """A raised, rounded 'card' panel with a soft drop shadow. Use .inner as the
    parent for any child widgets placed on top of the card."""

    def __init__(self, parent, width=300, height=120, radius=18, depth=6, bg=BG, **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg,
                          highlightthickness=0, bd=0, **kwargs)
        self.radius = radius
        self.depth = depth
        self.card_bg = bg
        self.bind("<Configure>", self._on_resize)
        self.inner = tk.Frame(self, bg=bg)
        self._draw()
        self._window = self.create_window(0, 0, window=self.inner, anchor="nw")

    def _on_resize(self, event):
        self.delete("shadow")
        self._draw(event.width, event.height)
        pad = self.depth + 6
        self.coords(self._window, pad, pad)
        self.inner.configure(width=max(event.width - 2 * pad, 1),
                              height=max(event.height - 2 * pad, 1))

    def _draw(self, w=None, h=None):
        w = w or int(self["width"])
        h = h or int(self["height"])
        d = self.depth
        r = self.radius
        # Dark shadow (bottom-right)
        pts_dark = _rounded_points(d, d, w - d + d * 0.4, h - d + d * 0.4, r)
        self.create_polygon(pts_dark, smooth=True, fill=DARK, outline="", tags="shadow")
        # Light shadow (top-left)
        pts_light = _rounded_points(0, 0, w - 2 * d, h - 2 * d, r)
        self.create_polygon(pts_light, smooth=True, fill=LIGHT, outline="", tags="shadow")
        # Main face
        pts_face = _rounded_points(d * 0.6, d * 0.6, w - d * 1.4, h - d * 1.4, r)
        self.create_polygon(pts_face, smooth=True, fill=self.card_bg, outline="", tags="shadow")


class NeuButton(tk.Canvas):
    """A soft, rounded button that appears to 'press in' when clicked."""

    def __init__(self, parent, text="Button", command: Optional[Callable] = None,
                 width=180, height=44, radius=16, bg=BG, accent=False,
                 font=("Segoe UI", 10, "bold"), state="normal", **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg,
                          highlightthickness=0, bd=0, **kwargs)
        self.command = command
        self.radius = radius
        self.bg_color = bg
        self.text = text
        self.font = font
        self.accent = accent
        self._pressed = False
        self._state = state
        self._btn_w, self._btn_h = width, height

        self.bind("<Configure>", lambda e: self._render())
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self._hover = False
        self._render()

    def configure_state(self, state: str):
        self._state = state
        self._render()

    def _on_enter(self, _e):
        if self._state != "disabled":
            self._hover = True
            self._render()

    def _on_leave(self, _e):
        self._hover = False
        self._pressed = False
        self._render()

    def _on_press(self, _e):
        if self._state == "disabled":
            return
        self._pressed = True
        self._render()

    def _on_release(self, _e):
        if self._state == "disabled":
            return
        was_pressed = self._pressed
        self._pressed = False
        self._render()
        if was_pressed and self.command:
            self.command()

    def _render(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 1:
            w = self._btn_w
        if h <= 1:
            h = self._btn_h
        w, h = max(w, 10), max(h, 10)
        r = self.radius
        d = 4

        face_color = self.bg_color
        text_color = TEXT
        if self.accent:
            face_color = ACCENT_DARK if self._pressed else ACCENT
            text_color = "#FFFFFF"
        if self._state == "disabled":
            face_color = "#D4D9E2"
            text_color = MUTED_TEXT

        if self._pressed and self._state != "disabled":
            # Inset (pressed) look: dark shadow top-left, light bottom-right (inverted)
            pts_dark = _rounded_points(0, 0, w - d, h - d, r)
            self.create_polygon(pts_dark, smooth=True, fill=DARK if not self.accent else ACCENT_DARK, outline="")
            pts_light = _rounded_points(d, d, w, h, r)
            self.create_polygon(pts_light, smooth=True, fill=LIGHT if not self.accent else ACCENT, outline="")
            pts_face = _rounded_points(d * 0.6, d * 0.6, w - d * 0.6, h - d * 0.6, r)
            self.create_polygon(pts_face, smooth=True, fill=face_color, outline="")
        else:
            # Raised look
            pts_light = _rounded_points(0, 0, w - d, h - d, r)
            self.create_polygon(pts_light, smooth=True, fill=LIGHT if not self.accent else ACCENT, outline="")
            pts_dark = _rounded_points(d, d, w, h, r)
            self.create_polygon(pts_dark, smooth=True, fill=DARK if not self.accent else ACCENT_DARK, outline="")
            pts_face = _rounded_points(d * 0.6, d * 0.6, w - d * 0.6, h - d * 0.6, r)
            self.create_polygon(pts_face, smooth=True, fill=face_color, outline="")

        cursor = "hand2" if self._state != "disabled" else "arrow"
        self.configure(cursor=cursor)
        self.create_text(w / 2, h / 2, text=self.text, fill=text_color, font=self.font)


class NeuEntryWell(tk.Canvas):
    """An inset ('pressed in') rounded well that holds a real tk.Entry so it
    looks like a debossed neumorphic input field."""

    def __init__(self, parent, textvariable=None, width=300, height=40, radius=14,
                 bg=BG, show="", font=("Segoe UI", 10), **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg,
                          highlightthickness=0, bd=0, **kwargs)
        self.bg_color = bg
        self.radius = radius
        self.bind("<Configure>", self._on_resize)
        self.entry = tk.Entry(self, textvariable=textvariable, show=show, font=font,
                               bd=0, highlightthickness=0, bg=bg, fg=TEXT,
                               insertbackground=TEXT, relief="flat")
        self._entry_window = None
        self._render()

    def _on_resize(self, event):
        self._render(event.width, event.height)

    def _render(self, w=None, h=None):
        w = w or int(self["width"])
        h = h or int(self["height"])
        self.delete("shape")
        r = self.radius
        d = 3
        # Inset shadow: dark on top-left, light on bottom-right
        pts_dark = _rounded_points(0, 0, w - d, h - d, r)
        self.create_polygon(pts_dark, smooth=True, fill=DARK, outline="", tags="shape")
        pts_light = _rounded_points(d, d, w, h, r)
        self.create_polygon(pts_light, smooth=True, fill=LIGHT, outline="", tags="shape")
        pts_face = _rounded_points(d * 0.8, d * 0.8, w - d * 0.8, h - d * 0.8, r)
        self.create_polygon(pts_face, smooth=True, fill=self.bg_color, outline="", tags="shape")

        if self._entry_window is None:
            self._entry_window = self.create_window(
                d * 2, h / 2, window=self.entry, anchor="w", width=max(w - d * 5, 10),
            )
        else:
            self.coords(self._entry_window, d * 2, h / 2)
            self.itemconfigure(self._entry_window, width=max(w - d * 5, 10))
        # Ensure the shapes stay behind the embedded entry widget.
        self.tag_lower("shape")


class NeuBadge(tk.Canvas):
    """A soft rounded pill used for status/risk banners with a solid fill color."""

    def __init__(self, parent, text="", fill=ACCENT, text_color="#FFFFFF",
                 width=400, height=48, radius=22, font=("Segoe UI", 12, "bold"), **kwargs):
        super().__init__(parent, width=width, height=height, bg=BG,
                          highlightthickness=0, bd=0, **kwargs)
        self.font = font
        self._text = text
        self._fill = fill
        self._text_color = text_color
        self._fallback_w, self._fallback_h = width, height
        self.bind("<Configure>", lambda e: self._render())
        self._render()

    def set_text(self, text: str, fill: str, text_color: str = "#FFFFFF"):
        self._text = text
        self._fill = fill
        self._text_color = text_color
        self._render()

    def _render(self):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        if w <= 1:
            w = self._fallback_w
        if h <= 1:
            h = self._fallback_h
        pts = _rounded_points(2, 2, w - 2, h - 2, h / 2)
        self.create_polygon(pts, smooth=True, fill=self._fill, outline="")
        self.create_text(w / 2, h / 2, text=self._text, fill=self._text_color, font=self.font)
