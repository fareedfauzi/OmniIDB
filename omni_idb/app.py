"""Aesthetic Tkinter GUI for OmniIDB (stdlib only, no third-party dependencies).

Designed to match the dark modern cybersecurity workbench aesthetic with
curved buttons, compact checkmark checkboxes, JetBrains Mono typography,
dual IDB preservation, REAI report deliverables, and auto-failover provider controls.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

from . import reporting, runner
from .config import (
    CLI_PROVIDERS,
    KEYLESS_PROVIDERS,
    PROVIDERS,
    AppSettings,
    cache_path,
    default_models_for_provider,
    detect_engine_root,
    detect_ida,
    is_cli_provider,
    is_signed_in_provider,
    project_root,
    provider_defaults,
    runner_script,
)
from .discovery import Sample, SampleKind, discover, format_size
from .runner import OmniEvent, GenesectEvent, RunnerEvent, RunRequest

# ---------------------------------------------------------------- palette
# Dark modern slate-navy aesthetic matching the designer UI
BG = "#0B0F19"             # Window background (deep midnight slate)
CARD = "#121824"           # Card surface background
CARD_BORDER = "#1E293B"    # Card border outline
INPUT_BG = "#0B0F19"       # Recessed input fields
INPUT_BORDER = "#1E293B"   # Input border outline
CONSOLE_BG = "#0B0F19"     # Console / log background
BTN_BG = "#1A2232"         # Standard button surface
BTN_BORDER = "#2A374E"     # Standard button border
BTN_HOVER = "#243046"      # Standard button hover
BLUE = "#2563EB"           # Primary brand / action blue
BLUE_HOVER = "#1D4ED8"     # Action button hover
FG = "#F8FAFC"             # Crisp off-white text
MUTED = "#94A3B8"          # Secondary muted text
DIM = "#64748B"            # Dim hints / placeholders
SKY = "#38BDF8"            # Accent cyan for icons/highlights

# Semantic status pill colors
GREEN = "#4ADE80"
GREEN_BG = "#0E281E"
GREEN_BORDER = "#166534"

RED = "#FCA5A5"
RED_BG = "#2A141A"
RED_BORDER = "#7F1D1D"

AMBER = "#FBBF24"
AMBER_BG = "#2D1F0E"
AMBER_BORDER = "#78350F"

STATUS_COLORS = {
    "Complete": ("#0E281E", "#4ADE80"),
    "Failed": ("#2A141A", "#FCA5A5"),
}
RUNNING_COLORS = ("#162033", "#93C5FD")
IDLE_COLORS = ("#121824", "#94A3B8")

MAX_LOGS = 4000
MAX_IDA_LOGS = 10000

# ---------------------------------------------------------------- typography
def load_custom_font() -> bool:
    """Load local JetBrains Mono TTF font dynamically into Windows GDI session."""
    if sys.platform != "win32":
        return False
    search_dirs = [
        project_root(),
        Path.cwd(),
        Path(sys.executable).resolve().parent,
        Path(__file__).resolve().parent.parent,
    ]
    seen = set()
    loaded_any = False
    for d in search_dirs:
        try:
            d = d.resolve()
            if d in seen or not d.is_dir():
                continue
            seen.add(d)
            for ttf in d.glob("*[Jj]et[Bb]rains*.ttf"):
                import ctypes
                FR_PRIVATE = 0x10
                res = ctypes.windll.gdi32.AddFontResourceExW(str(ttf.resolve()), FR_PRIVATE, 0)
                if res > 0:
                    loaded_any = True
        except Exception:
            pass
    return loaded_any


_FONT_LOADED = load_custom_font()


def _detect_font_family(root: Optional[tk.Tk] = None) -> str:
    """Select the best available monospace font, prioritizing JetBrains Mono."""
    load_custom_font()
    try:
        import tkinter.font as tkfont
        available = set(tkfont.families(root))
        for cand in ("JetBrains Mono", "Cascadia Code", "Cascadia Mono", "Consolas", "Courier New"):
            if cand in available:
                return cand
    except Exception:
        pass
    return "JetBrains Mono"


FONT_FAMILY = "JetBrains Mono"

MONO = (FONT_FAMILY, 9)
UI_FONT = (FONT_FAMILY, 9)
UI_FONT_BOLD = (FONT_FAMILY, 9, "bold")
TITLE_FONT = (FONT_FAMILY, 10, "bold")
SUB_FONT = (FONT_FAMILY, 8)
HEADER_TITLE_FONT = (FONT_FAMILY, 15, "bold")
BUTTON_FONT = (FONT_FAMILY, 9, "bold")
SMALL_BTN_FONT = (FONT_FAMILY, 8, "bold")
BADGE_FONT = (FONT_FAMILY, 8, "bold")
CARD_ICON_FONT = (FONT_FAMILY, 16)


# ---------------------------------------------------------------- helpers
def _status_colors(status: str) -> tuple[str, str]:
    if status in STATUS_COLORS:
        return STATUS_COLORS[status]
    if status == "Opening in IDA" or status.startswith(("Renaming", "Processing", "Analyzing", "Running")):
        return RUNNING_COLORS
    return IDLE_COLORS


# ---------------------------------------------------------------- custom compact check icons
def create_check_icons() -> tuple[tk.PhotoImage, tk.PhotoImage]:
    """Render sleek checkmark icons with crisp white checkmark and generous gap to caption."""
    BOX_W = 14
    BOX_H = 14
    GAP = 8
    TOTAL_W = BOX_W + GAP

    img_un = tk.PhotoImage(width=TOTAL_W, height=BOX_H)
    img_ck = tk.PhotoImage(width=TOTAL_W, height=BOX_H)

    pixels_un = []
    pixels_ck = []

    check_coords = {
        (3, 7), (3, 8),
        (4, 8), (4, 9),
        (5, 9), (5, 10),
        (6, 8), (6, 9),
        (7, 7), (7, 8),
        (8, 6), (8, 7),
        (9, 5), (9, 6),
        (10, 4), (10, 5),
    }

    corners = {(0, 0), (BOX_W - 1, 0), (0, BOX_H - 1), (BOX_W - 1, BOX_H - 1)}

    for y in range(BOX_H):
        row_un = []
        row_ck = []
        for x in range(BOX_W):
            if (x, y) in corners:
                row_un.append(CARD)
                row_ck.append(CARD)
            elif x in (0, BOX_W - 1) or y in (0, BOX_H - 1):
                row_un.append(BTN_BORDER)
                row_ck.append("#3B82F6")
            else:
                row_un.append(INPUT_BG)
                if (x, y) in check_coords:
                    row_ck.append("#FFFFFF")
                else:
                    row_ck.append(BLUE)
        pixels_un.append(row_un)
        pixels_ck.append(row_ck)

    img_un.put(pixels_un, to=(0, 0, BOX_W, BOX_H))
    img_ck.put(pixels_ck, to=(0, 0, BOX_W, BOX_H))
    return img_un, img_ck


def create_radio_icons() -> tuple[tk.PhotoImage, tk.PhotoImage]:
    """Render sleek circular radio button icons with crisp dot and generous gap to caption."""
    BOX_W = 14
    BOX_H = 14
    GAP = 8
    TOTAL_W = BOX_W + GAP

    img_un = tk.PhotoImage(width=TOTAL_W, height=BOX_H)
    img_ck = tk.PhotoImage(width=TOTAL_W, height=BOX_H)

    pixels_un = []
    pixels_ck = []

    cx, cy = 6.5, 6.5
    r_outer_sq = 6.0**2
    r_inner_sq = 4.8**2
    r_dot_sq = 2.6**2

    for y in range(BOX_H):
        row_un = []
        row_ck = []
        for x in range(TOTAL_W):
            if x >= BOX_W:
                row_un.append(CARD)
                row_ck.append(CARD)
                continue
            d_sq = (x - cx) ** 2 + (y - cy) ** 2
            if d_sq > r_outer_sq:
                row_un.append(CARD)
                row_ck.append(CARD)
            elif d_sq >= r_inner_sq:
                row_un.append(BTN_BORDER)
                row_ck.append("#3B82F6")
            else:
                row_un.append(INPUT_BG)
                if d_sq <= r_dot_sq:
                    row_ck.append("#38BDF8")
                else:
                    row_ck.append(INPUT_BG)
        pixels_un.append(row_un)
        pixels_ck.append(row_ck)

    img_un.put(pixels_un, to=(0, 0, TOTAL_W, BOX_H))
    img_ck.put(pixels_ck, to=(0, 0, TOTAL_W, BOX_H))
    return img_un, img_ck


# ---------------------------------------------------------------- rounded button
class RoundedButton(tk.Canvas):
    """Button with curved edge corners, anti-aliased splines, and smooth interactive states."""

    def __init__(
        self,
        parent,
        text: str,
        command: Optional[Callable] = None,
        padx: int = 12,
        pady: int = 5,
        radius: int = 6,
        bg_color: str = CARD,
        fill: str = BTN_BG,
        hover_fill: str = BTN_HOVER,
        outline: str = BTN_BORDER,
        text_color: str = FG,
        font: Optional[tuple] = None,
        state: str = "normal",
        width: Optional[int] = None,
        height: Optional[int] = None,
    ):
        self.btn_font = font or BUTTON_FONT
        font_obj = tkfont.Font(font=self.btn_font)
        self.width = width or (font_obj.measure(text) + padx * 2)
        self.height = height or (font_obj.metrics("linespace") + pady * 2)
        super().__init__(
            parent,
            width=self.width,
            height=self.height,
            bg=bg_color,
            highlightthickness=0,
            cursor="hand2" if state == "normal" else "arrow",
        )
        self.command = command
        self.radius = radius
        self.bg_color = bg_color
        self.fill_color = fill
        self.hover_fill = hover_fill
        self.outline_color = outline
        self.text_color = text_color
        self.state = state
        self.text = text
        self._draw(self.fill_color)

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _draw(self, fill: str) -> None:
        self.delete("all")
        r = self.radius
        w, h = self.width, self.height
        pts = [
            r, 1,
            w - r, 1,
            w - 1, 1,
            w - 1, r,
            w - 1, h - r,
            w - 1, h - 1,
            w - r, h - 1,
            r, h - 1,
            1, h - 1,
            1, h - r,
            1, r,
            1, 1,
        ]
        is_disabled = self.state in ("disabled", tk.DISABLED)
        outline = "#1E293B" if is_disabled else self.outline_color
        bg = "#141A26" if is_disabled else fill
        fg = "#64748B" if is_disabled else self.text_color
        self.create_polygon(pts, smooth=True, fill=bg, outline=outline, width=1.2)
        self.create_text(w // 2, h // 2, text=self.text, fill=fg, font=self.btn_font)

    def set_text(self, text: str) -> None:
        self.text = text
        self._draw(self.fill_color)

    def configure_state(self, state: str) -> None:
        self.state = state
        self.configure(cursor="hand2" if state == "normal" else "arrow")
        self._draw(self.fill_color)

    def _on_enter(self, _e) -> None:
        if self.state == "normal":
            self._draw(self.hover_fill)

    def _on_leave(self, _e) -> None:
        if self.state == "normal":
            self._draw(self.fill_color)

    def _on_press(self, _e) -> None:
        if self.state == "normal":
            self._draw(self.fill_color)

    def _on_release(self, _e) -> None:
        if self.state == "normal":
            self._draw(self.hover_fill)
            if self.command:
                self.command()


# ---------------------------------------------------------------- tooltip
class ToolTip:
    """Subtle floating tooltip helper for (?) indicators."""

    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None) -> None:
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        frame = tk.Frame(tw, bg="#1E293B", highlightthickness=1, highlightbackground="#334155", padx=8, pady=5)
        frame.pack()
        label = tk.Label(frame, text=self.text, bg="#1E293B", fg="#F8FAFC", font=SUB_FONT, wraplength=280, justify="left")
        label.pack()

    def hide(self, _event=None) -> None:
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


def make_help_badge(parent, text: str) -> tk.Label:
    badge = tk.Label(parent, text="?", bg=CARD, fg=DIM, font=(FONT_FAMILY, 8, "bold"), cursor="hand2")
    badge.tooltip = ToolTip(badge, text)
    return badge


# ---------------------------------------------------------------- widgets
class LogView(tk.Frame):
    """Read-only, auto-scrolling, colorised text console with JetBrains Mono."""

    def __init__(
        self,
        master,
        colorizer: Callable[[str], str],
        placeholder: str,
        on_clear: Optional[Callable[[], None]] = None,
        on_save: Optional[Callable[[], None]] = None,
    ):
        super().__init__(master, bg=CONSOLE_BG, highlightthickness=1, highlightbackground=CARD_BORDER)
        self._colorizer = colorizer
        self._placeholder = placeholder
        self.on_clear = on_clear
        self.on_save = on_save
        self.text = tk.Text(
            self, bg=CONSOLE_BG, fg="#CBD5E1", font=MONO, wrap="word", relief="flat", bd=0,
            padx=10, pady=8, state="disabled", insertbackground=FG, selectbackground="#1D4ED8",
        )
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview, style="Vertical.TScrollbar")
        self.text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        for name, color in (("ok", GREEN), ("err", RED), ("run", SKY), ("warn", AMBER), ("dim", DIM), ("norm", "#CBD5E1")):
            self.text.tag_configure(name, foreground=color)
        self.text.tag_configure("placeholder", foreground=DIM, font=(FONT_FAMILY, 9, "italic"))
        self._count = 0

        # Right-click context menu
        self.context_menu = tk.Menu(self, tearoff=0, bg=CARD, fg=FG, activebackground=BLUE, activeforeground="#FFFFFF", font=UI_FONT)
        self.context_menu.add_command(label="Copy", command=self._copy_selection_or_all)
        self.context_menu.add_command(label="Select All", command=self._select_all)
        self.context_menu.add_separator()
        if self.on_save:
            self.context_menu.add_command(label="Save to File...", command=self.on_save)
        if self.on_clear:
            self.context_menu.add_command(label="Clear", command=self.on_clear)

        self.text.bind("<Button-3>", self._on_right_click)
        self.text.bind("<Control-a>", self._select_all_event)
        self.text.bind("<Control-A>", self._select_all_event)
        self.clear()

    def _select_all_event(self, event=None) -> str:
        self._select_all()
        return "break"

    def _select_all(self) -> None:
        if self._count > 0:
            self.text.tag_add("sel", "1.0", "end")

    def _copy_selection_or_all(self) -> None:
        try:
            if self.text.tag_ranges("sel"):
                selected_text = self.text.get("sel.first", "sel.last")
            else:
                selected_text = self.text.get("1.0", "end-1c")
            if selected_text and selected_text != self._placeholder:
                self.clipboard_clear()
                self.clipboard_append(selected_text)
        except Exception:
            pass

    def _on_right_click(self, event) -> None:
        self.context_menu.post(event.x_root, event.y_root)

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", self._placeholder, "placeholder")
        self.text.configure(state="disabled")
        self._count = 0

    def trim_top(self, count: int) -> None:
        if count <= 0 or self._count == 0:
            return
        self.text.configure(state="normal")
        self.text.delete("1.0", f"{count + 1}.0")
        self._count = max(0, self._count - count)
        self.text.configure(state="disabled")

    def set_lines(self, lines: list[str]) -> None:
        self.clear()
        if lines:
            self.append(lines)

    def append(self, lines: list[str]) -> None:
        if not lines:
            return
        at_bottom = self._count == 0 or self.text.yview()[1] >= 0.95
        self.text.configure(state="normal")
        if self._count == 0:
            self.text.delete("1.0", "end")
        for line in lines:
            self.text.insert("end", line + "\n", self._colorizer(line))
        self._count += len(lines)
        self.text.configure(state="disabled")
        if at_bottom:
            self.text.see("end")


def activity_color(line: str) -> str:
    s = line.strip()
    if s.startswith("--- Batch"):
        if "0 failed" in s and ("Finished" in s or "succeeded" in s):
            return "ok"
        if "failed" in s and not (" 0 failed" in s or "0 failed," in s):
            return "err"
        return "dim"

    if s.startswith(("✓", "[+]")):
        return "ok"
    if s.startswith(("✗", "[-]")):
        return "err"
    if s.startswith(("▶", "[*]", "->", "=>")):
        return "run"
    if s.startswith(("⚠", "[!]")):
        return "warn"
    if s.startswith(("---", "===", "...")):
        return "dim"

    lower = s.lower()
    if any(k in lower for k in ("failover", "fallback")):
        return "warn"
    if any(k in lower for k in ("error:", "exception:", "failed:", "failure:", "could not")):
        return "err"
    if any(k in lower for k in ("succeeded", "success", "successfully", "completed successfully")):
        return "ok"
    if any(k in lower for k in ("opening in ida", "running in ida", "analyzing", "decompiling")):
        return "run"

    return "norm"


def ida_color(line: str) -> str:
    s = line.strip()
    if s.startswith(("---", "===", "###")):
        return "dim"
    lower = s.lower()
    if any(p in lower for p in ("fatal:", "error:", "exception:", "internal error", "failed to", "cannot open")):
        return "err"
    if any(p in lower for p in ("warning:", "caution:")):
        return "warn"
    if any(p in lower for p in ("successfully", "completed", "autoanalysis done")):
        return "ok"
    return "norm"


SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")


class QueueView(tk.Frame):
    """Sample table with status badges, MD5 hashes, animated spinners, and an aesthetic empty state."""

    def __init__(
        self,
        master,
        compact: bool = False,
        on_open_output: Optional[Callable[[str], None]] = None,
        on_open_report: Optional[Callable[[str, str], None]] = None,
        on_open_location: Optional[Callable[[str], None]] = None,
        on_copy_path: Optional[Callable[[str], None]] = None,
        on_copy_md5: Optional[Callable[[str], None]] = None,
        on_remove_sample: Optional[Callable[[str], None]] = None,
        on_sort: Optional[Callable[[str], None]] = None,
        is_running_fn: Optional[Callable[[], bool]] = None,
    ):
        super().__init__(master, bg=CONSOLE_BG)
        self.compact = compact
        self.on_open_output = on_open_output
        self.on_open_report = on_open_report
        self.on_open_location = on_open_location
        self.on_copy_path = on_copy_path
        self.on_copy_md5 = on_copy_md5
        self.on_remove_sample = on_remove_sample
        self.on_sort = on_sort
        self.is_running_fn = is_running_fn
        self.spinner_index = 0
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        cols = (
            ("n", "name", "md5", "status", "time_spent")
            if compact
            else ("n", "name", "md5", "status", "time_spent", "type", "size")
        )
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse", style="Omni.Treeview")
        self.orig_heads = {
            "n": ("#", 42, 36),
            "name": ("Sample Name", 300, 160),
            "md5": ("MD5 Hash", 240, 140),
            "status": ("Status", 240, 140),
            "time_spent": ("Time Spent", 100, 80),
            "type": ("Type", 110, 80),
            "size": ("Size", 85, 65),
        }
        for col in cols:
            title, width, minw = self.orig_heads[col]
            self.tree.heading(col, text=title, command=lambda c=col: self._on_heading_click(c))
            self.tree.column(col, width=width, minwidth=minw, anchor="w", stretch=(col == "name"))
        for tag, (bg, fg) in {
            "done": STATUS_COLORS["Complete"],
            "fail": STATUS_COLORS["Failed"],
            "run": RUNNING_COLORS,
            "skip": (AMBER_BG, AMBER),
        }.items():
            self.tree.tag_configure(tag, background=bg, foreground=fg)

        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        xscroll = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview, style="Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        # Double-click and keyboard shortcuts
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>", self._on_double_click)
        self.tree.bind("<Delete>", self._on_delete_key)
        self.tree.bind("<Control-c>", self._on_copy_path_key)
        self.tree.bind("<Control-C>", self._on_copy_path_key)

        # Right-click context menu
        self.context_menu = tk.Menu(self, tearoff=0, bg=CARD, fg=FG, activebackground=BLUE, activeforeground="#FFFFFF", font=UI_FONT)
        self.context_menu.add_command(label="Open Output Folder", command=self._open_selected_folder)
        self.context_menu.add_command(label="Open HTML Report", command=self._open_selected_report_html)
        self.context_menu.add_command(label="Open PDF Report", command=self._open_selected_report_pdf)
        self.context_menu.add_command(label="Open File Location", command=self._open_selected_location)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy Sample Path", command=self._copy_selected_path)
        self.context_menu.add_command(label="Copy MD5 Hash", command=self._copy_selected_md5)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Remove from Queue", command=self._remove_selected)
        self.tree.bind("<Button-3>", self._on_right_click)

        # Empty state canvas & label
        self.empty_frame = tk.Frame(self, bg=CONSOLE_BG)
        self.empty_icon = tk.Canvas(self.empty_frame, width=48, height=44, bg=CONSOLE_BG, highlightthickness=0)
        self.empty_icon.pack(pady=(0, 6))
        self._draw_empty_icon(self.empty_icon)
        self.empty_label = tk.Label(
            self.empty_frame,
            text="No binary samples loaded in queue.\nSelect a binary sample or directory above and click 'Run OmniIDB' to populate queue.",
            bg=CONSOLE_BG,
            fg=DIM,
            font=UI_FONT,
            justify="center",
        )
        self.empty_label.pack()

    def _on_heading_click(self, col: str) -> None:
        if self.on_sort:
            self.on_sort(col)

    def update_sort_indicators(self, active_col: Optional[str], desc: bool) -> None:
        for col, (title, _, _) in self.orig_heads.items():
            if col not in self.tree["columns"]:
                continue
            if col == active_col:
                arrow = " ▼" if desc else " ▲"
                self.tree.heading(col, text=f"{title}{arrow}")
            else:
                self.tree.heading(col, text=title)

    def _on_double_click(self, event=None) -> None:
        if event and hasattr(event, "y"):
            region = self.tree.identify_region(event.x, event.y)
            if region not in ("cell", "tree"):
                return
            row_id = self.tree.identify_row(event.y)
        else:
            sel = self.tree.selection()
            row_id = sel[0] if sel else None
        if row_id and self.on_open_output:
            self.on_open_output(row_id)

    def _on_right_click(self, event) -> None:
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            is_running = self.is_running_fn() if self.is_running_fn else False
            remove_state = "disabled" if is_running else "normal"
            try:
                self.context_menu.entryconfigure("Remove from Queue", state=remove_state)
            except Exception:
                pass
            self.context_menu.post(event.x_root, event.y_root)

    def _open_selected_folder(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_open_output:
            self.on_open_output(sel[0])

    def _open_selected_report_html(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_open_report:
            self.on_open_report(sel[0], "html")

    def _open_selected_report_pdf(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_open_report:
            self.on_open_report(sel[0], "pdf")

    def _open_selected_location(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_open_location:
            self.on_open_location(sel[0])

    def _copy_selected_path(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_copy_path:
            self.on_copy_path(sel[0])

    def _copy_selected_md5(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_copy_md5:
            self.on_copy_md5(sel[0])

    def _remove_selected(self) -> None:
        sel = self.tree.selection()
        if sel and self.on_remove_sample:
            self.on_remove_sample(sel[0])

    def _on_delete_key(self, event=None) -> None:
        self._remove_selected()

    def _on_copy_path_key(self, event=None) -> None:
        self._copy_selected_path()

    @staticmethod
    def _draw_empty_icon(canvas: tk.Canvas) -> None:
        canvas.delete("all")
        # Draw sleek tray/inbox vector icon
        canvas.create_polygon(8, 12, 40, 12, 34, 34, 14, 34, fill="#121824", outline="#2A374E", width=1.5)
        canvas.create_line(14, 24, 20, 24, fill="#38BDF8", width=1.5)
        canvas.create_line(28, 24, 34, 24, fill="#38BDF8", width=1.5)
        canvas.create_arc(20, 18, 28, 26, start=180, extent=180, style="arc", outline="#38BDF8", width=1.5)

    def refresh(self, rows: list[tuple[int, Sample]], empty_message: Optional[str]) -> None:
        if empty_message:
            self.tree.delete(*self.tree.get_children())
            self.empty_label.configure(text=empty_message)
            self.empty_frame.place(relx=0.5, rely=0.45, anchor="center")
            return
        self.empty_frame.place_forget()

        spinner_char = SPINNER_FRAMES[self.spinner_index % len(SPINNER_FRAMES)]
        target_iids = [str(index) for index, _ in rows]
        target_set = set(target_iids)
        current_children = self.tree.get_children()

        prev_selection = self.tree.selection()

        if list(current_children) != target_iids:
            self.tree.delete(*self.tree.get_children())
            for index, sample in rows:
                tag = (
                    "done" if sample.is_complete()
                    else "fail" if sample.is_failed()
                    else "skip" if sample.is_skipped()
                    else "run" if sample.is_running()
                    else ""
                )
                raw_stage = (
                    sample.stage
                    if sample.is_running() and sample.stage and sample.stage != "-"
                    else sample.status
                )
                display_status = f"{spinner_char}  {raw_stage}" if sample.is_running() else raw_stage
                sample_md5 = getattr(sample, "md5", "") or "--"
                values = [
                    index + 1,
                    sample.path.name or str(sample.path),
                    sample_md5,
                    display_status,
                    sample.time_spent(),
                ]
                if not self.compact:
                    values += [sample.kind.label, format_size(sample.size)]
                self.tree.insert("", "end", iid=str(index), values=values, tags=(tag,))
        else:
            for index, sample in rows:
                tag = (
                    "done" if sample.is_complete()
                    else "fail" if sample.is_failed()
                    else "skip" if sample.is_skipped()
                    else "run" if sample.is_running()
                    else ""
                )
                raw_stage = (
                    sample.stage
                    if sample.is_running() and sample.stage and sample.stage != "-"
                    else sample.status
                )
                display_status = f"{spinner_char}  {raw_stage}" if sample.is_running() else raw_stage
                sample_md5 = getattr(sample, "md5", "") or "--"
                values = [
                    index + 1,
                    sample.path.name or str(sample.path),
                    sample_md5,
                    display_status,
                    sample.time_spent(),
                ]
                if not self.compact:
                    values += [sample.kind.label, format_size(sample.size)]
                self.tree.item(str(index), values=values, tags=(tag,))

        if prev_selection:
            valid_sel = [s for s in prev_selection if s in target_set]
            if valid_sel:
                try:
                    self.tree.selection_set(valid_sel)
                except Exception:
                    pass



class ScrollableColumn(tk.Frame):
    """Vertical scrollable column for configuration cards with mousewheel support."""

    def __init__(self, parent, bg: str = BG, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)

        self._window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self._on_scroll)

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel, add="+")

    def _on_inner_configure(self, event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._update_scrollbar()

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self._window_id, width=event.width)
        self._update_scrollbar()

    def _update_scrollbar(self):
        bbox = self.canvas.bbox("all")
        if bbox and (bbox[3] - bbox[1]) > (self.canvas.winfo_height() + 4) and self.canvas.winfo_height() > 50:
            if not self.scrollbar.winfo_ismapped():
                self.scrollbar.pack(side="right", fill="y")
        else:
            if self.scrollbar.winfo_ismapped():
                self.scrollbar.pack_forget()

    def _on_scroll(self, *args):
        self.scrollbar.set(*args)

    def _on_mousewheel(self, event):
        try:
            x, y = self.winfo_pointerxy()
            wx = self.winfo_rootx()
            wy = self.winfo_rooty()
            ww = self.winfo_width()
            wh = self.winfo_height()
            if wx <= x <= wx + ww and wy <= y <= wy + wh:
                bbox = self.canvas.bbox("all")
                if bbox and (bbox[3] - bbox[1]) > self.canvas.winfo_height():
                    self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except Exception:
            pass


def card(master, **grid) -> tk.Frame:
    """Create a card container with 1px outline."""
    frame = tk.Frame(master, bg=CARD, highlightthickness=1, highlightbackground=CARD_BORDER, padx=14, pady=12)
    if grid:
        frame.grid(**grid)
    return frame


def card_header(parent: tk.Frame, icon_char: str, title: str, subtitle: str) -> tk.Frame:
    """Header row with icon, title, and subtitle."""
    h = tk.Frame(parent, bg=CARD)
    h.pack(fill="x", pady=(0, 6))
    icon_lbl = tk.Label(h, text=icon_char, bg=CARD, fg=SKY, font=CARD_ICON_FONT)
    icon_lbl.pack(side="left", padx=(0, 10))
    text_frame = tk.Frame(h, bg=CARD)
    text_frame.pack(side="left", fill="x", expand=True)
    tk.Label(text_frame, text=title, bg=CARD, fg=FG, font=TITLE_FONT).pack(anchor="w")
    tk.Label(text_frame, text=subtitle, bg=CARD, fg=DIM, font=SUB_FONT).pack(anchor="w")
    return h


def apply_theme(root: tk.Tk) -> None:
    global FONT_FAMILY, MONO, UI_FONT, UI_FONT_BOLD, TITLE_FONT, SUB_FONT, HEADER_TITLE_FONT, BUTTON_FONT, SMALL_BTN_FONT, BADGE_FONT, CARD_ICON_FONT
    FONT_FAMILY = _detect_font_family(root)
    MONO = (FONT_FAMILY, 9)
    UI_FONT = (FONT_FAMILY, 9)
    UI_FONT_BOLD = (FONT_FAMILY, 9, "bold")
    TITLE_FONT = (FONT_FAMILY, 10, "bold")
    SUB_FONT = (FONT_FAMILY, 8)
    HEADER_TITLE_FONT = (FONT_FAMILY, 15, "bold")
    BUTTON_FONT = (FONT_FAMILY, 9, "bold")
    SMALL_BTN_FONT = (FONT_FAMILY, 8, "bold")
    BADGE_FONT = (FONT_FAMILY, 8, "bold")
    CARD_ICON_FONT = (FONT_FAMILY, 16)

    # Configure Tk core named fonts so all native & ttk elements use JetBrains Mono
    try:
        import tkinter.font as tkfont
        for name in ("TkDefaultFont", "TkTextFont", "TkFixedFont", "TkMenuFont"):
            tkfont.nametofont(name).configure(family=FONT_FAMILY, size=9)
        tkfont.nametofont("TkHeadingFont").configure(family=FONT_FAMILY, size=10, weight="bold")
        tkfont.nametofont("TkCaptionFont").configure(family=FONT_FAMILY, size=8)
        tkfont.nametofont("TkSmallCaptionFont").configure(family=FONT_FAMILY, size=8)
    except Exception:
        pass

    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(bg=BG)

    # Setup authentic compact 13x13 checkmark and radio icons
    un_img, ck_img = create_check_icons()
    root._check_un_img = un_img
    root._check_ck_img = ck_img

    run_img, rck_img = create_radio_icons()
    root._radio_un_img = run_img
    root._radio_ck_img = rck_img

    style.element_create("Checkmark.indicator", "image", ck_img, ("!selected", un_img))
    style.layout(
        "TCheckbutton",
        [
            (
                "Checkbutton.padding",
                {
                    "sticky": "nswe",
                    "children": [
                        ("Checkmark.indicator", {"side": "left", "sticky": ""}),
                        (
                            "Checkbutton.focus",
                            {
                                "side": "left",
                                "sticky": "w",
                                "children": [("Checkbutton.label", {"sticky": "nswe"})],
                            },
                        ),
                    ],
                },
            )
        ],
    )

    style.element_create("Radioindicator.image", "image", rck_img, ("!selected", run_img))
    style.layout(
        "TRadiobutton",
        [
            (
                "Radiobutton.padding",
                {
                    "sticky": "nswe",
                    "children": [
                        ("Radioindicator.image", {"side": "left", "sticky": ""}),
                        (
                            "Radiobutton.focus",
                            {
                                "side": "left",
                                "sticky": "w",
                                "children": [("Radiobutton.label", {"sticky": "nswe"})],
                            },
                        ),
                    ],
                },
            )
        ],
    )

    # General widget styling with JetBrains Mono
    style.configure(".", background=CARD, foreground=FG, fieldbackground=INPUT_BG, font=UI_FONT, bordercolor=CARD_BORDER)
    style.configure("TFrame", background=CARD)
    style.configure("TLabel", background=CARD, foreground=FG, font=UI_FONT)
    style.configure("TCheckbutton", background=CARD, foreground=FG, font=UI_FONT, focuscolor=CARD, padding=(0, 1))
    style.map("TCheckbutton", background=[("active", CARD)], foreground=[("active", "#FFFFFF")])
    style.configure("TRadiobutton", background=CARD, foreground=FG, font=UI_FONT, focuscolor=CARD, padding=(0, 1))
    style.map(
        "TRadiobutton",
        background=[("active", CARD)],
        foreground=[("disabled", "#64748B"), ("active", "#FFFFFF")],
    )

    # Inputs with dark inset background and crisp borders
    style.configure("TEntry", fieldbackground=INPUT_BG, foreground=FG, insertcolor=FG, bordercolor=INPUT_BORDER, font=UI_FONT, padding=(8, 4))
    style.configure("TCombobox", fieldbackground=INPUT_BG, background=INPUT_BG, foreground=FG, arrowcolor=FG, bordercolor=INPUT_BORDER, font=UI_FONT, padding=3)
    style.map("TCombobox", fieldbackground=[("readonly", INPUT_BG)], foreground=[("readonly", FG)])
    style.configure("TSpinbox", fieldbackground=INPUT_BG, foreground=FG, arrowcolor=FG, bordercolor=INPUT_BORDER, font=UI_FONT)

    # Progress bar and Scrollbar
    style.configure("Horizontal.TProgressbar", troughcolor=BG, background=BLUE, bordercolor=CARD_BORDER, thickness=6)
    style.configure("Vertical.TScrollbar", background=BTN_BG, troughcolor=CONSOLE_BG, arrowcolor=MUTED, bordercolor=CONSOLE_BG)
    style.configure("Horizontal.TScrollbar", background=BTN_BG, troughcolor=CONSOLE_BG, arrowcolor=MUTED, bordercolor=CONSOLE_BG)

    # Treeview (Sample queue) with JetBrains Mono
    style.configure("Omni.Treeview", background=CONSOLE_BG, fieldbackground=CONSOLE_BG, foreground=FG, font=UI_FONT, rowheight=24, borderwidth=0)
    style.configure("Omni.Treeview.Heading", background=CARD, foreground=MUTED, font=(FONT_FAMILY, 8, "bold"), relief="flat", borderwidth=0)
    style.map("Omni.Treeview", background=[("selected", "#1D4ED8")])

    root.option_add("*TCombobox*Listbox.background", INPUT_BG)
    root.option_add("*TCombobox*Listbox.foreground", FG)
    root.option_add("*TCombobox*Listbox.font", UI_FONT)
    root.option_add("*TCombobox*Listbox.selectBackground", BLUE)
    root.option_add("*TCombobox*Listbox.selectForeground", "#FFFFFF")


# ---------------------------------------------------------------- app
class OmniApp:
    TABS = ("Queue", "Log", "IdaLog")

    def __init__(self, root: tk.Tk, initial_path: Optional[str] = None):
        self.root = root
        root.title("OmniIDB — Autonomous Bulk AI Reverse Engineering & IDB Enrichment for IDA Pro")
        root.geometry("1260x880")
        root.minsize(1020, 680)
        try:
            root.state("zoomed")
        except Exception:
            try:
                root.attributes("-zoomed", True)
            except Exception:
                pass
        apply_theme(root)

        self.app_icon = None
        self.header_logo = None
        self._load_app_logos()

        self.settings = AppSettings.load()
        # Automatically ensure genesect_root resolves to project root or IDA plugins (hidden from UI)
        if not self.settings.genesect_root.strip() or not runner_script(self.settings.genesect_root).is_file():
            auto_root = detect_engine_root() or project_root()
            self.settings.genesect_root = str(auto_root)

        if initial_path:
            self.settings.input_path = initial_path
            self.settings.infer_output_root()

        self.events: "queue.Queue[RunnerEvent]" = queue.Queue()
        self.samples: list[Sample] = []
        self.rejected = []
        self.logs: list[str] = []
        self.ida_logs: list[str] = []
        self.cancel: Optional[threading.Event] = None
        self.running = self.auth_running = self.test_running = False
        self.progress_current = self.progress_total = 0
        self.console_tab = "Queue"
        self.queue_dirty = True
        self._last_time_tick = 0.0

        self._build_vars()
        self._build_ui()
        self._update_analyze_workspace_state()
        self._bind_provider_visibility()
        if self.settings.input_path.strip():
            if not Path(self.settings.input_path.strip()).exists():
                self.settings.input_path = ""
                self.v_input.set("")
            else:
                self.refresh_samples()
        self.show_tab("Queue")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._poll)

    def _load_app_logos(self) -> None:
        logo_path = project_root() / "omni-IDB-logo.png"
        if not logo_path.is_file():
            candidate = Path.cwd() / "omni-IDB-logo.png"
            if candidate.is_file():
                logo_path = candidate
        if logo_path.is_file():
            try:
                self.app_icon = tk.PhotoImage(file=str(logo_path))
                self.root.iconphoto(True, self.app_icon)
            except Exception:
                pass
            try:
                from PIL import Image, ImageTk
                pil_img = Image.open(str(logo_path)).convert("RGBA")
                pil_img = pil_img.resize((26, 26), Image.Resampling.LANCZOS)
                self.header_logo = ImageTk.PhotoImage(pil_img)
            except Exception:
                try:
                    if self.app_icon:
                        sub = max(1, self.app_icon.width() // 26)
                        self.header_logo = self.app_icon.subsample(sub, sub)
                except Exception:
                    self.header_logo = None

    # ------------------------------------------------------------ state
    def _build_vars(self) -> None:
        s = self.settings
        from .go_support import resolve_goresym
        self.v_input = tk.StringVar(value=s.input_path)
        self.v_output = tk.StringVar(value=s.output_root)
        ida_cand = s.ida_path if (s.ida_path and Path(s.ida_path).is_file()) else str(detect_ida() or s.ida_path or "")
        self.v_ida = tk.StringVar(value=ida_cand)
        go_path = s.goresym_path if (s.goresym_path and "_MEI" not in s.goresym_path and Path(s.goresym_path).is_file()) else resolve_goresym()
        self.v_goresym = tk.StringVar(value=go_path)
        self.v_provider = tk.StringVar(value=s.provider)
        self.v_url = tk.StringVar(value=s.api_url)
        self.v_key = tk.StringVar()
        self.v_model = tk.StringVar(value=s.model)
        self.v_exe = tk.StringVar(value=s.executable)
        # By default uncheck Enable Fallback Provider
        self.v_fallback_enabled = tk.BooleanVar(value=False)
        self.testing_target = "main"
        self.v_fallback_provider = tk.StringVar(value=s.fallback_provider)
        self.v_fallback_url = tk.StringVar(value=s.fallback_api_url)
        self.v_fallback_key = tk.StringVar()
        self.v_fallback_model = tk.StringVar(value=s.fallback_model)
        self.v_fallback_exe = tk.StringVar(value=s.fallback_executable)
        self.v_rename_fn = tk.BooleanVar(value=s.rename_functions)
        self.v_rename_fn_addr = tk.BooleanVar(value=getattr(s, "rename_functions_with_address", False))
        self.v_rename_var = tk.BooleanVar(value=s.rename_variables)
        self.v_workspace = tk.BooleanVar(value=s.generate_workspace)
        # By default make AI investigation and reporting "None"
        self.v_report_mode = tk.StringVar(value="none")
        self.v_agent = tk.BooleanVar(value=False)
        self.v_analyze_workspace = tk.BooleanVar(value=False)
        self.v_dotnet_mode = tk.StringVar(value=getattr(s, "dotnet_mode", "skip") or "skip")
        self.v_turns = tk.IntVar(value=s.investigation_turns)
        self.v_recursive = tk.BooleanVar(value=s.recursive)
        self.v_batch = tk.IntVar(value=s.batch_size)
        self.v_workers = tk.IntVar(value=getattr(s, "workers", 3))
        self.v_low_score_rescan = tk.BooleanVar(value=getattr(s, "low_score_rescan", False))
        self.v_cache = tk.BooleanVar(value=s.use_rename_cache)
        self.v_token_budget = tk.IntVar(value=s.token_budget)
        self.v_filter = tk.StringVar()
        self.v_status_filter = tk.StringVar(value="All")
        self.v_queued = tk.StringVar(value="0 sample(s) queued")
        self.sort_col: Optional[str] = None
        self.sort_desc: bool = False
        for var in (self.v_filter, self.v_status_filter):
            var.trace_add("write", lambda *_: self._mark_queue())

    def _pull_settings(self) -> None:
        """Copy widget values back into ``self.settings``."""
        s = self.settings
        s.input_path = self.v_input.get().strip().strip("\"'")
        s.output_root = self.v_output.get().strip().strip("\"'")
        s.ida_path = self.v_ida.get().strip().strip("\"'")
        s.goresym_path = self.v_goresym.get().strip().strip("\"'")
        if not s.genesect_root:
            s.genesect_root = str(detect_engine_root() or project_root())
        s.provider = self.v_provider.get()
        s.api_url = self.v_url.get()
        s.model = self.v_model.get()
        s.executable = self.v_exe.get()
        s.fallback_enabled = self.v_fallback_enabled.get()
        s.fallback_provider = self.v_fallback_provider.get()
        s.fallback_api_url = self.v_fallback_url.get()
        s.fallback_model = self.v_fallback_model.get()
        s.fallback_executable = self.v_fallback_exe.get()
        s.rename_functions = self.v_rename_fn.get()
        s.rename_functions_with_address = self.v_rename_fn_addr.get()
        s.rename_variables = self.v_rename_var.get()
        s.use_rename_cache = self.v_cache.get()
        s.generate_workspace = self.v_workspace.get()
        mode = self.v_report_mode.get()
        s.autonomous_investigation = (mode == "investigate")
        s.analyze_workspace = (
            mode == "workspace_analysis"
            and self.v_workspace.get()
        )
        s.dotnet_mode = self.v_dotnet_mode.get()
        s.recursive = self.v_recursive.get()
        try:
            s.investigation_turns = max(3, min(30, int(self.v_turns.get())))
            s.batch_size = max(1, min(50, int(self.v_batch.get())))
            s.workers = max(1, min(8, int(self.v_workers.get())))
            s.low_score_rescan = self.v_low_score_rescan.get()
            s.token_budget = max(0, int(self.v_token_budget.get()))
        except (tk.TclError, ValueError):
            pass

    # ------------------------------------------------------------ UI build
    def _build_ui(self) -> None:
        root = self.root
        outer = tk.Frame(root, bg=BG, padx=14, pady=10)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=1)

        # 1. Top Header Bar (Clean, JetBrains Mono, no logo, no settings/help)
        header = tk.Frame(outer, bg=BG)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        title_box = tk.Frame(header, bg=BG)
        title_box.pack(anchor="w")
        if getattr(self, "header_logo", None):
            tk.Label(title_box, image=self.header_logo, bg=BG).pack(side="left", padx=(0, 8))
        tk.Label(title_box, text="OmniIDB", bg=BG, fg=FG, font=HEADER_TITLE_FONT).pack(side="left")
        v_badge = tk.Label(
            title_box, text="v1.0.0", bg="#161E2E", fg=MUTED, font=BADGE_FONT,
            highlightthickness=1, highlightbackground=CARD_BORDER, padx=6, pady=1,
        )
        v_badge.pack(side="left", padx=(8, 0))

        # Subtitle
        tk.Label(
            header, text="Autonomous Bulk AI Reverse Engineering & IDB Enrichment for IDA Pro",
            bg=BG, fg=DIM, font=SUB_FONT,
        ).pack(anchor="w", pady=(2, 0))

        # 2. Target Sample / Directory Card (Full width at top)
        target = card(outer, row=1, column=0, sticky="ew", pady=(0, 8))
        target.columnconfigure(0, weight=1)
        card_header(target, "📁", "Target Sample / Directory", "Select a binary sample or directory to analyze")

        r1 = tk.Frame(target, bg=CARD)
        r1.pack(fill="x", pady=(2, 6))
        r1.columnconfigure(0, weight=1)
        entry_input = ttk.Entry(r1, textvariable=self.v_input)
        entry_input.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        entry_input.bind("<Return>", lambda _e: self.refresh_samples())
        entry_input.bind("<FocusOut>", lambda _e: self.refresh_samples())

        # Curved Edge Buttons: Browse & Add Samples
        RoundedButton(r1, "📁 Browse...", command=self.choose_input_file, bg_color=CARD, radius=6, padx=10, pady=4).grid(row=0, column=1, padx=(0, 6))
        RoundedButton(r1, "➕ Add Samples...", command=self.choose_input_folder, bg_color=CARD, radius=6, padx=10, pady=4).grid(row=0, column=2)

        # Row 2 options: Recursive
        r2 = tk.Frame(target, bg=CARD)
        r2.pack(fill="x")
        ttk.Checkbutton(
            r2, text="Scan subfolders recursively", variable=self.v_recursive, command=self.refresh_samples,
        ).pack(side="left")

        # 3. Main Body Split Pane: Left = Configurations, Right = Run Bar + Long Queue/Log Table
        body_pane = tk.Frame(outer, bg=BG)
        body_pane.grid(row=2, column=0, sticky="nsew", pady=(0, 0))
        body_pane.columnconfigure((0, 1), weight=1, uniform="body_pane")
        body_pane.rowconfigure(0, weight=1)

        # ------------------------------------------------ Left Settings Column
        left_col = ScrollableColumn(body_pane)
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left_inner = left_col.inner

        # Card A: AI Engine Configuration
        ai_card = card(left_inner)
        ai_card.pack(fill="x", pady=(0, 10))
        card_header(ai_card, "🤖", "AI Engine Configuration", "Configure the AI provider and authentication")

        grid = tk.Frame(ai_card, bg=CARD)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        self.ai_rows: dict[str, tuple[tk.Widget, tk.Widget]] = {}

        def add_row(key: str, label: str, widget_factory) -> None:
            lab = tk.Label(grid, text=label, bg=CARD, fg=MUTED, font=SUB_FONT, anchor="w")
            widget = widget_factory(grid)
            self.ai_rows[key] = (lab, widget)

        add_row("provider", "Provider:", lambda p: ttk.Combobox(p, textvariable=self.v_provider, values=PROVIDERS, state="readonly", width=22))

        def make_cli_box(p):
            f = tk.Frame(p, bg=CARD)
            f.columnconfigure(0, weight=1)
            ttk.Entry(f, textvariable=self.v_exe).grid(row=0, column=0, sticky="ew", padx=(0, 6))
            RoundedButton(f, "Browse...", command=lambda: self._pick_file(self.v_exe), bg_color=CARD, padx=8, pady=3, radius=6).grid(row=0, column=1)
            return f

        add_row("exe", "CLI Binary:", make_cli_box)
        add_row("signin", "Sign-in:", lambda p: tk.Frame(p, bg=CARD))
        add_row("url", "API URL:", lambda p: ttk.Entry(p, textvariable=self.v_url))
        add_row("key", "API Key:", lambda p: ttk.Entry(p, textvariable=self.v_key, show="•"))

        def make_model_box(p):
            self.model_box = ttk.Combobox(p, textvariable=self.v_model, values=default_models_for_provider(self.v_provider.get()))
            return self.model_box

        add_row("model", "Model:", make_model_box)
        self.ai_rows["provider"][1].bind("<<ComboboxSelected>>", lambda _e: self._provider_changed())

        # Fallback provider configuration (auto-switch on error / token)
        self.fb_frame = tk.Frame(ai_card, bg=CARD)
        self.fb_frame.pack(fill="x", pady=(6, 2))
        ttk.Checkbutton(
            self.fb_frame,
            text="Enable Fallback Provider (auto-failover on token/error)",
            variable=self.v_fallback_enabled,
            command=self._fallback_toggled,
        ).pack(anchor="w")

        self.fb_body = tk.Frame(ai_card, bg=CARD)
        self.fb_body.columnconfigure(1, weight=1)
        self.fb_rows: dict[str, tuple[tk.Widget, tk.Widget]] = {}

        def add_fb_row(key: str, label: str, widget_factory) -> None:
            lab = tk.Label(self.fb_body, text=label, bg=CARD, fg=MUTED, font=SUB_FONT, anchor="w")
            widget = widget_factory(self.fb_body)
            self.fb_rows[key] = (lab, widget)

        def make_fb_exe_box(p):
            f = tk.Frame(p, bg=CARD)
            f.columnconfigure(0, weight=1)
            ttk.Entry(f, textvariable=self.v_fallback_exe).grid(row=0, column=0, sticky="ew", padx=(0, 6))
            RoundedButton(f, "Browse...", command=lambda: self._pick_file(self.v_fallback_exe, title="Select Fallback CLI Binary"), bg_color=CARD, padx=8, pady=3, radius=6).grid(row=0, column=1)
            return f

        add_fb_row("provider", "Fallback:", lambda p: ttk.Combobox(p, textvariable=self.v_fallback_provider, values=PROVIDERS, state="readonly", width=22))
        add_fb_row("exe", "CLI Binary:", make_fb_exe_box)
        add_fb_row("signin", "Sign-in:", lambda p: tk.Frame(p, bg=CARD))
        add_fb_row("url", "API URL:", lambda p: ttk.Entry(p, textvariable=self.v_fallback_url))
        add_fb_row("key", "API Key:", lambda p: ttk.Entry(p, textvariable=self.v_fallback_key, show="•"))

        def make_fb_model_box(p):
            self.fb_model_box = ttk.Combobox(p, textvariable=self.v_fallback_model, values=default_models_for_provider(self.v_fallback_provider.get()))
            return self.fb_model_box

        add_fb_row("model", "Model:", make_fb_model_box)
        self.fb_rows["provider"][1].bind("<<ComboboxSelected>>", lambda _e: self._fallback_provider_changed())

        self.ai_separator = ttk.Separator(ai_card)
        self.ai_separator.pack(fill="x", pady=(8, 8))

        # Bottom test connection action row & result pill badge
        self.trow = tk.Frame(ai_card, bg=CARD)
        self.trow.pack(fill="x")
        self.trow.columnconfigure(1, weight=1)

        self.test_btn = RoundedButton(
            self.trow, "⚡  Test Connection", command=lambda: self.start_test_connection("main"),
            fill=BLUE, hover_fill=BLUE_HOVER, outline="#3B82F6", text_color="#FFFFFF",
            font=BUTTON_FONT, padx=12, pady=4, radius=6, bg_color=CARD,
        )
        self.test_btn.grid(row=0, column=0, sticky="w")

        self.test_fb_btn = RoundedButton(
            self.trow, "⚡  Test Fallback", command=lambda: self.start_test_connection("fallback"),
            fill="#4F46E5", hover_fill="#4338CA", outline="#6366F1", text_color="#FFFFFF",
            font=BUTTON_FONT, padx=12, pady=4, radius=6, bg_color=CARD,
        )

        self.test_badge = tk.Frame(self.trow, bg=CARD, highlightthickness=0)
        self.test_badge.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        self.test_badge_lbl = tk.Label(
            self.test_badge, text="", bg=CARD, fg=MUTED, font=UI_FONT, anchor="w", padx=8, pady=3,
        )
        self.test_badge_lbl.pack(fill="x")

        # Card B: Analysis Operations
        ops_card = card(left_inner)
        ops_card.pack(fill="x", pady=(0, 10))
        ops_top = card_header(ops_card, "⚙", "Analysis Operations", "Select the analysis tasks to perform")

        self.select_all_btn = RoundedButton(
            ops_top, "Select All", command=self.toggle_select_all_ops,
            bg_color=CARD, font=SMALL_BTN_FONT, padx=8, pady=2, radius=6,
        )
        self.select_all_btn.place(relx=1.0, rely=0.2, anchor="ne")

        ops_list = tk.Frame(ops_card, bg=CARD)
        ops_list.pack(fill="x", pady=(2, 6))

        def add_op(text: str, var: tk.BooleanVar, help_text: str, cmd=None) -> tk.Frame:
            row = tk.Frame(ops_list, bg=CARD)
            row.pack(fill="x", pady=2)
            chk = ttk.Checkbutton(row, text=text, variable=var, command=cmd)
            chk.pack(side="left")
            make_help_badge(row, help_text).pack(side="left", padx=6)
            return row

        def _update_select_all_btn() -> None:
            all_on = all([self.v_rename_fn.get(), self.v_rename_var.get(), self.v_workspace.get()])
            self.select_all_btn.set_text("Deselect All" if all_on else "Select All")

        def _on_op_change() -> None:
            self._update_rename_fn_state()
            _update_select_all_btn()

        def _on_ws_change() -> None:
            self._workspace_toggled()
            _update_select_all_btn()

        add_op(
            "Rename sub_* functions (semantic naming)", self.v_rename_fn,
            "Runs dependency-aware bottom-up bulk function renamer across unnamed subroutines.",
            _on_op_change,
        )
        self.chk_fn_addr_row = tk.Frame(ops_list, bg=CARD)
        self.chk_fn_addr_row.pack(fill="x", pady=(0, 2), padx=(22, 0))
        self.chk_fn_addr = ttk.Checkbutton(
            self.chk_fn_addr_row,
            text="Append address suffix to function names (e.g. sub_100 → copyfile_100)",
            variable=self.v_rename_fn_addr,
        )
        self.chk_fn_addr.pack(side="left")
        make_help_badge(
            self.chk_fn_addr_row,
            "Preserves the function's unique address in its new name while applying AI semantic naming (<suggestedname_address>).",
        ).pack(side="left", padx=6)

        add_op(
            "Rename local variables & parameters", self.v_rename_var,
            "Runs Hex-Rays local variable renamer on decompiled functions.",
            _on_op_change,
        )
        self.ws_row = add_op(
            "Export OmniIDB AI workspace & context pack", self.v_workspace,
            "Produces offline AI workspace (decompiled code, disassembly, call graphs, strings, imports).",
            _on_ws_change,
        )
        self._update_rename_fn_state()
        _update_select_all_btn()

        # AI Investigation & Reporting (Mutually exclusive reporting workflow)
        ttk.Separator(ops_card).pack(fill="x", pady=(6, 8))

        rep_hdr = tk.Frame(ops_card, bg=CARD)
        rep_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(rep_hdr, text="🔍", bg=CARD, fg=SKY, font=CARD_ICON_FONT).pack(side="left", padx=(0, 10))
        rep_text = tk.Frame(rep_hdr, bg=CARD)
        rep_text.pack(side="left", fill="x", expand=True)
        tk.Label(rep_text, text="AI Investigation & Reporting", bg=CARD, fg=FG, font=TITLE_FONT).pack(anchor="w")
        tk.Label(rep_text, text="Select at most one deep-dive AI reporting workflow", bg=CARD, fg=DIM, font=SUB_FONT).pack(anchor="w")

        rep_list = tk.Frame(ops_card, bg=CARD)
        rep_list.pack(fill="x", pady=(2, 4))

        # 1. None
        r_none = tk.Frame(rep_list, bg=CARD)
        r_none.pack(fill="x", pady=2)
        ttk.Radiobutton(
            r_none,
            text="None (renaming & workspace export only, fastest)",
            variable=self.v_report_mode,
            value="none",
            command=self._report_mode_changed,
        ).pack(side="left")
        make_help_badge(
            r_none,
            "Fastest execution. Enriches the IDA database and exports context packs without generating an AI analysis report.",
        ).pack(side="left", padx=6)

        # 2. In-Database Agent Analysis
        r_agent = tk.Frame(rep_list, bg=CARD)
        r_agent.pack(fill="x", pady=2)
        ttk.Radiobutton(
            r_agent,
            text="In-Database Agent Analysis (Autonomous agent analysis inside IDA -> MD, HTML, PDF report)",
            variable=self.v_report_mode,
            value="investigate",
            command=self._report_mode_changed,
        ).pack(side="left")
        make_help_badge(
            r_agent,
            "Runs autonomous multi-turn agent analysis querying IDA APIs (decompilation, xrefs, hex bytes) to produce Markdown, HTML, and vector PDF reports.",
        ).pack(side="left", padx=6)

        self.turns_row = tk.Frame(rep_list, bg=CARD)
        tk.Label(self.turns_row, text="Investigation Turns:", bg=CARD, fg=MUTED, font=SUB_FONT).pack(side="left", padx=(20, 6))
        ttk.Spinbox(self.turns_row, from_=3, to=30, textvariable=self.v_turns, width=5).pack(side="left")
        tk.Label(self.turns_row, text="(3 to 30 turns)", bg=CARD, fg=DIM, font=SUB_FONT).pack(side="left", padx=6)
        if self.v_report_mode.get() == "investigate":
            self.turns_row.pack(fill="x", pady=(2, 4))

        # 3. Exported Workspace AI Analysis
        r_ws = tk.Frame(rep_list, bg=CARD)
        r_ws.pack(fill="x", pady=2)
        self.rb_ws_analysis = ttk.Radiobutton(
            r_ws,
            text="Exported Workspace AI Analysis (analyze exported native or .NET code -> MD, HTML, PDF report)",
            variable=self.v_report_mode,
            value="workspace_analysis",
            command=self._report_mode_changed,
        )
        self.rb_ws_analysis.pack(side="left")
        self.ws_analysis_badge = make_help_badge(
            r_ws,
            "CLI agents inspect files directly. ChatGPT Account and API providers analyze a bounded evidence bundle of exported source and catalogs.",
        )
        self.ws_analysis_badge.pack(side="left", padx=6)

        # .NET Assembly Handling Sub-section
        ttk.Separator(ops_card).pack(fill="x", pady=(6, 8))
        net_hdr = tk.Frame(ops_card, bg=CARD)
        net_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(net_hdr, text="⚙", bg=CARD, fg=SKY, font=CARD_ICON_FONT).pack(side="left", padx=(0, 10))
        net_text = tk.Frame(net_hdr, bg=CARD)
        net_text.pack(side="left", fill="x", expand=True)
        tk.Label(net_text, text=".NET Assembly Handling", bg=CARD, fg=FG, font=TITLE_FONT).pack(anchor="w")
        tk.Label(net_text, text="Behavior when target binary is a managed .NET executable or DLL", bg=CARD, fg=DIM, font=SUB_FONT).pack(anchor="w")

        net_list = tk.Frame(ops_card, bg=CARD)
        net_list.pack(fill="x", pady=(2, 4))

        # 1. Skip .NET Assemblies
        r_skip_net = tk.Frame(net_list, bg=CARD)
        r_skip_net.pack(fill="x", pady=2)
        ttk.Radiobutton(
            r_skip_net,
            text="Skip .NET Assemblies (native IDA Hex-Rays only)",
            variable=self.v_dotnet_mode,
            value="skip",
        ).pack(side="left")
        make_help_badge(
            r_skip_net,
            "Skips managed .NET executables. IDA Pro and Hex-Rays only target native x86/x64/ARM machine code.",
        ).pack(side="left", padx=6)

        # 2. Decompile & Export .NET AI Workspace
        r_dec_net = tk.Frame(net_list, bg=CARD)
        r_dec_net.pack(fill="x", pady=2)
        ttk.Radiobutton(
            r_dec_net,
            text="Decompile & Export .NET AI Workspace (extract CIL, types, strings & C#)",
            variable=self.v_dotnet_mode,
            value="decompile",
        ).pack(side="left")
        make_help_badge(
            r_dec_net,
            "Pure-Python CLR metadata parser extracts TypeDefs, MethodDefs, P/Invoke imports, user strings, and CIL module signatures for AI agent inspection without requiring IDA Pro.",
        ).pack(side="left", padx=6)

        # Output Directory Sub-section
        ttk.Separator(ops_card).pack(fill="x", pady=(6, 8))
        out_hdr = tk.Frame(ops_card, bg=CARD)
        out_hdr.pack(fill="x", pady=(0, 4))
        tk.Label(out_hdr, text="📁", bg=CARD, fg=SKY, font=CARD_ICON_FONT).pack(side="left", padx=(0, 10))
        out_text = tk.Frame(out_hdr, bg=CARD)
        out_text.pack(side="left", fill="x", expand=True)
        tk.Label(out_text, text="Output Directory", bg=CARD, fg=FG, font=TITLE_FONT).pack(anchor="w")
        tk.Label(out_text, text="Directory to store the analysis results", bg=CARD, fg=DIM, font=SUB_FONT).pack(anchor="w")

        orow = tk.Frame(ops_card, bg=CARD)
        orow.pack(fill="x", pady=(4, 0))
        orow.columnconfigure(0, weight=1)
        ttk.Entry(orow, textvariable=self.v_output).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        RoundedButton(orow, "📁 Browse...", command=lambda: self._pick_dir(self.v_output), bg_color=CARD, radius=6, padx=10, pady=4).grid(row=0, column=1)

        # Card C: Environment and Configuration
        ida_card = card(left_inner)
        ida_card.pack(fill="x", pady=(0, 0))
        card_header(ida_card, "🖥", "Environment & Configuration", "Configure IDA Pro executable and analysis engine settings")

        ida_grid = tk.Frame(ida_card, bg=CARD)
        ida_grid.pack(fill="x")
        ida_grid.columnconfigure(1, weight=1)

        # Row 1: IDA Executable + curved Browse button
        tk.Label(ida_grid, text="IDA Executable:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=0, column=0, pady=3, sticky="w")
        ttk.Entry(ida_grid, textvariable=self.v_ida).grid(row=0, column=1, sticky="ew", padx=(4, 6))
        RoundedButton(ida_grid, "Browse...", command=lambda: self._pick_file(self.v_ida, title="Select IDA Pro Executable"), bg_color=CARD, padx=8, pady=3, radius=6).grid(row=0, column=2)

        # Row 2: GoReSym Executable (for Go binaries)
        tk.Label(ida_grid, text="GoReSym Binary:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=1, column=0, pady=3, sticky="w")
        grow = tk.Frame(ida_grid, bg=CARD)
        grow.grid(row=1, column=1, sticky="ew", padx=(4, 6))
        grow.columnconfigure(0, weight=1)
        ttk.Entry(grow, textvariable=self.v_goresym).grid(row=0, column=0, sticky="ew")
        make_help_badge(
            grow,
            "Mandiant GoReSym CLI to recover original function names and types from stripped Go binaries.\n"
            "Automatically detects GoReSym.exe in project root, tools/ directory, or system PATH.\n"
            "Click 'Update' to auto-fetch or update to the latest official release from GitHub.",
        ).grid(row=0, column=1, padx=(6, 0))
        g_btns = tk.Frame(ida_grid, bg=CARD)
        g_btns.grid(row=1, column=2)
        RoundedButton(g_btns, "Browse...", command=lambda: self._pick_file(self.v_goresym, title="Select GoReSym Binary"), bg_color=CARD, padx=6, pady=3, radius=6).pack(side="left", padx=(0, 4))
        self.btn_goresym_update = RoundedButton(g_btns, "⬇ Update", command=self._on_update_goresym, bg_color=CARD, padx=6, pady=3, radius=6)
        self.btn_goresym_update.pack(side="left")

        # Row 3: AI Batch Size + Concurrency (Workers)
        tk.Label(ida_grid, text="AI Batch & Workers:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=2, column=0, pady=(6, 0), sticky="w")
        brow = tk.Frame(ida_grid, bg=CARD)
        brow.grid(row=2, column=1, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Spinbox(brow, from_=1, to=50, textvariable=self.v_batch, width=4).pack(side="left")
        make_help_badge(brow, "Number of functions grouped into each AI prompt (default 15). Larger batches significantly reduce API roundtrips.").pack(side="left", padx=(4, 8))
        tk.Label(brow, text="Workers:", bg=CARD, fg=FG, font=UI_FONT_BOLD).pack(side="left")
        ttk.Spinbox(brow, from_=1, to=8, textvariable=self.v_workers, width=3).pack(side="left", padx=(4, 0))
        make_help_badge(brow, "Parallel AI request worker threads (1-8, default 3). Pre-extracts functions on IDA main thread, queries AI concurrently across workers, then safely applies names back in IDA.").pack(side="left", padx=(4, 8))
        tk.Label(brow, text="threads", bg=CARD, fg=DIM, font=SUB_FONT).pack(side="left")

        # Row 4: Low-score Rescan
        tk.Label(ida_grid, text="Low-score Rescan:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=3, column=0, pady=(6, 0), sticky="w")
        lsrow = tk.Frame(ida_grid, bg=CARD)
        lsrow.grid(row=3, column=1, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(lsrow, text="Enable low-score rescan (slow, re-analyzes ≤50% scores individually)", variable=self.v_low_score_rescan).pack(side="left")
        make_help_badge(lsrow, "When unchecked (recommended), accepts wrapper names (wrap_*) to finish much faster. When checked, re-analyzes every low-scoring function one-by-one, which can be significantly slower.").pack(side="left", padx=6)

        # Row 5: Rename Cache
        tk.Label(ida_grid, text="Rename Cache:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=4, column=0, pady=(6, 0), sticky="w")
        crow = tk.Frame(ida_grid, bg=CARD)
        crow.grid(row=4, column=1, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(crow, text="Reuse function & variable names across samples", variable=self.v_cache).pack(side="left")
        make_help_badge(crow, "Cross-sample consensus cache: skips re-querying AI when identical or structurally matching decompiled code has already been analyzed.").pack(side="left", padx=6)
        RoundedButton(crow, "Clear Cache", command=self._on_clear_cache, bg_color=CARD, padx=6, pady=2, radius=4).pack(side="left", padx=(6, 6))
        self.cache_stats_lbl = tk.Label(crow, text=self._format_cache_stats(), bg=CARD, fg=DIM, font=SUB_FONT)
        self.cache_stats_lbl.pack(side="left")

        # Row 6: Token Budget
        tk.Label(ida_grid, text="Token Budget:", bg=CARD, fg=FG, font=UI_FONT_BOLD, width=15, anchor="w").grid(row=5, column=0, pady=(6, 0), sticky="w")
        trow = tk.Frame(ida_grid, bg=CARD)
        trow.grid(row=5, column=1, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Spinbox(trow, from_=0, to=10000000, increment=50000, textvariable=self.v_token_budget, width=10).pack(side="left")
        make_help_badge(trow, "Batch-wide token spending cap. 0 = unlimited. When exhausted, switches to free fallback or stops billable requests.").pack(side="left", padx=6)
        tk.Label(trow, text="Batch token cap (0 = unlimited)", bg=CARD, fg=DIM, font=SUB_FONT).pack(side="left")

        # ------------------------------------------------ Right Column: Action Bar + Long Table/Console
        right_frame = tk.Frame(body_pane, bg=BG)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)

        # 4. Top Action Bar: Run OmniIDB + Stop + Sample Count
        run_bar = tk.Frame(right_frame, bg=BG)
        run_bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        run_bar.columnconfigure(2, weight=1)

        self.run_btn = RoundedButton(
            run_bar, "▶  Run OmniIDB", command=self.on_run,
            fill=BLUE, hover_fill=BLUE_HOVER, outline="#3B82F6", text_color="#FFFFFF",
            font=BUTTON_FONT, padx=16, pady=6, radius=6, bg_color=BG,
        )
        self.run_btn.pack(side="left", padx=(0, 8))

        self.cancel_btn = RoundedButton(
            run_bar, "⏹  Stop", command=self.on_cancel,
            fill=BTN_BG, hover_fill=BTN_HOVER, outline=BTN_BORDER, text_color=FG,
            font=BUTTON_FONT, padx=14, pady=6, radius=6, state="disabled", bg_color=BG,
        )
        self.cancel_btn.pack(side="left")
        self.stop_btn = self.cancel_btn

        self.queue_counter_lbl = tk.Label(run_bar, textvariable=self.v_queued, bg=BG, fg=MUTED, font=UI_FONT)
        self.queue_counter_lbl.pack(side="right")

        # 5. Long Console Card (Sample Queue, Activity Log, ida.log - No Split View)
        console = card(right_frame, row=1, column=0, sticky="nsew")
        console.columnconfigure(0, weight=1)
        console.rowconfigure(1, weight=1)

        bar = tk.Frame(console, bg=CARD)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        bar.columnconfigure(1, weight=1)

        pills = tk.Frame(bar, bg="#0E131D", padx=3, pady=3, highlightthickness=1, highlightbackground=CARD_BORDER)
        pills.pack(side="left")
        self.tab_buttons: dict[str, tk.Button] = {}
        tab_labels = {
            "Queue": "Sample Queue",
            "Log": "Activity Log",
            "IdaLog": "ida.log",
        }
        for key in self.TABS:
            title_c = tab_labels[key]
            b = tk.Button(
                pills, text=f"{title_c} (0)", relief="flat", bd=0, font=SMALL_BTN_FONT,
                padx=10, pady=3, command=lambda k=key: self.show_tab(k), cursor="hand2",
                bg="#0E131D", fg=MUTED, activebackground=BLUE, activeforeground="#FFFFFF",
            )
            b.pack(side="left", padx=1)
            self.tab_buttons[key] = b

        self.controls = tk.Frame(bar, bg=CARD)
        self.controls.pack(side="right")

        body = tk.Frame(console, bg=CARD)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        self.pages: dict[str, tk.Frame] = {}
        for key in self.TABS:
            frame = tk.Frame(body, bg=CARD)
            frame.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = frame

        self.queue_full = QueueView(
            self.pages["Queue"],
            compact=False,
            on_open_output=self.open_sample_output_folder,
            on_open_report=self.open_sample_report,
            on_open_location=self.open_sample_location,
            on_copy_path=self.copy_sample_path,
            on_copy_md5=self.copy_sample_md5,
            on_remove_sample=self.remove_sample_by_id,
            on_sort=self._on_sort_column,
            is_running_fn=lambda: self.running,
        )
        self.queue_full.pack(fill="both", expand=True)
        self.log_view = LogView(
            self.pages["Log"],
            activity_color,
            "Activity log is empty. Click 'Run OmniIDB' to start analysis.",
            on_clear=self._clear_logs,
            on_save=lambda: self._save_log_to_file("Log"),
        )
        self.log_view.pack(fill="both", expand=True)
        self.ida_view = LogView(
            self.pages["IdaLog"],
            ida_color,
            "ida.log is empty. Live IDA Pro decompiler and loader output will stream here.",
            on_clear=self._clear_ida_logs,
            on_save=lambda: self._save_log_to_file("IdaLog"),
        )
        self.ida_view.pack(fill="both", expand=True)

        self._build_controls()
        self._update_tab_titles()

    def _build_controls(self) -> None:
        for child in self.controls.winfo_children():
            child.destroy()
        tab = self.console_tab
        c = self.controls

        # Curved Edge Red-accented Clear button
        clear_btn = RoundedButton(
            c, "Clear", command=self._on_clear_active_tab,
            fill="#2A141A", hover_fill="#3D1822", outline="#7F1D1D", text_color="#FCA5A5",
            font=SMALL_BTN_FONT, padx=8, pady=2, radius=6, bg_color=CARD,
        )
        clear_btn.pack(side="right", padx=(6, 0))

        if tab == "Log":
            RoundedButton(c, "Save...", command=lambda: self._save_log_to_file("Log"), bg_color=CARD, padx=8, pady=2, radius=6, font=SMALL_BTN_FONT).pack(side="right", padx=2)
            RoundedButton(c, "Copy", command=lambda: self._copy("\r\n".join(self.logs)), bg_color=CARD, padx=8, pady=2, radius=6, font=SMALL_BTN_FONT).pack(side="right", padx=2)
        if tab == "IdaLog":
            RoundedButton(c, "Save...", command=lambda: self._save_log_to_file("IdaLog"), bg_color=CARD, padx=8, pady=2, radius=6, font=SMALL_BTN_FONT).pack(side="right", padx=2)
            RoundedButton(c, "Copy", command=lambda: self._copy("\r\n".join(self.ida_logs)), bg_color=CARD, padx=8, pady=2, radius=6, font=SMALL_BTN_FONT).pack(side="right", padx=2)
        if tab == "Queue" and len(self.samples) >= 1:
            entry = ttk.Entry(c, textvariable=self.v_filter, width=14)
            entry.pack(side="right", padx=4)
            tk.Label(c, text="🔍 Filter:", bg=CARD, fg=MUTED, font=SUB_FONT).pack(side="right", padx=(4, 2))
            for label, key, color in self._sample_chips():
                active = self.v_status_filter.get() == key
                tk.Button(
                    c, text=label, relief="flat", bd=0, padx=6, pady=2, font=SMALL_BTN_FONT,
                    bg=color if active else BTN_BG, fg="#FFFFFF" if active else MUTED,
                    command=lambda k=key: self._toggle_status_filter(k), cursor="hand2",
                ).pack(side="right", padx=2)

    def _on_clear_active_tab(self) -> None:
        if self.console_tab == "Log":
            self._clear_logs()
        elif self.console_tab == "IdaLog":
            self._clear_ida_logs()
        elif self.console_tab == "Queue":
            if self.running:
                messagebox.showwarning(
                    "Cannot Clear Queue",
                    "Analysis is currently running. Stop analysis before clearing the queue.",
                    parent=self.root,
                )
                return
            if not self.samples:
                return
            if not messagebox.askyesno(
                "Clear Sample Queue",
                f"Remove all {len(self.samples)} sample(s) from the queue?",
                parent=self.root,
            ):
                return
            self.samples.clear()
            self.v_queued.set("0 sample(s) queued")
            self._mark_queue()
            self._build_controls()
            self._update_tab_titles()

    def _sample_chips(self):
        s = self.samples
        chips = []
        for key, label, color, pred in (
            ("Failed", "✗ Fail", "#7F1D1D", Sample.is_failed),
            ("Complete", "✓ Done", "#166534", Sample.is_complete),
            ("Skipped", "↷ Skip", "#78350F", Sample.is_skipped),
            ("Running", "⚡ Run", "#1E3A8A", Sample.is_running),
            ("Pending", "⏳ Ready", "#2A374E", Sample.is_pending),
        ):
            n = sum(1 for x in s if pred(x))
            if n:
                chips.append((f"{label}:{n}", key, color))
        chips.append((f"All:{len(s)}", "All", BTN_BG))
        return chips

    # ------------------------------------------------------------ actions
    def _update_rename_fn_state(self) -> None:
        if hasattr(self, "chk_fn_addr"):
            if self.v_rename_fn.get():
                self.chk_fn_addr.configure(state="normal")
            else:
                self.chk_fn_addr.configure(state="disabled")

    def toggle_select_all_ops(self) -> None:
        all_on = all([self.v_rename_fn.get(), self.v_rename_var.get(), self.v_workspace.get()])
        new_val = not all_on
        self.v_rename_fn.set(new_val)
        self.v_rename_var.set(new_val)
        self.v_workspace.set(new_val)
        self._update_rename_fn_state()
        self._workspace_toggled()
        self.select_all_btn.set_text("Deselect All" if new_val else "Select All")

    def _workspace_toggled(self) -> None:
        if not self.v_workspace.get():
            if self.v_report_mode.get() == "workspace_analysis":
                self.v_report_mode.set("none")
                self._report_mode_changed()
        self._update_analyze_workspace_state()

    def _report_mode_changed(self) -> None:
        mode = self.v_report_mode.get()
        self.v_agent.set(mode == "investigate")
        self.v_analyze_workspace.set(mode == "workspace_analysis")

        if mode == "investigate":
            self.turns_row.pack(fill="x", pady=(2, 4))
        else:
            self.turns_row.pack_forget()

        if mode == "workspace_analysis":
            if not self.v_workspace.get():
                self.v_workspace.set(True)
                self._workspace_toggled()

    def _update_analyze_workspace_state(self) -> None:
        if not hasattr(self, "rb_ws_analysis"):
            return
        provider = self.v_provider.get()
        direct = is_cli_provider(provider)
        self.rb_ws_analysis.configure(state="normal")
        if hasattr(self.ws_analysis_badge, "tooltip"):
            mode = "inspect the workspace directly" if direct else "analyze exported source and catalog evidence"
            self.ws_analysis_badge.tooltip.text = (
                f"{provider} will {mode} and generate Markdown, HTML, and PDF malware research reports. "
                "The configured fallback is used only if the primary fails. Selecting this mode automatically enables workspace export."
            )
        self.ws_analysis_badge.configure(fg=DIM)


    def _toggle_status_filter(self, key: str) -> None:
        self.v_status_filter.set("All" if self.v_status_filter.get() == key and key != "All" else key)
        self._build_controls()

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _clear_logs(self) -> None:
        self.logs.clear()
        self.log_view.clear()
        self._update_tab_titles()

    def _clear_ida_logs(self) -> None:
        self.ida_logs.clear()
        self.ida_view.clear()
        self._update_tab_titles()

    def _save_log_to_file(self, tab: str) -> None:
        lines = self.logs if tab == "Log" else self.ida_logs
        if not lines:
            messagebox.showinfo("Log Empty", f"The {tab} log is currently empty.", parent=self.root)
            return
        default_name = "activity.log" if tab == "Log" else "ida.log"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title=f"Save {tab} to File",
            initialfile=default_name,
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if path:
            try:
                Path(path).write_text("\n".join(lines), encoding="utf-8")
                self._add_logs([f"[+] Log saved to {path}"])
            except Exception as exc:
                messagebox.showerror("Save Error", f"Could not save log file:\n{exc}", parent=self.root)

    def open_sample_output_folder(self, item_id: str) -> None:
        """Open the target sample's output directory in File Explorer."""
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                sample = self.samples[idx]
                out_root = self.v_output.get().strip() or self.settings.output_root.strip()
                if not out_root:
                    messagebox.showinfo(
                        "No Output Directory",
                        "Please specify an output directory first.",
                        parent=self.root,
                    )
                    return
                from .runner import sanitize, sha256_file
                digest = sha256_file(sample.path)
                folder = f"{sanitize(sample.path.stem)}-{digest[:12]}"
                target = Path(out_root) / folder
                if not target.exists():
                    target.mkdir(parents=True, exist_ok=True)
                if sys.platform == "win32":
                    os.startfile(str(target))
                elif sys.platform == "darwin":
                    subprocess.run(["open", str(target)], check=False)
                else:
                    subprocess.run(["xdg-open", str(target)], check=False)
        except Exception as exc:
            messagebox.showerror("Error Opening Folder", f"Could not open output folder:\n{exc}", parent=self.root)

    def open_sample_report(self, item_id: str, fmt: str = "html") -> None:
        """Open the target sample's generated HTML or PDF report in the default system viewer."""
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                sample = self.samples[idx]
                out_root = self.v_output.get().strip() or self.settings.output_root.strip()
                if not out_root:
                    messagebox.showinfo("No Output Directory", "Please specify an output directory first.", parent=self.root)
                    return
                from .runner import sanitize, sha256_file
                digest = sha256_file(sample.path)
                folder = f"{sanitize(sample.path.stem)}-{digest[:12]}"
                target = Path(out_root) / folder
                report_dir = target / "report"
                ws_dir = target / "AI Workspace"

                ext = ".html" if fmt.lower() == "html" else ".pdf"
                candidates = [
                    report_dir / f"report{ext}",
                    report_dir / f"workspace_analysis{ext}",
                    ws_dir / f"malware_analysis_report{ext}",
                ]
                found = None
                for cand in candidates:
                    if cand.is_file():
                        found = cand
                        break
                if found:
                    if sys.platform == "win32":
                        os.startfile(str(found))
                    elif sys.platform == "darwin":
                        subprocess.run(["open", str(found)], check=False)
                    else:
                        subprocess.run(["xdg-open", str(found)], check=False)
                else:
                    messagebox.showinfo(
                        "Report Not Found",
                        f"No {fmt.upper()} report found for {sample.path.name} yet.\nRun the analysis with AI Investigation or Workspace Analysis enabled.",
                        parent=self.root,
                    )
        except Exception as exc:
            messagebox.showerror("Error Opening Report", f"Could not open report:\n{exc}", parent=self.root)

    def open_sample_location(self, item_id: str) -> None:
        """Open the sample's containing directory in File Explorer and select the file."""
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                sample = self.samples[idx]
                p = sample.path.resolve()
                if not p.exists():
                    messagebox.showinfo("Sample Not Found", f"File does not exist:\n{p}", parent=self.root)
                    return
                if sys.platform == "win32":
                    subprocess.run(["explorer.exe", f"/select,{str(p)}"], check=False)
                elif sys.platform == "darwin":
                    subprocess.run(["open", "-R", str(p)], check=False)
                else:
                    subprocess.run(["xdg-open", str(p.parent)], check=False)
        except Exception as exc:
            messagebox.showerror("Error Opening Location", f"Could not open location:\n{exc}", parent=self.root)

    def copy_sample_path(self, item_id: str) -> None:
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                self._copy(str(self.samples[idx].path))
        except Exception:
            pass

    def copy_sample_md5(self, item_id: str) -> None:
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                md5 = getattr(self.samples[idx], "md5", "") or ""
                if md5:
                    self._copy(md5)
        except Exception:
            pass

    def remove_sample_by_id(self, item_id: str) -> None:
        if self.running:
            messagebox.showwarning("Cannot Remove", "Cannot remove samples while analysis is running.", parent=self.root)
            return
        try:
            idx = int(item_id)
            if 0 <= idx < len(self.samples):
                removed = self.samples.pop(idx)
                self.v_queued.set(f"{len(self.samples)} sample(s) queued")
                self._mark_queue()
                self._build_controls()
                self._update_tab_titles()
                self._add_logs([f"[-] Removed from queue: {removed.path.name}"])
        except Exception as exc:
            messagebox.showerror("Error", f"Could not remove sample: {exc}", parent=self.root)

    def _on_sort_column(self, col: str) -> None:
        if self.sort_col == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col
            self.sort_desc = False
        self._mark_queue()
        if hasattr(self, "queue_full"):
            self.queue_full.update_sort_indicators(self.sort_col, self.sort_desc)

    def _agent_toggled(self) -> None:
        if self.v_agent.get():
            self.v_report_mode.set("investigate")
        elif self.v_report_mode.get() == "investigate":
            self.v_report_mode.set("none")
        self._report_mode_changed()

    def _pick_dir(self, var: tk.StringVar, title: str = "Select Directory") -> None:
        path = filedialog.askdirectory(title=title)
        if path:
            var.set(path)

    def _pick_file(self, var: tk.StringVar, title: str = "Select File", filetypes: tuple = (("Executable Files", "*.exe"), ("All Files", "*.*"))) -> None:
        path = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if path:
            var.set(path)

    def _format_cache_stats(self) -> str:
        try:
            from .rename_cache import cache_stats
            st = cache_stats(cache_path())
            if not st or (st.get("function_entries", 0) == 0 and st.get("variable_entries", 0) == 0):
                return "Cache is empty"
            size_kb = st.get("size_bytes", st.get("file_bytes", 0)) / 1024
            return f"{st.get('function_entries', 0)} fn, {st.get('variable_entries', 0)} var ({size_kb:.1f} KB, {st.get('total_hits', 0)} hits)"
        except Exception:
            return ""

    def _on_clear_cache(self) -> None:
        if messagebox.askyesno("Clear Rename Cache", "Clear all cached function and variable names?"):
            try:
                from .rename_cache import clear_cache_file
                clear_cache_file(cache_path())
                if hasattr(self, "cache_stats_lbl"):
                    self.cache_stats_lbl.config(text=self._format_cache_stats())
            except Exception as exc:
                messagebox.showerror("Cache Error", f"Could not clear cache: {exc}")

    def _on_update_goresym(self) -> None:
        """Download or update GoReSym binary from Mandiant's official GitHub releases."""
        if hasattr(self, "btn_goresym_update") and self.btn_goresym_update.state == "disabled":
            return

        # Visual feedback: disable button & show "⏳ Updating..."
        if hasattr(self, "btn_goresym_update"):
            self.btn_goresym_update.configure_state("disabled")
            self.btn_goresym_update.set_text("⏳ Updating...")

        # Switch to activity log tab and log action
        self.show_tab("Log")
        self._add_logs([
            "[*] Checking latest GoReSym release from Mandiant GitHub repository...",
            "[*] Platform asset detected: " + ("GoReSym-windows.zip" if sys.platform == "win32" else ("GoReSym-mac.zip" if sys.platform == "darwin" else "GoReSym-linux.zip")),
        ])

        def run_update():
            from .go_support import download_latest_goresym, resolve_goresym

            def on_progress(p_msg: str) -> None:
                self.root.after(0, lambda: self._add_logs([p_msg]))

            try:
                ok, msg = download_latest_goresym(on_progress=on_progress)
            except Exception as e:
                ok, msg = False, f"Unexpected error during download: {e}"

            def done():
                try:
                    if hasattr(self, "btn_goresym_update"):
                        self.btn_goresym_update.configure_state("normal")
                        self.btn_goresym_update.set_text("⬇ Update")

                    if ok:
                        new_path = resolve_goresym()
                        self.v_goresym.set(new_path)
                        self._pull_settings()
                        self._save_settings()
                        self._add_logs([
                            f"[+] {msg}",
                            f"[+] GoReSym binary active: {new_path}",
                        ])
                        messagebox.showinfo("GoReSym Updated", msg, parent=self.root)
                    else:
                        self._add_logs([f"[-] Error updating GoReSym: {msg}"])
                        messagebox.showwarning("GoReSym Update Failed", msg, parent=self.root)
                except Exception as ex:
                    self._add_logs([f"[-] Error in update callback: {ex}"])

            self.root.after(0, done)

        import threading
        threading.Thread(target=run_update, daemon=True).start()

    def choose_input_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Target Executable Sample or IDA Database",
            filetypes=[
                (
                    "Supported Targets (*.exe, *.dll, *.idb, *.i64, ...)",
                    "*.exe;*.dll;*.sys;*.drv;*.ocx;*.cpl;*.scr;*.exe_;*.idb;*.i64;*.elf;*.so;*.dylib",
                ),
                ("Windows Executables (*.exe, *.dll, *.sys, ...)", "*.exe;*.dll;*.sys;*.drv;*.ocx;*.cpl;*.scr;*.exe_"),
                ("IDA Pro Databases (*.idb, *.i64)", "*.idb;*.i64"),
                ("Linux & macOS Binaries (*.elf, *.so, *.dylib)", "*.elf;*.so;*.dylib"),
                ("All Files (*.*)", "*.*"),
            ],
        )
        if path:
            self._set_input(path)

    def choose_input_folder(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self._set_input(path)

    def _set_input(self, path: str) -> None:
        self.v_input.set(path)
        self._pull_settings()
        self.settings.infer_output_root()
        self.v_output.set(self.settings.output_root)
        self.refresh_samples()

    # ------------------------------------------------------------ provider UI
    def _bind_provider_visibility(self) -> None:
        self._provider_layout()
        self._fallback_toggled()

    def _provider_changed(self) -> None:
        self.settings.provider = self.v_provider.get()
        self.settings.apply_provider_defaults()
        self.v_url.set(self.settings.api_url)
        self.v_model.set(self.settings.model)
        self.v_exe.set(self.settings.executable)
        self.v_key.set("")
        self._set_test_pill(None, "")
        if hasattr(self, "model_box"):
            self.model_box["values"] = default_models_for_provider(self.v_provider.get())
        self._provider_layout()
        self._update_analyze_workspace_state()

    def _fallback_toggled(self) -> None:
        if self.v_fallback_enabled.get():
            self.fb_body.pack(fill="x", pady=(2, 4), before=self.ai_separator)
            self._fallback_layout()
            self.test_btn.set_text("⚡ Test Main")
            self.test_fb_btn.set_text("⚡ Test Fallback")
            self.test_fb_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
            self.test_badge.grid(row=0, column=2, sticky="ew", padx=(10, 0))
            self.trow.columnconfigure(1, weight=0)
            self.trow.columnconfigure(2, weight=1)
        else:
            self.fb_body.pack_forget()
            self.test_btn.set_text("⚡ Test Connection")
            self.test_fb_btn.grid_remove()
            self.test_badge.grid(row=0, column=1, sticky="ew", padx=(10, 0))
            self.trow.columnconfigure(1, weight=1)
            self.trow.columnconfigure(2, weight=0)
        self._update_analyze_workspace_state()

    def _fallback_provider_changed(self) -> None:
        self.settings.fallback_provider = self.v_fallback_provider.get()
        self.settings.apply_fallback_provider_defaults()
        self.v_fallback_url.set(self.settings.fallback_api_url)
        self.v_fallback_model.set(self.settings.fallback_model)
        self.v_fallback_exe.set(self.settings.fallback_executable)
        self.v_fallback_key.set("")
        if hasattr(self, "fb_model_box"):
            self.fb_model_box["values"] = default_models_for_provider(self.v_fallback_provider.get())
        self._fallback_layout()
        self._update_analyze_workspace_state()


    def _fallback_layout(self) -> None:
        if not self.v_fallback_enabled.get():
            return
        provider = self.v_fallback_provider.get()
        for lab, widget in self.fb_rows.values():
            lab.grid_forget()
            widget.grid_forget()
        signed = is_signed_in_provider(provider)
        keys = ["provider"]
        if signed:
            if provider != "ChatGPTAccount":
                keys.append("exe")
            keys.append("signin")
        else:
            keys += ["url", "key"]
        keys.append("model")
        for r, key in enumerate(keys):
            lab, widget = self.fb_rows[key]
            lab.grid(row=r, column=0, sticky="w", pady=2, padx=(0, 10))
            widget.grid(row=r, column=1, sticky="ew" if key != "provider" else "w", pady=2)
        if signed:
            self._build_signin(self.fb_rows["signin"][1], target="fallback")

    def _provider_layout(self) -> None:
        provider = self.v_provider.get()
        for lab, widget in self.ai_rows.values():
            lab.grid_forget()
            widget.grid_forget()
        signed = is_signed_in_provider(provider)
        keys = ["provider"]
        if signed:
            if provider != "ChatGPTAccount":
                keys.append("exe")
            keys.append("signin")
        else:
            keys += ["url", "key"]
        keys.append("model")
        for r, key in enumerate(keys):
            lab, widget = self.ai_rows[key]
            lab.grid(row=r, column=0, sticky="w", pady=2, padx=(0, 10))
            widget.grid(row=r, column=1, sticky="ew" if key != "provider" else "w", pady=2)
        if signed:
            self._build_signin(self.ai_rows["signin"][1], target="main")

    def _build_signin(self, holder: tk.Frame, target: str = "main") -> None:
        for child in holder.winfo_children():
            child.destroy()
        provider = self.v_fallback_provider.get() if target == "fallback" else self.v_provider.get()
        if provider == "ChatGPTAccount":
            btn = RoundedButton(
                holder, "↗ Continue with ChatGPT in Browser", command=self.start_chatgpt,
                bg_color=CARD, padx=10, pady=3, radius=6, font=SUB_FONT,
            )
            btn.pack(side="left")
            if self.auth_running:
                btn.configure_state("disabled")
        elif provider in ("ClaudeCode", "AntigravityCLI", "CopilotCLI"):
            name = "Claude" if provider == "ClaudeCode" else ("Copilot" if provider == "CopilotCLI" else "Antigravity")
            btn = RoundedButton(
                holder, f"↗ Open {name} sign-in terminal", command=lambda n=name, t=target: self._open_cli(n, ("auth",) if n == "Copilot" else (), target=t),
                bg_color=CARD, padx=10, pady=3, radius=6, font=SUB_FONT,
            )
            btn.pack(side="left")
        elif provider == "OpenCode":
            providers = runner.get_opencode_auth_status()
            signed = bool(providers)
            if providers is not None:
                text = f"✓ Signed in ({', '.join(providers)})" if signed else "auth.json present"
                tk.Label(holder, text=text, bg=CARD, fg=GREEN if signed else AMBER, font=UI_FONT_BOLD).pack(side="left", padx=(0, 8))
            btn = RoundedButton(
                holder, "Re-authenticate" if signed else "Sign in with OpenCode",
                command=lambda t=target: self._open_cli("OpenCode", ("auth", "login"), target=t),
                bg_color=CARD, padx=10, pady=3, radius=6, font=SUB_FONT,
            )
            btn.pack(side="left")

    def _open_cli(self, name: str, args: tuple[str, ...] = (), target: str = "main") -> None:
        try:
            exe_var = self.v_fallback_exe if target == "fallback" else self.v_exe
            exe = exe_var.get().strip()
            if not exe:
                if name == "Claude":
                    exe = "claude"
                elif name == "Copilot":
                    exe = "copilot"
                elif name == "OpenCode":
                    exe = "opencode"
                else:
                    exe = "agy"
            runner.open_cli_sign_in(exe, args)
            self._set_test_pill(None, f"Sign-in terminal opened for {name}.")
        except OSError as error:
            self._set_test_pill(False, str(error))

    def start_chatgpt(self) -> None:
        self.auth_running = True
        self._set_test_pill(None, "Opening ChatGPT sign-in in browser...")
        self._provider_layout()
        runner.start_chatgpt_auth(self._engine_root(), self.events, self.v_ida.get())

    def _engine_root(self) -> Path:
        text = self.settings.genesect_root.strip()
        return Path(text) if text else (detect_engine_root() or project_root())

    def _needs_key(self, provider: Optional[str] = None, key_val: Optional[str] = None) -> bool:
        p = provider if provider is not None else self.v_provider.get()
        k = key_val if key_val is not None else self.v_key.get()
        return not is_signed_in_provider(p) and p not in KEYLESS_PROVIDERS and not k.strip()

    def start_test_connection(self, target: str = "main") -> None:
        self.testing_target = target
        if target == "fallback":
            p = self.v_fallback_provider.get()
            if self._needs_key(p, self.v_fallback_key.get()):
                self._set_test_pill(False, f"Please enter an API key for fallback ({p}) first.")
                return
            self.test_running = True
            self.test_fb_btn.set_text("⏳ Testing...")
            self.test_btn.configure_state("disabled")
            self.test_fb_btn.configure_state("disabled")
            self._set_test_pill("testing", f"Probing fallback AI ({p})...")
            payload = {
                "provider": p,
                "api_url": self.v_fallback_url.get(),
                "api_key": self.v_fallback_key.get(),
                "model": self.v_fallback_model.get(),
                "executable": self.v_fallback_exe.get(),
                "target": "fallback",
            }
        else:
            p = self.v_provider.get()
            if self._needs_key(p, self.v_key.get()):
                self._set_test_pill(False, f"Please enter an API key for {p} first.")
                return
            self.test_running = True
            self.test_btn.set_text("⏳ Testing...")
            self.test_btn.configure_state("disabled")
            self.test_fb_btn.configure_state("disabled")
            self._set_test_pill("testing", f"Probing main AI ({p})...")
            payload = {
                "provider": p,
                "api_url": self.v_url.get(),
                "api_key": self.v_key.get(),
                "model": self.v_model.get(),
                "executable": self.v_exe.get(),
                "target": "main",
            }
        runner.start_test_connection(self._engine_root(), payload, self.events, self.v_ida.get())

    def _set_test_pill(self, state: Optional[bool | str], message: str) -> None:
        """Render the rounded pill badge seen in the mockup."""
        if state is None and not message:
            self.test_badge.configure(bg=CARD, highlightthickness=0)
            self.test_badge_lbl.configure(text="", bg=CARD, fg=MUTED)
            return

        if state is True:
            bg_c, border_c, fg_c, icon = GREEN_BG, GREEN_BORDER, GREEN, "✓ "
        elif state is False:
            bg_c, border_c, fg_c, icon = RED_BG, RED_BORDER, RED, "⚠ "
        else:
            bg_c, border_c, fg_c, icon = "#162033", "#2563EB", "#93C5FD", "⏳ "

        display_msg = message if len(message) <= 45 else message[:42] + "..."
        self.test_badge.configure(bg=bg_c, highlightthickness=1, highlightbackground=border_c)
        self.test_badge_lbl.configure(text=f"{icon}{display_msg}", bg=bg_c, fg=fg_c)

    def on_close(self) -> None:
        """Gracefully handle window close: save configuration and terminate cleanly."""
        try:
            self._pull_settings()
            self.settings.save()
        except Exception:
            pass
        if self.cancel:
            self.cancel.set()
        try:
            self.root.destroy()
        except Exception:
            pass

    # ------------------------------------------------------------ samples
    def refresh_samples(self) -> None:
        self._pull_settings()
        s = self.settings
        target_path = s.input_path.strip()
        if not target_path:
            self.samples, self.rejected = [], []
            self.v_queued.set("0 sample(s) queued")
            self._mark_queue()
            self._build_controls()
            self._update_tab_titles()
            return

        if not Path(target_path).exists():
            self.samples, self.rejected = [], []
            self.v_queued.set("0 sample(s) queued")
            self._mark_queue()
            self._build_controls()
            self._update_tab_titles()
            self._add_logs([f"Input path not found on disk: {target_path}"])
            return

        try:
            report = discover(target_path, s.recursive, s.output_root.strip() or None)
        except OSError as error:
            self.samples, self.rejected = [], []
            self._add_logs([f"Discovery error: {error}"])
        else:
            self.samples, self.rejected = report.samples, report.rejected
            new_lines = [f"Rejected {r.path}: {r.reason}" for r in self.rejected]
            self._add_logs(new_lines)

        self.v_queued.set(f"{len(self.samples)} sample(s) queued")
        self._mark_queue()
        self._build_controls()
        self._update_tab_titles()

    def _filtered_samples(self) -> list[tuple[int, Sample]]:
        needle = self.v_filter.get().strip().lower()
        mode = self.v_status_filter.get()
        preds = {
            "All": lambda s: True,
            "Pending": Sample.is_pending,
            "Running": Sample.is_running,
            "Complete": Sample.is_complete,
            "Failed": Sample.is_failed,
            "Skipped": Sample.is_skipped,
        }
        pred = preds.get(mode, preds["All"])

        def matches_needle(s: Sample) -> bool:
            if not needle:
                return True
            md5_val = (getattr(s, "md5", "") or "").lower()
            return (
                needle in s.path.name.lower()
                or needle in str(s.path).lower()
                or needle in md5_val
                or needle in s.kind.label.lower()
                or needle in s.status.lower()
                or needle in s.stage.lower()
            )

        rows = [(i, s) for i, s in enumerate(self.samples) if matches_needle(s) and pred(s)]
        if getattr(self, "sort_col", None):
            col = self.sort_col
            def sort_key(item: tuple[int, Sample]):
                idx, s = item
                if col == "n":
                    return idx
                if col == "name":
                    return s.path.name.lower()
                if col == "md5":
                    return (getattr(s, "md5", "") or "").lower()
                if col == "status":
                    return (s.status.lower(), s.stage.lower())
                if col == "time_spent":
                    return s.elapsed_seconds if s.elapsed_seconds is not None else -1
                if col == "type":
                    return s.kind.label.lower()
                if col == "size":
                    return s.size
                return idx
            rows.sort(key=sort_key, reverse=getattr(self, "sort_desc", False))
        return rows

    def _mark_queue(self) -> None:
        self.queue_dirty = True

    def _render_queue(self) -> None:
        rows = self._filtered_samples()
        if not self.samples:
            msg = "No binary samples loaded in queue.\nSelect a binary sample or directory above and click 'Run OmniIDB' to populate queue."
        elif not rows:
            msg = "No samples match the active filter."
        else:
            msg = None
        self.queue_full.refresh(rows, msg)

    # ------------------------------------------------------------ tab switching
    def show_tab(self, tab: str) -> None:
        self.console_tab = tab
        for key, page in self.pages.items():
            if key == tab:
                page.tkraise()
        for key, btn in self.tab_buttons.items():
            active = key == tab
            btn.configure(
                bg=BLUE if active else "#0E131D",
                fg="#FFFFFF" if active else MUTED,
            )
        self._build_controls()
        if tab == "Queue":
            self._render_queue()

    def _update_tab_titles(self) -> None:
        tab_names = {
            "Queue": f"Sample Queue ({len(self.samples)})",
            "Log": f"Activity Log ({len(self.logs)})",
            "IdaLog": f"ida.log ({len(self.ida_logs)})",
        }
        for key, title in tab_names.items():
            if key in self.tab_buttons:
                self.tab_buttons[key].configure(text=title)

    # ------------------------------------------------------------ batch run
    def on_run(self) -> None:
        try:
            if self.running:
                return
            self._pull_settings()
            if not self.samples and self.v_input.get().strip():
                self.refresh_samples()

            error = None
            needs_ida = any(sample.kind != SampleKind.DOTNET_ASSEMBLY for sample in self.samples)
            if not self.samples:
                error = "No samples discovered. Choose a sample file or directory."
            elif needs_ida and (not self.settings.ida_path.strip() or not Path(self.settings.ida_path).is_file()):
                error = f"IDA executable not found at '{self.settings.ida_path}'."
            elif not self.settings.output_root.strip():
                error = "Please specify an output directory."
            elif self._needs_key(self.v_provider.get(), self.v_key.get()):
                error = f"An API key is required for provider '{self.v_provider.get()}'."
            elif self.v_fallback_enabled.get() and self._needs_key(self.v_fallback_provider.get(), self.v_fallback_key.get()):
                error = f"An API key is required for fallback provider '{self.v_fallback_provider.get()}'."

            if error:
                messagebox.showerror("Cannot Start OmniIDB", error, parent=self.root)
                return

            try:
                self.settings.save()
            except OSError:
                pass

            for sample in self.samples:
                sample.status = "Ready"
                sample.stage = "-"
                sample.start_time = None
                sample.elapsed_seconds = None
            self.logs.clear()
            self.ida_logs.clear()
            self.log_view.clear()
            self.ida_view.clear()
            self.progress_current, self.progress_total = 0, len(self.samples)
            self.running = True
            self._last_time_tick = time.time()
            self._set_running_ui(True)
            if self.console_tab == "Queue":
                self.show_tab("Log")

            self.cancel = runner.start(
                RunRequest(
                    self.settings,
                    self.v_key.get(),
                    list(self.samples),
                    fallback_api_key=self.v_fallback_key.get(),
                ),
                self.events,
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            messagebox.showerror("Run Error", f"Failed to start OmniIDB run:\n\n{exc}", parent=self.root)

    def on_cancel(self) -> None:
        if self.cancel:
            self.cancel.set()
            self._add_logs(["⏹ Cancellation requested by user..."])

    def _set_running_ui(self, running: bool) -> None:
        self.run_btn.configure_state("disabled" if running else "normal")
        self.cancel_btn.configure_state("normal" if running else "disabled")

    # ------------------------------------------------------------ event pump
    def _add_logs(self, lines: list[str]) -> None:
        lines = [m for m in lines if m]
        if not lines:
            return
        self.logs.extend(lines)
        if len(self.logs) > MAX_LOGS:
            overflow = len(self.logs) - MAX_LOGS + 500
            del self.logs[:overflow]
            self.log_view.trim_top(overflow)
        self.log_view.append(lines)

    def _poll(self) -> None:
        new_logs: list[str] = []
        new_ida: list[str] = []
        try:
            while True:
                self._handle(self.events.get_nowait(), new_logs, new_ida)
        except queue.Empty:
            pass
        self._add_logs(new_logs)
        if new_ida:
            self.ida_logs.extend(new_ida)
            if len(self.ida_logs) > MAX_IDA_LOGS:
                overflow = len(self.ida_logs) - MAX_IDA_LOGS + 1000
                del self.ida_logs[:overflow]
                self.ida_view.trim_top(overflow)
            self.ida_view.append(new_ida)
        now = time.time()
        if self.running and (now - self._last_time_tick >= 0.15):
            self._last_time_tick = now
            if hasattr(self, "queue_full"):
                self.queue_full.spinner_index = (self.queue_full.spinner_index + 1) % len(SPINNER_FRAMES)
            self._mark_queue()
        if new_logs or new_ida or self.queue_dirty:
            self._update_tab_titles()
        if self.queue_dirty and self.console_tab == "Queue":
            self.queue_dirty = False
            self._render_queue()
        self.root.after(80, self._poll)


    def _handle(self, ev: RunnerEvent, new_logs: list[str], new_ida: list[str]) -> None:
        d, kind = ev.data, ev.kind
        if kind == "batch_started":
            self.progress_total = d["total"]
            new_logs.append(f"Starting batch of {d['total']} sample(s)...")
        elif kind == "sample_started":
            idx = d["index"]
            if 0 <= idx < len(self.samples):
                s = self.samples[idx]
                s.status = "Opening in IDA"
                s.stage = "Opening in IDA"
                s.start_time = time.time()
                s.elapsed_seconds = None
                self._mark_queue()
            new_logs.append(f"▶ {d['path']}")
        elif kind == "sample_stage":
            idx = d["index"]
            if 0 <= idx < len(self.samples):
                self.samples[idx].stage = d["stage"]
                self._mark_queue()
        elif kind == "sample_status":
            idx = d["index"]
            if 0 <= idx < len(self.samples):
                self.samples[idx].status = d["status"]
                self._mark_queue()
        elif kind == "progress":
            self.progress_current, self.progress_total = d["current"], d["total"]
        elif kind == "log":
            new_logs.append(d["message"])
        elif kind == "ida_log_line":
            new_ida.append(d["message"])
        elif kind in ("omni_event", "genesect_event"):
            pass
        elif kind == "provider_switch":
            src = d.get("provider_from") or "primary"
            dst = d.get("provider_to") or "fallback"
            new_logs.append(f"⚠ [PROVIDER FALLBACK] Switched from {src} to {dst}: {d.get('message', '')}")
            self._set_test_pill(False, f"Failover: {src} -> {dst}")
        elif kind == "sample_finished":
            idx = d["index"]
            if 0 <= idx < len(self.samples):
                s = self.samples[idx]
                if not s.is_skipped():
                    s.status = "Complete" if d["ok"] else "Failed"
                    s.stage = "Completed" if d["ok"] else "Failed"
                if s.start_time is not None:
                    s.elapsed_seconds = time.time() - s.start_time
                self._mark_queue()
            self.progress_current = idx + 1
            icon = "↷ " if (0 <= idx < len(self.samples) and self.samples[idx].is_skipped()) else ("✓ " if d["ok"] else "✗ ")
            new_logs.append(icon + d["message"])
        elif kind == "batch_finished":
            self.running = False
            self.cancel = None
            self._set_running_ui(False)
            word = "Cancelled" if d["cancelled"] else "Finished"
            new_logs.append(f"--- Batch {word}: {d['succeeded']} succeeded, {d['failed']} failed ---")
            if hasattr(self, "cache_stats_lbl"):
                try:
                    self.cache_stats_lbl.config(text=self._format_cache_stats())
                except Exception:
                    pass
        elif kind == "auth_finished":
            self.auth_running = False
            self._provider_layout()
            self._fallback_layout()
            self._set_test_pill(d["ok"], "Sign-in complete." if d["ok"] else "Sign-in failed.")
            new_logs.append(d["message"])
        elif kind == "test_connection_result":
            self.test_running = False
            self.test_btn.configure_state("normal")
            if hasattr(self, "test_fb_btn"):
                self.test_fb_btn.configure_state("normal")
            if self.v_fallback_enabled.get():
                self.test_btn.set_text("⚡ Test Main")
                if hasattr(self, "test_fb_btn"):
                    self.test_fb_btn.set_text("⚡ Test Fallback")
            else:
                self.test_btn.set_text("⚡ Test Connection")

            target = d.get("target", getattr(self, "testing_target", "main"))
            if target == "fallback":
                provider_name = self.v_fallback_provider.get()
                if d.get("available_models") and hasattr(self, "fb_model_box"):
                    models = d["available_models"]
                    self.fb_model_box["values"] = models
                    if d.get("resolved_model"):
                        self.v_fallback_model.set(d["resolved_model"])
                    elif models and (not self.v_fallback_model.get().strip() or self.v_fallback_model.get() in ("auto", "default")):
                        self.v_fallback_model.set(models[0])
                    self._pull_settings()
                    try:
                        self.settings.save()
                    except OSError:
                        pass
                    summary_models = ", ".join(models[:6]) + ("..." if len(models) > 6 else "")
                    new_logs.append(f"Available fallback models for {provider_name} ({len(models)}): {summary_models}")
                elif d.get("resolved_model"):
                    self.v_fallback_model.set(d["resolved_model"])
                    self._pull_settings()
                    try:
                        self.settings.save()
                    except OSError:
                        pass
                self._set_test_pill(d["ok"], f"[Fallback] {d['message']}")
                new_logs.append(("✓ AI Fallback: " if d["ok"] else "✗ AI Fallback: ") + d["message"])
            else:
                provider_name = self.v_provider.get()
                if d.get("available_models") and hasattr(self, "model_box"):
                    models = d["available_models"]
                    self.model_box["values"] = models
                    if d.get("resolved_model"):
                        self.v_model.set(d["resolved_model"])
                    elif models and (not self.v_model.get().strip() or self.v_model.get() in ("auto", "default")):
                        self.v_model.set(models[0])
                    self._pull_settings()
                    try:
                        self.settings.save()
                    except OSError:
                        pass
                    summary_models = ", ".join(models[:6]) + ("..." if len(models) > 6 else "")
                    new_logs.append(f"Available model(s) for {provider_name} ({len(models)}): {summary_models}")
                elif d.get("resolved_model"):
                    self.v_model.set(d["resolved_model"])
                    self._pull_settings()
                    try:
                        self.settings.save()
                    except OSError:
                        pass
                self._set_test_pill(d["ok"], d["message"])
                new_logs.append(("✓ AI Connection: " if d["ok"] else "✗ AI Connection: ") + d["message"])

    def _set_sample(self, index: int, status: str, stage: Optional[str] = None) -> None:
        if 0 <= index < len(self.samples):
            self.samples[index].status = status
            if stage is not None:
                self.samples[index].stage = stage
            self._mark_queue()


def run(initial_path: Optional[str] = None) -> None:
    root = tk.Tk()
    OmniApp(root, initial_path)
    root.mainloop()
