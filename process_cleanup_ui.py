"""Tk user interface for the local residual-process cleanup engine.

The dialog never inspects or terminates processes itself.  It displays the
redacted scan model from :mod:`process_cleanup` and passes the exact selected
``CleanupCandidate`` objects back to that engine for revalidation and
termination.
"""
from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, ttk
from typing import Callable, Optional, Sequence

from process_cleanup import (
    CLASS_INFO,
    CLASS_PROTECTED,
    CLASS_RECOMMENDED,
    CLASS_REVIEW,
    CleanupCandidate,
    CleanupPolicy,
    ScanResult,
    TerminationReport,
    scan_processes,
    terminate_candidates,
)


_FACE = "#c0c0c0"
_LIGHT = "#ffffff"
_MID = "#808080"
_DARK = "#404040"
_TEXT = "#000000"
_MUTED = "#555555"
_NAVY = "#000080"
_GREEN = "#006400"
_AMBER = "#8a5200"
_RED = "#9b1c1c"


def _memory_text(value: int) -> str:
    amount = max(0, int(value or 0))
    if amount >= 1024 ** 3:
        return f"{amount / (1024 ** 3):.2f} GB"
    if amount >= 1024 ** 2:
        return f"{amount / (1024 ** 2):.0f} MB"
    if amount >= 1024:
        return f"{amount / 1024:.0f} KB"
    return f"{amount} B"


def _age_text(seconds: float) -> str:
    value = max(0, int(seconds or 0))
    days, value = divmod(value, 86400)
    hours, value = divmod(value, 3600)
    minutes, _seconds = divmod(value, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m"
    return "<1m"


class ProcessCleanupDialog(tk.Toplevel):
    """On-demand scanner and exact-identity process termination dialog.

    ``on_log`` is optional and receives short, already-redacted summary lines
    on the Tk thread.  It may be a function such as ``logger.info``.
    """

    _POLL_BUSY_MS = 100
    _POLL_IDLE_MS = 500
    _CLOCK_MS = 1000

    def __init__(
            self, parent, policy: Optional[CleanupPolicy] = None,
            on_log: Optional[Callable[[str], None]] = None):
        super().__init__(parent)
        self._policy = policy or CleanupPolicy()
        self._on_log = on_log
        self._messages: queue.Queue[tuple[int, str, object]] = queue.Queue()
        self._operation_token = 0
        self._worker: Optional[threading.Thread] = None
        self._cancel_event: Optional[threading.Event] = None
        self._busy_kind = ""
        self._closing = False
        self._after_ids: set[str] = set()
        self._candidates: dict[str, CleanupCandidate] = {}
        self._selected_ids: set[str] = set()
        self._scan_stamp: Optional[float] = None
        self._scan_invalid = True
        self._details_expanded = False
        self._collapsed_height: Optional[int] = None
        self._column_after: Optional[str] = None

        self.title("Process Cleanup")
        self.configure(bg=_FACE)
        self.resizable(True, True)
        self.protocol("WM_DELETE_WINDOW", self._close)
        try:
            self.transient(parent)
        except tk.TclError:
            pass

        self._scale = self._tk_scale()
        self._install_fonts()
        # Geometry is already expressed in physical window pixels.  Applying
        # Tk's text scale here a second time made the old dialog enormous on
        # high-DPI/RDP displays.  Only internal spacing and fonts are scaled.
        avail_w = max(420, int(self.winfo_screenwidth()) - 32)
        avail_h = max(340, int(self.winfo_screenheight()) - 72)
        width = min(820, avail_w)
        height = min(520, avail_h)
        self._window_width_target = width
        self.geometry(f"{width}x{height}")
        # Leave a small physical-pixel gutter below the first row.  At 144 DPI
        # the Treeview row used to end exactly on its lower border, which made
        # the row look clipped even though Tk reported it as visible.
        min_height = min(
            avail_h, max(432, self._px(260) + 12))
        self.minsize(min(680, width), min_height)

        self._configure_styles()
        self._build()
        self._schedule(self._POLL_IDLE_MS, self._poll_messages)
        self._schedule(self._CLOCK_MS, self._refresh_freshness)
        self._schedule(120, self.scan)

    def _tk_scale(self) -> float:
        try:
            return max(0.75, min(3.0, float(self.tk.call("tk", "scaling"))))
        except (tk.TclError, TypeError, ValueError):
            return 1.0

    def _px(self, value: int) -> int:
        # Internal pixel dimensions follow text DPI; top-level geometry does
        # not. Tk's baseline scaling is normally about 1.33 at 96 DPI.
        return max(1, int(round(value * self._scale / 1.333333)))

    def _install_fonts(self) -> None:
        """Reuse RayApp semantic fonts, with identical standalone fallbacks."""
        roles = {
            "default": ("RCMDefaultFont", "Tahoma", 8, "normal"),
            "bold": ("RCMBoldFont", "Tahoma", 8, "bold"),
            "value": ("RCMValueFont", "Tahoma", 9, "bold"),
            "small": ("RCMSmallFont", "Tahoma", 7, "normal"),
            "mono": ("RCMMonoFont", "Consolas", 9, "normal"),
        }
        existing = set(tkfont.names(self))
        self._fonts: dict[str, str] = {}
        for role, (shared, family, size, weight) in roles.items():
            if shared in existing:
                self._fonts[role] = shared
                continue
            fallback = f"RCMCleanup{role.title()}Font"
            try:
                font = tkfont.Font(root=self, name=fallback, exists=True)
            except tk.TclError:
                font = tkfont.Font(root=self, name=fallback)
            font.configure(family=family, size=size, weight=weight)
            self._fonts[role] = fallback

    def _font(self, role: str) -> str:
        return self._fonts.get(role, self._fonts["default"])

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.configure(
            "Cleanup.Treeview", background=_LIGHT, fieldbackground=_LIGHT,
            foreground=_TEXT, rowheight=self._px(20),
            font=self._font("default"), borderwidth=0)
        style.configure(
            "Cleanup.Treeview.Heading", background=_FACE, foreground=_TEXT,
            relief="raised", padding=(self._px(3), self._px(2)),
            font=self._font("bold"))
        style.map(
            "Cleanup.Treeview",
            background=[("selected", _NAVY)],
            foreground=[("selected", _LIGHT)])
        style.configure("Cleanup.TFrame", background=_FACE)
        style.configure("Cleanup.TLabel", background=_FACE, foreground=_TEXT)
        style.configure(
            "Cleanup.Muted.TLabel", background=_FACE, foreground=_MUTED)

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        # Match the main window: a terse identity line followed by classic
        # groove groups.  The previous white-card style consumed nearly a
        # quarter of the window before any result was visible.
        header = tk.Frame(self, bg=_FACE)
        header.grid(
            row=0, column=0, sticky="ew", padx=self._px(8),
            pady=(self._px(7), self._px(3)))
        header.columnconfigure(0, weight=1)
        tk.Label(
            header, text="LOCAL PROCESS CLEANUP", bg=_FACE, fg=_TEXT,
            anchor="w", font=self._font("bold")).grid(
                row=0, column=0, sticky="w")
        self._header_safety = tk.Label(
            header,
            text="CPU/RAM show impact only; RCM also checks lifecycle and safety.",
            bg=_FACE, fg=_MUTED, anchor="w", justify="left",
            font=self._font("small"))
        self._header_safety.grid(
            row=1, column=0, sticky="ew", pady=(self._px(1), 0))
        header.bind("<Configure>", self._fit_responsive_labels)

        content = tk.Frame(self, bg=_FACE)
        content.grid(
            row=1, column=0, sticky="nsew", padx=self._px(8),
            pady=(0, self._px(4)))
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        self._content = content

        table_group = tk.LabelFrame(
            content, text=" Candidates ", bg=_FACE, fg=_TEXT,
            bd=2, relief="groove", font=self._font("default"),
            padx=self._px(4), pady=self._px(4))
        table_group.grid(row=0, column=0, sticky="nsew")
        table_group.columnconfigure(0, weight=1)
        table_group.rowconfigure(
            2, weight=1, minsize=self._px(48))
        self._table_group = table_group
        self._class_legend = tk.Label(
            table_group,
            text=(
                "Class: Recommended = strong evidence  |  "
                "Review = check manually  |  Protected = cannot end"),
            bg=_FACE, fg=_MUTED, anchor="w", justify="left",
            font=self._font("small"))
        self._class_legend.grid(row=0, column=0, sticky="ew")
        self._selection_legend = tk.Label(
            table_group,
            text=(
                "Selection: [x] selected to end  |  [ ] not selected  |  "
                "\u2014 unavailable"),
            bg=_FACE, fg=_TEXT, anchor="w", justify="left",
            font=self._font("small"))
        self._selection_legend.grid(
            row=1, column=0, sticky="ew",
            pady=(0, self._px(3)))
        table_frame = tk.Frame(
            table_group, bg=_MID, bd=1, relief="sunken")
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self._table_frame = table_frame

        # Full evidence is shown directly below the list and in the optional
        # detail drawer.  Omitting a second long prose column lets every
        # sortable value fit without a horizontal scrollbar.
        columns = ("selected", "classification", "program", "cpu", "ram", "age")
        self._tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            selectmode="browse", style="Cleanup.Treeview")
        headings = {
            "selected": "End?",
            "classification": "Class",
            "program": "Process / workload",
            "cpu": "CPU",
            "ram": "RAM",
            "age": "Age",
        }
        for column in columns:
            anchor = "center" if column in {
                "selected", "classification", "cpu", "ram", "age"} else "w"
            self._tree.heading(column, text=headings[column], anchor=anchor)
            self._tree.column(
                column, width=self._px(80), minwidth=self._px(32),
                anchor=anchor, stretch=(column == "program"))
        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self._tree.yview)
        self._tree_yscroll = yscroll
        self._tree.configure(yscrollcommand=yscroll.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        yscroll.grid_remove()
        self._tree.tag_configure("recommended", foreground=_GREEN)
        self._tree.tag_configure("review", foreground=_AMBER)
        self._tree.tag_configure("info", foreground=_MUTED)
        self._tree.tag_configure("protected", foreground=_RED)
        self._tree.bind("<<TreeviewSelect>>", self._show_selected_details)
        self._tree.bind("<Button-1>", self._on_tree_click, add="+")
        self._tree.bind("<space>", self._on_tree_space)
        self._tree.bind("<Configure>", self._queue_column_fit)

        summary = tk.LabelFrame(
            content, text=" Selected item ", bg=_FACE, fg=_TEXT,
            bd=2, relief="groove", font=self._font("default"),
            padx=self._px(6), pady=self._px(4))
        summary.grid(
            row=1, column=0, sticky="ew", pady=(self._px(4), 0))
        summary.columnconfigure(0, weight=1)
        self._summary_title_var = tk.StringVar(
            value="Select a row to review its evidence.")
        self._summary_var = tk.StringVar(value="")
        tk.Label(
            summary, textvariable=self._summary_title_var, bg=_FACE, fg=_TEXT,
            anchor="w", font=self._font("bold")).grid(
                row=0, column=0, sticky="ew")
        self._summary_label = tk.Label(
            summary, textvariable=self._summary_var, bg=_FACE, fg=_MUTED,
            anchor="w", justify="left", font=self._font("small"),
            wraplength=self._px(400))
        self._summary_label.grid(
            row=1, column=0, sticky="ew", pady=(self._px(1), 0))
        self._details_button = tk.Button(
            summary, text="Details >>", command=self._toggle_details,
            bg=_FACE, fg=_TEXT, relief="raised", bd=2,
            highlightthickness=0, font=self._font("default"),
            padx=self._px(5), pady=0)
        self._details_button.grid(
            row=0, column=1, rowspan=2, sticky="e",
            padx=(self._px(8), 0))
        self._summary_group = summary
        summary.bind("<Configure>", self._fit_responsive_labels)

        self._detail_frame = tk.LabelFrame(
            content, text=" Details - command line is redacted ",
            bg=_FACE, fg=_TEXT, bd=2, relief="groove",
            font=self._font("default"),
            padx=self._px(4), pady=self._px(4))
        self._detail_frame.columnconfigure(0, weight=1)
        self._detail_frame.rowconfigure(0, weight=1)
        self._details = tk.Text(
            self._detail_frame, wrap="word", height=5, bg=_LIGHT, fg=_TEXT,
            relief="sunken", bd=1, font=self._font("mono"),
            padx=self._px(4), pady=self._px(3), state="disabled")
        detail_scroll = ttk.Scrollbar(
            self._detail_frame, orient="vertical",
            command=self._details.yview)
        self._details_yscroll = detail_scroll
        self._details.configure(yscrollcommand=detail_scroll.set)
        self._details.grid(row=0, column=0, sticky="nsew")
        detail_scroll.grid(row=0, column=1, sticky="ns")
        detail_scroll.grid_remove()
        self._details.bind(
            "<Configure>",
            lambda _event: self._schedule(
                0, self._refresh_details_scrollbar))

        footer = tk.Frame(self, bg=_FACE)
        footer.grid(
            row=2, column=0, sticky="ew", padx=self._px(8),
            pady=(0, self._px(7)))
        footer.columnconfigure(0, weight=1)

        status_row = tk.Frame(
            footer, bg=_LIGHT, bd=1, relief="sunken")
        status_row.grid(
            row=0, column=0, columnspan=2, sticky="ew",
            pady=(0, self._px(4)))
        status_row.columnconfigure(0, weight=1)
        self._status_var = tk.StringVar(value="Preparing scan...")
        self._ttl_var = tk.StringVar(value="")
        tk.Label(
            status_row, textvariable=self._status_var, bg=_LIGHT, fg=_TEXT,
            anchor="w", font=self._font("small"),
            padx=self._px(4), pady=self._px(2)).grid(
                row=0, column=0, sticky="ew")
        tk.Label(
            status_row, textvariable=self._ttl_var, bg=_LIGHT, fg=_MUTED,
            anchor="e", font=self._font("small"),
            padx=self._px(4), pady=self._px(2)).grid(
                row=0, column=1, sticky="e")

        selection_buttons = tk.Frame(footer, bg=_FACE)
        selection_buttons.grid(row=1, column=0, sticky="w")
        self._recommended_button = tk.Button(
            selection_buttons, text="Recommended only",
            command=self._select_recommended, bg=_FACE, fg=_TEXT,
            relief="raised", bd=2, highlightthickness=0,
            font=self._font("default"), padx=self._px(5), pady=0)
        self._recommended_button.pack(side="left")
        self._clear_button = tk.Button(
            selection_buttons, text="Clear",
            command=self._clear_selection, bg=_FACE, fg=_TEXT,
            relief="raised", bd=2, highlightthickness=0,
            font=self._font("default"), padx=self._px(5), pady=0)
        self._clear_button.pack(side="left", padx=(self._px(4), 0))

        action_buttons = tk.Frame(footer, bg=_FACE)
        action_buttons.grid(
            row=2, column=0, columnspan=2, sticky="e",
            pady=(self._px(3), 0))
        self._action_buttons = action_buttons
        self._scan_button = tk.Button(
            action_buttons, text="Rescan", command=self.scan,
            bg=_FACE, fg=_TEXT, relief="raised", bd=2,
            highlightthickness=0, font=self._font("default"),
            padx=self._px(5), pady=0)
        self._scan_button.pack(side="left")
        self._cancel_button = tk.Button(
            action_buttons, text="Cancel", command=self.cancel_operation,
            bg=_FACE, fg=_TEXT, relief="raised", bd=2,
            highlightthickness=0, font=self._font("default"),
            padx=self._px(5), pady=0, state="disabled")
        self._cancel_button.pack(side="left", padx=(self._px(4), 0))
        self._end_button = tk.Button(
            action_buttons, text="End Selected",
            command=self._confirm_termination, bg=_FACE, fg=_TEXT,
            activeforeground=_RED, relief="raised", bd=2,
            highlightthickness=0, font=self._font("bold"),
            padx=self._px(6), pady=0, state="disabled")
        self._end_button.pack(side="left", padx=(self._px(6), 0))
        self._close_button = tk.Button(
            action_buttons, text="Close", command=self._close,
            bg=_FACE, fg=_TEXT, relief="raised", bd=2,
            highlightthickness=0, font=self._font("default"),
            padx=self._px(5), pady=0)
        self._close_button.pack(side="left", padx=(self._px(4), 0))

        self.bind("<Escape>", lambda _event: self._close())
        self.bind("<F5>", lambda _event: self.scan())
        self.bind("<Configure>", self._fit_responsive_labels, add="+")
        self._queue_column_fit()

    def _queue_column_fit(self, _event=None) -> None:
        if self._closing:
            return
        if self._column_after is not None:
            try:
                self.after_cancel(self._column_after)
            except tk.TclError:
                pass
        self._column_after = self.after(30, self._fit_columns)

    def _fit_responsive_labels(self, _event=None) -> None:
        """Wrap prose inside the current viewport instead of requesting width."""
        try:
            header_width = max(180, self._header_safety.master.winfo_width())
            self._header_safety.configure(
                wraplength=max(160, header_width - self._px(4)))
            detail_width = max(
                140, self._details_button.winfo_reqwidth() + self._px(8))
            summary_width = max(
                160, self._summary_group.winfo_width() - detail_width
                - self._px(18))
            self._summary_label.configure(wraplength=summary_width)
            # Never derive wrapping from the Tree's transient 1px allocation:
            # on an empty result at 144 DPI that feedback loop made both
            # legends tall enough to squeeze the entire list out.  The
            # top-level/content viewport is stable even before rows exist.
            window_width = self.winfo_width()
            if window_width <= 1:
                window_width = self._window_width_target
            content_width = self._content.winfo_width()
            if content_width <= 1:
                content_width = window_width - 2 * self._px(8)
            legend_width = max(
                260, content_width - 2 * self._px(10))
            self._class_legend.configure(wraplength=legend_width)
            self._selection_legend.configure(wraplength=legend_width)
        except tk.TclError:
            pass

    def _refresh_live_scale(self) -> None:
        """Atomically refit scale-sensitive metrics after an RDP/DPI switch."""
        live = self._tk_scale()
        if abs(live - self._scale) < 0.01:
            return
        self._scale = live
        self._configure_styles()
        self._table_group.rowconfigure(
            2, minsize=self._px(48))
        available_h = max(360, self.winfo_screenheight() - 72)
        self.minsize(
            min(680, max(420, self.winfo_screenwidth() - 32)),
            min(available_h, max(432, self._px(260) + 12)))
        buttons = (
            self._recommended_button, self._clear_button,
            self._details_button, self._scan_button, self._cancel_button,
            self._end_button, self._close_button)
        for button in buttons:
            button.configure(
                padx=self._px(6 if button is self._end_button else 5),
                pady=0)
        self._fit_responsive_labels()

    def _fit_columns(self) -> None:
        """Fit every heading/value column to the visible list width."""
        self._column_after = None
        if self._closing or not self.winfo_exists():
            return
        self._refresh_live_scale()
        needs_scroll = self._tree_needs_scroll()
        scrollbar_cost = (
            self._tree_yscroll.winfo_reqwidth()
            if needs_scroll and not self._tree_yscroll.winfo_ismapped()
            else 0)
        available = max(
            180, self._tree.winfo_width() - scrollbar_cost - 2)
        font = tkfont.Font(root=self, font=self._font("default"))
        pad = self._px(8)
        samples = {
            "selected": ("End?", "[x]"),
            "classification": (
                "Class", "Recommended", "Protected", "Review"),
            "cpu": ("CPU", "100.0%"),
            "ram": ("RAM", "10.00 GB"),
            "age": ("Age", "99d 23h"),
        }
        fixed: dict[str, int] = {}
        for column, values in samples.items():
            fixed[column] = max(font.measure(value) for value in values) + pad
        fixed["selected"] += self._px(4)
        fixed_total = sum(fixed.values())
        program_heading = font.measure("Process") + pad
        program = max(program_heading, available - fixed_total)
        if fixed_total + program > available:
            # Extremely narrow/high-DPI windows keep every column reachable.
            # Numeric values remain in the selected-item summary as well.
            excess = fixed_total + program - available
            shrinkable = ("classification", "ram", "age", "cpu")
            for column in shrinkable:
                floor = font.measure({
                    "classification": "Class",
                    "ram": "RAM",
                    "age": "Age",
                    "cpu": "CPU",
                }[column]) + self._px(4)
                take = min(excess, max(0, fixed[column] - floor))
                fixed[column] -= take
                excess -= take
                if excess <= 0:
                    break
            if excess > 0:
                program = max(self._px(36), program - excess)
        for column, width in fixed.items():
            self._tree.column(
                column, width=width, minwidth=1, stretch=False)
        self._tree.column(
            "program", width=program, minwidth=1, stretch=False)
        self._fit_responsive_labels()
        self._refresh_tree_scrollbar()

    def _tree_needs_scroll(self) -> bool:
        try:
            first, last = self._tree.yview()
            return bool(
                self._tree.get_children()
                and (first > 0.001 or last < 0.999))
        except tk.TclError:
            return False

    def _refresh_tree_scrollbar(self) -> None:
        """Show the candidate scrollbar only when rows exceed the viewport."""
        try:
            needs_scroll = self._tree_needs_scroll()
            if needs_scroll:
                if not self._tree_yscroll.winfo_ismapped():
                    self._tree_yscroll.grid(row=0, column=1, sticky="ns")
            elif self._tree_yscroll.winfo_ismapped():
                self._tree_yscroll.grid_remove()
        except tk.TclError:
            pass

    def _toggle_details(self) -> None:
        self._set_details_expanded(not self._details_expanded)

    def _set_details_expanded(self, expanded: bool) -> None:
        expanded = bool(expanded)
        if expanded == self._details_expanded:
            return
        self.update_idletasks()
        current_w = self.winfo_width()
        current_h = self.winfo_height()
        current_x = self.winfo_x()
        current_y = self.winfo_y()
        self._details_expanded = expanded
        if self._details_expanded:
            self._collapsed_height = current_h
            available_h = max(360, self.winfo_screenheight() - 72)
            expanded_h = min(
                available_h, current_h + self._px(150))
            self.geometry(
                f"{current_w}x{expanded_h}+{current_x}+{current_y}")
            self._detail_frame.grid(
                row=2, column=0, sticky="nsew",
                pady=(self._px(4), 0))
            self._details_button.configure(text="Details <<")
            self._schedule(0, self._refresh_details_scrollbar)
        else:
            self._detail_frame.grid_remove()
            self._details_button.configure(text="Details >>")
            collapsed_h = self._collapsed_height or min(520, current_h)
            self.geometry(
                f"{current_w}x{collapsed_h}+{current_x}+{current_y}")
            self._collapsed_height = None
        self._queue_column_fit()

    def _schedule(self, delay_ms: int, callback) -> None:
        if self._closing:
            return
        holder: list[str] = []

        def run() -> None:
            if holder:
                self._after_ids.discard(holder[0])
            if not self._closing and self.winfo_exists():
                callback()

        after_id = self.after(delay_ms, run)
        holder.append(after_id)
        self._after_ids.add(after_id)

    def _emit_log(self, text: str) -> None:
        if self._on_log is None:
            return
        try:
            self._on_log(str(text))
        except Exception:
            pass

    def _set_busy(self, kind: str) -> None:
        self._busy_kind = kind
        self._scan_button.configure(state="disabled")
        # Ending is an already-confirmed exact operation. On Windows there is
        # no meaningful graceful/force distinction, so only scans expose a
        # user-facing Cancel action.
        self._cancel_button.configure(
            state=("normal" if kind == "scan" else "disabled"))
        self._recommended_button.configure(state="disabled")
        self._clear_button.configure(state="disabled")
        self._end_button.configure(state="disabled")

    def _set_idle(self) -> None:
        self._busy_kind = ""
        self._worker = None
        self._cancel_event = None
        self._scan_button.configure(state="normal")
        self._cancel_button.configure(state="disabled")
        self._recommended_button.configure(state="normal")
        self._clear_button.configure(state="normal")
        self._refresh_actions()

    def scan(self) -> None:
        if self._closing or self._busy_kind:
            return
        self._operation_token += 1
        token = self._operation_token
        cancel_event = threading.Event()
        self._cancel_event = cancel_event
        self._scan_invalid = True
        self._scan_stamp = None
        self._ttl_var.set("")
        self._status_var.set(
            f"Scanning processes and sampling CPU for "
            f"{max(0.05, float(self._policy.sample_sec)):.1f} seconds...")
        self._set_busy("scan")

        def work() -> None:
            try:
                result = scan_processes(self._policy, cancel_event)
                self._messages.put((token, "scan-result", result))
            except Exception as exc:
                self._messages.put((
                    token, "error",
                    f"Scan failed: {type(exc).__name__}: {exc}"))

        self._worker = threading.Thread(
            target=work, daemon=True, name="RCMProcessCleanupScan")
        self._worker.start()

    def cancel_operation(self) -> None:
        event = self._cancel_event
        if not self._busy_kind or event is None:
            return
        event.set()
        self._cancel_button.configure(state="disabled")
        self._status_var.set(
            "Cancelling scan..." if self._busy_kind == "scan"
            else "Cancelling after the current process check...")

    def _poll_messages(self) -> None:
        while True:
            try:
                token, kind, payload = self._messages.get_nowait()
            except queue.Empty:
                break
            if token != self._operation_token:
                continue
            if kind == "scan-result":
                self._apply_scan_result(payload)
            elif kind == "termination-result":
                self._apply_termination_report(payload)
            elif kind == "error":
                self._set_idle()
                self._scan_invalid = True
                self._status_var.set(str(payload))
                self._emit_log(f"Process cleanup: {payload}")
                messagebox.showerror(
                    "Process Cleanup", str(payload), parent=self)
        delay = (
            self._POLL_BUSY_MS if self._busy_kind
            else self._POLL_IDLE_MS)
        self._schedule(delay, self._poll_messages)

    def _apply_scan_result(self, result: ScanResult) -> None:
        self._set_idle()
        self._candidates.clear()
        self._selected_ids.clear()
        self._tree.delete(*self._tree.get_children())
        if result.cancelled:
            self._scan_invalid = True
            self._scan_stamp = None
            self._status_var.set("Scan cancelled. Rescan to get fresh results.")
            self._summary_title_var.set("Scan cancelled")
            self._summary_var.set("Press Rescan to obtain a fresh result.")
            self._details_text("")
            return
        if result.errors:
            self._scan_invalid = True
            self._scan_stamp = None
            summary = "; ".join(str(item) for item in result.errors[:3])
            self._status_var.set(
                "Scan incomplete; safety checks failed. Nothing can be ended.")
            self._summary_title_var.set("Scan incomplete - no action allowed")
            self._summary_var.set(
                "One or more Windows safety checks could not be completed.")
            self._details_text(
                "RCM could not complete every required Windows safety check.\n"
                "No cleanup candidates are actionable. Rescan after fixing "
                f"the access problem.\n\n{summary}")
            self._emit_log(
                f"Process cleanup scan blocked: {len(result.errors)} "
                "safety check error(s)")
            self._refresh_actions()
            return

        for candidate in result.candidates:
            group_id = candidate.group_id
            self._candidates[group_id] = candidate
            if candidate.classification == CLASS_RECOMMENDED:
                self._selected_ids.add(group_id)
            self._tree.insert(
                "", "end", iid=group_id,
                values=self._row_values(candidate),
                tags=(candidate.classification.casefold(),))

        stamps = [
            item.scanned_monotonic for item in result.candidates
            if item.scanned_monotonic > 0]
        self._scan_stamp = min(stamps) if stamps else time.monotonic()
        self._scan_invalid = False
        self._status_var.set(
            f"Scanned {result.process_count} processes; "
            f"{len(result.candidates)} group(s) listed, "
            f"{result.recommended_count} recommended.")
        self._emit_log(
            f"Process cleanup scan: {result.process_count} processes, "
            f"{len(result.candidates)} listed, "
            f"{result.recommended_count} recommended")
        children = self._tree.get_children()
        if children:
            self._tree.selection_set(children[0])
            self._tree.focus(children[0])
            self._show_candidate_details(self._candidates[children[0]])
        else:
            self._summary_title_var.set("No candidates")
            self._summary_var.set(
                "CPU or RAM usage by itself never makes a process actionable.")
            self._details_text(
                "No background process groups met the review threshold.\n\n"
                "RCM does not list a process only because it uses CPU or RAM.")
        self._schedule(0, self._refresh_tree_scrollbar)
        self._refresh_actions()
        self._update_freshness()

    def _row_values(self, candidate: CleanupCandidate) -> tuple[str, ...]:
        if candidate.classification not in {
                CLASS_RECOMMENDED, CLASS_REVIEW}:
            marker = "\u2014"
        else:
            marker = "[x]" if candidate.group_id in self._selected_ids else "[ ]"
        class_text = {
            CLASS_RECOMMENDED: "Recommended",
            CLASS_REVIEW: "Review",
            CLASS_INFO: "Info",
            CLASS_PROTECTED: "Protected",
        }.get(candidate.classification, candidate.classification)
        return (
            marker,
            class_text,
            candidate.label,
            f"{candidate.cpu_pct:.1f}%",
            _memory_text(candidate.memory_bytes),
            _age_text(candidate.age_sec),
        )

    def _on_tree_click(self, event):
        if self._busy_kind:
            return None
        item_id = self._tree.identify_row(event.y)
        column = self._tree.identify_column(event.x)
        if item_id and column == "#1":
            self._tree.selection_set(item_id)
            self._tree.focus(item_id)
            self._toggle_candidate(item_id)
            return "break"
        return None

    def _on_tree_space(self, _event):
        if not self._busy_kind:
            item_id = self._tree.focus()
            if item_id:
                self._toggle_candidate(item_id)
        return "break"

    def _toggle_candidate(self, group_id: str) -> None:
        candidate = self._candidates.get(group_id)
        if (candidate is None or candidate.classification not in {
                CLASS_RECOMMENDED, CLASS_REVIEW}):
            return
        if group_id in self._selected_ids:
            self._selected_ids.remove(group_id)
        else:
            self._selected_ids.add(group_id)
        self._tree.item(group_id, values=self._row_values(candidate))
        self._show_candidate_details(candidate)
        self._refresh_actions()

    def _select_recommended(self) -> None:
        if self._busy_kind:
            return
        self._selected_ids = {
            item.group_id for item in self._candidates.values()
            if item.classification == CLASS_RECOMMENDED}
        self._refresh_rows()

    def _clear_selection(self) -> None:
        if self._busy_kind:
            return
        self._selected_ids.clear()
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        for group_id, candidate in self._candidates.items():
            if self._tree.exists(group_id):
                self._tree.item(group_id, values=self._row_values(candidate))
        self._refresh_actions()

    def _show_selected_details(self, _event=None) -> None:
        selected = self._tree.selection()
        if selected:
            candidate = self._candidates.get(selected[0])
            if candidate is not None:
                self._show_candidate_details(candidate)

    def _show_candidate_details(self, candidate: CleanupCandidate) -> None:
        reasons = list(candidate.reasons)
        if candidate.protected_reason:
            reasons.append(candidate.protected_reason)
        brief = "; ".join(reasons[:3]) or "background process evidence"
        if len(reasons) > 3:
            brief += f"; +{len(reasons) - 3} more"
        self._summary_title_var.set(
            f"{candidate.label} - {candidate.classification}, "
            f"score {candidate.score}/100")
        self._summary_var.set(
            f"Class is evidence, not a safety guarantee.  Why: {brief}    "
            f"CPU {candidate.cpu_pct:.1f}%  |  "
            f"RAM {_memory_text(candidate.memory_bytes)}  |  "
            f"Age {_age_text(candidate.age_sec)}")
        lines = [
            f"{candidate.label}  [{candidate.classification}, "
            f"score {candidate.score}/100]",
            "",
            f"Process IDs: {', '.join(str(pid) for pid in candidate.member_pids)}",
            f"CPU / RAM: {candidate.cpu_pct:.1f}% / "
            f"{_memory_text(candidate.memory_bytes)}",
            f"Age: {_age_text(candidate.age_sec)}",
        ]
        if candidate.project_root:
            lines.append(f"Project: {candidate.project_root}")
        if candidate.ports:
            lines.append(
                f"Listener ports: "
                f"{', '.join(str(port) for port in candidate.ports)}")
        lines.extend((
            f"Active or non-local network endpoint: "
            f"{'yes' if candidate.active_connection else 'no'}",
            "",
            "Evidence:",
        ))
        lines.extend(
            f"  - {reason}" for reason in candidate.reasons)
        if candidate.protected_reason:
            lines.extend(("", f"Protected: {candidate.protected_reason}"))
        lines.extend((
            "",
            "Redacted command:",
            candidate.safe_command or "(not available)",
        ))
        self._details_text("\n".join(lines))

    def _details_text(self, text: str) -> None:
        self._details.configure(state="normal")
        self._details.delete("1.0", "end")
        self._details.insert("1.0", text)
        self._details.configure(state="disabled")
        self._schedule(0, self._refresh_details_scrollbar)

    def _refresh_details_scrollbar(self) -> None:
        """Expose the details scrollbar only when the Text view overflows."""
        if self._closing or not self.winfo_exists():
            return
        try:
            self.update_idletasks()
            first, last = self._details.yview()
            needs_scroll = first > 0.001 or last < 0.999
            if needs_scroll:
                if not self._details_yscroll.winfo_ismapped():
                    self._details_yscroll.grid(
                        row=0, column=1, sticky="ns")
            elif self._details_yscroll.winfo_ismapped():
                self._details_yscroll.grid_remove()
        except tk.TclError:
            pass

    def _fresh(self) -> bool:
        if self._scan_invalid or self._scan_stamp is None:
            return False
        age = time.monotonic() - self._scan_stamp
        return age <= max(0.0, float(self._policy.result_max_age_sec))

    def _update_freshness(self) -> None:
        """Refresh freshness state without creating another timer chain."""
        if abs(self._tk_scale() - self._scale) >= 0.01:
            self._refresh_live_scale()
            self._queue_column_fit()
        if self._scan_stamp is None:
            self._ttl_var.set("")
        elif self._fresh():
            remaining = max(
                0, int(float(self._policy.result_max_age_sec)
                       - (time.monotonic() - self._scan_stamp)))
            self._ttl_var.set(
                f"Fresh {remaining}s")
        else:
            self._scan_invalid = True
            self._ttl_var.set("Stale \u00b7 rescan required")
        self._refresh_actions()

    def _refresh_freshness(self) -> None:
        self._update_freshness()
        self._schedule(self._CLOCK_MS, self._refresh_freshness)

    def _refresh_actions(self) -> None:
        if self._busy_kind:
            self._end_button.configure(state="disabled")
            return
        selectable = [
            group_id for group_id in self._selected_ids
            if group_id in self._candidates
            and self._candidates[group_id].classification in {
                CLASS_RECOMMENDED, CLASS_REVIEW}]
        state = "normal" if selectable and self._fresh() else "disabled"
        self._end_button.configure(state=state)

    def _confirm_termination(self) -> None:
        if self._busy_kind:
            return
        if not self._fresh():
            messagebox.showwarning(
                "Process Cleanup",
                "These scan results are stale. Rescan before ending anything.",
                parent=self)
            self._refresh_actions()
            return
        selected = [
            item for group_id, item in self._candidates.items()
            if group_id in self._selected_ids
            and item.classification in {CLASS_RECOMMENDED, CLASS_REVIEW}]
        if not selected:
            return
        review_count = sum(
            item.classification != CLASS_RECOMMENDED for item in selected)
        warning = (
            f"End {len(selected)} selected background process group(s)?\n\n"
            "RCM will re-check and end only the exact process identities "
            "captured by this fresh scan. Windows may terminate them "
            "immediately, so unsaved work inside those processes can be "
            "lost."
        )
        if review_count:
            warning += (
                f"\n\n{review_count} selected group(s) are not in the "
                "Recommended class. Confirm that you recognize them.")
        if not messagebox.askyesno(
                "Confirm Process Cleanup", warning,
                icon="warning", default="no", parent=self):
            return
        self._start_termination(selected)

    def _start_termination(
            self, selected: Sequence[CleanupCandidate]) -> None:
        self._operation_token += 1
        token = self._operation_token
        cancel_event = threading.Event()
        self._cancel_event = cancel_event
        self._status_var.set(
            f"Revalidating and ending {len(selected)} selected group(s)...")
        self._set_busy("termination")

        def work() -> None:
            try:
                report = terminate_candidates(
                    selected, self._policy, cancel_event, force=False)
                self._messages.put((token, "termination-result", report))
            except Exception as exc:
                self._messages.put((
                    token, "error",
                    f"Cleanup failed: {type(exc).__name__}: {exc}"))

        self._worker = threading.Thread(
            target=work, daemon=True, name="RCMProcessCleanupEnd")
        self._worker.start()

    def _apply_termination_report(self, report: TerminationReport) -> None:
        self._set_idle()
        self._scan_invalid = True
        self._selected_ids.clear()
        self._refresh_rows()
        ended = report.ended_count
        skipped = sum(item.status.startswith("Skipped") for item in report.items)
        remaining = sum(bool(item.remaining_pids) for item in report.items)
        if report.cancelled:
            headline = (
                f"Cleanup cancelled: {ended} ended; rescan to verify state.")
        else:
            headline = (
                f"Cleanup finished: {ended} ended, {skipped} skipped, "
                f"{remaining} still running. Rescan to verify.")
        self._status_var.set(headline)
        self._ttl_var.set("Results invalidated \u00b7 rescan required")
        lines = [headline, ""]
        for item in report.items:
            line = f"{item.label}: {item.status}"
            if item.ended_pids:
                line += (
                    f" (ended PID"
                    f"{'s' if len(item.ended_pids) != 1 else ''} "
                    f"{', '.join(str(pid) for pid in item.ended_pids)})")
            if item.remaining_pids:
                line += (
                    f" (still running: "
                    f"{', '.join(str(pid) for pid in item.remaining_pids)})")
            lines.append(line)
            if item.message:
                lines.append(f"  {item.message}")
        self._details_text("\n".join(lines))
        self._summary_title_var.set(headline)
        self._summary_var.set(
            "The previous scan is invalid now. Rescan to verify current state.")
        self._emit_log(f"Process cleanup: {headline}")
        self._refresh_actions()
        messagebox.showinfo("Process Cleanup", headline, parent=self)

    def _close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._operation_token += 1
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._column_after is not None:
            try:
                self.after_cancel(self._column_after)
            except tk.TclError:
                pass
            self._column_after = None
        for after_id in tuple(self._after_ids):
            try:
                self.after_cancel(after_id)
            except tk.TclError:
                pass
        self._after_ids.clear()
        try:
            self.destroy()
        except tk.TclError:
            pass

    def cancel_and_close(self) -> None:
        """Cancel outstanding work and close the dialog during app shutdown."""
        self._close()


__all__ = ["ProcessCleanupDialog"]
