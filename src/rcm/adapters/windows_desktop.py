"""Lazy, import-safe Windows desktop adapters."""

from __future__ import annotations

from collections.abc import Callable
import math
from pathlib import PureWindowsPath
from threading import Event, Lock, Thread, current_thread
import time
from typing import Any, Protocol

from ..desktop import (
    AutostartPort,
    DesktopHost,
    LifecycleAction,
    ShutdownFallback,
    SingletonLease,
    SingletonPort,
    UiThreadGuard,
)
from ..identity import ApplicationIdentity
from ..resources import read_help_bytes
from ..ui.help import parse_help
from ..ui.main_window import MainWindowView
from ..ui.rdp_dialog import RdpDraft
from ..ui.state import (
    CommandKind,
    Fields,
    RenderState,
    Surface,
    UiCommand,
    UiVisibility,
)
from ..ui.status_board import StatusBoardView


class _Tray(Protocol):
    def start(self) -> None: ...

    def set_title(self, title: str) -> None: ...

    def stop(self) -> None: ...


class WindowsSingleton(SingletonPort):
    def acquire(self, identity: ApplicationIdentity) -> SingletonLease | None:
        if not isinstance(identity, ApplicationIdentity):
            raise TypeError("identity must be an ApplicationIdentity")
        return _acquire_windows_mutex(identity.mutex_name)


def _acquire_windows_mutex(name: str) -> SingletonLease | None:
    import ctypes
    import os
    from ctypes import wintypes

    if os.name != "nt":
        raise RuntimeError("the Windows singleton adapter requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    create.restype = wintypes.HANDLE
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = create(None, False, name)
    if not handle:
        error = ctypes.get_last_error()
        # An existing global mutex created at another integrity level may be
        # visible but not openable with CreateMutexW's requested access.  That
        # still proves another instance owns the production identity, so fail
        # closed instead of crashing or allowing a duplicate process.
        if error == 5:  # ERROR_ACCESS_DENIED
            return None
        raise OSError(error, "CreateMutexW failed")
    if ctypes.get_last_error() == 183:
        close(handle)
        return None
    lock = Lock()
    released = False

    def release() -> None:
        nonlocal released
        with lock:
            if not released:
                if not close(handle):
                    raise OSError(ctypes.get_last_error(), "CloseHandle failed")
                released = True

    return SingletonLease(name, release)


class WindowsAutostart(AutostartPort):
    _KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"

    def enabled(self, identity: ApplicationIdentity) -> bool:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._KEY) as key:
                value, kind = winreg.QueryValueEx(key, identity.config_namespace)
        except FileNotFoundError:
            return False
        return kind == winreg.REG_SZ and isinstance(value, str) and bool(value)

    def set_enabled(
        self,
        identity: ApplicationIdentity,
        *,
        enabled: bool,
        executable: str,
    ) -> None:
        import winreg

        if type(enabled) is not bool:
            raise TypeError("enabled must be a bool")
        path = PureWindowsPath(executable)
        if not path.is_absolute() or path.anchor.startswith("\\\\"):
            raise ValueError("autostart executable must be one absolute local path")
        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            self._KEY,
            access=winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
        ) as key:
            if enabled:
                winreg.SetValueEx(
                    key,
                    identity.config_namespace,
                    0,
                    winreg.REG_SZ,
                    f'"{path}" --start-minimized',
                )
            else:
                try:
                    winreg.DeleteValue(key, identity.config_namespace)
                except FileNotFoundError:
                    pass


class ExactOwnedFallback(ShutdownFallback):
    def __init__(
        self,
        terminator: Callable[[tuple[str, ...], float], bool],
    ) -> None:
        if not callable(terminator):
            raise TypeError("terminator must be callable")
        self._terminator = terminator

    def terminate_owned(
        self,
        component_names: tuple[str, ...],
        timeout_seconds: float,
    ) -> bool:
        if (
            type(component_names) is not tuple
            or len(component_names) != len(set(component_names))
            or any(not isinstance(name, str) or not name for name in component_names)
        ):
            raise ValueError("component names must be unique non-empty strings")
        if not component_names:
            return True
        return bool(self._terminator(component_names, timeout_seconds))

    __call__ = terminate_owned


class TkDesktopHost(DesktopHost):
    def __init__(
        self,
        root: Any | None = None,
        *,
        tray_factory: Callable[[Callable[[], None], Callable[[], None]], _Tray]
        | None = None,
        thread_guard: UiThreadGuard | None = None,
        rdp_probe: Callable[[str, int, float], bool] | None = None,
    ) -> None:
        self._root = root
        self._tk: Any | None = None
        self._guard = UiThreadGuard() if thread_guard is None else thread_guard
        self._command: Callable[[UiCommand], None] | None = None
        self._sequence = 0
        self._dialogs: dict[Surface, Any] = {}
        self._buttons: list[tuple[Any, CommandKind, Surface | None]] = []
        self._rdp_form: dict[str, Any] | None = None
        self._rdp_probe_generation = 0
        self._rdp_probe_threads: set[Thread] = set()
        self._rdp_probe_threads_lock = Lock()
        self._rdp_probe_cancel: Event | None = None
        self._rdp_probe_is_default = rdp_probe is None
        self._rdp_probe = _tcp_rdp_probe if rdp_probe is None else rdp_probe
        if not callable(self._rdp_probe):
            raise TypeError("rdp_probe must be callable")
        self._main_view = MainWindowView()
        self._status_view = StatusBoardView()
        self._state = RenderState()
        self._tray_factory = (
            _default_tray if tray_factory is None else tray_factory
        )
        self._tray: _Tray | None = None
        if root is not None:
            self._ensure_initialized()

    def _ensure_initialized(self) -> None:
        if self._tk is not None:
            return
        import tkinter as tk

        root = self._root
        created = root is None
        if root is None:
            root = tk.Tk()
        try:
            tray = self._tray_factory(self._tray_show, self._tray_quit)
        except Exception:
            if created:
                root.destroy()
            raise
        self._tk, self._root, self._tray = tk, root, tray
        try:
            self._build()
        except Exception:
            tray.stop()
            if created:
                root.destroy()
            self._tk = self._tray = None
            self._root = None if created else root
            raise

    def _build(self) -> None:
        tk = self._tk
        self._root.title("Ray Cluster Manager")
        self._root.minsize(620, 430)
        self._root.protocol("WM_DELETE_WINDOW", self._request_hide)
        outer = tk.Frame(self._root, bg="#c0c0c0", padx=8, pady=8)
        outer.pack(fill="both", expand=True)
        self._title = tk.Label(
            outer, text="Ray Cluster Manager", bg="#000080", fg="white",
            anchor="w", padx=6, pady=3,
        )
        self._title.pack(fill="x")
        self._nodes = tk.Listbox(
            outer, bg="black", fg="#00ff00", selectbackground="#000080",
            font=("Consolas", 9), activestyle="none",
        )
        self._nodes.pack(fill="both", expand=True, pady=(8, 6))
        self._nodes.bind("<<ListboxSelect>>", self._select_node)
        self._status = tk.Label(
            outer, text="Ready", bg="#c0c0c0", anchor="w", relief="sunken",
        )
        self._status.pack(fill="x", pady=(0, 6))
        groups = (
            (
                ("Start local Ray", CommandKind.START, ()),
                ("Stop local Ray", CommandKind.STOP, ()),
                ("Restart", CommandKind.RESTART, ()),
                ("Status", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.STATUS.value),)),
                ("Settings", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.SETTINGS.value),)),
            ),
            (
                ("Node", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.NODE.value),)),
                ("RDP", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.RDP.value),)),
                ("Cleanup", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.CLEANUP.value),)),
                ("Help", CommandKind.OPEN_SURFACE,
                 (("surface", Surface.HELP.value),)),
                ("Quit", CommandKind.QUIT, ()),
            ),
            (
                ("Enable RDP Host", CommandKind.APPLY_RDP_HOST,
                 (("enabled", True), ("require_nla", True))),
                ("Enable Private Firewall", CommandKind.APPLY_PRIVATE_FIREWALL,
                 (("enabled", True),)),
            ),
        )
        for group in groups:
            buttons = tk.Frame(outer, bg="#c0c0c0")
            buttons.pack(fill="x", pady=(0, 3))
            for label, kind, fields in group:
                button = tk.Button(
                    buttons,
                    text=label,
                    command=lambda k=kind, f=fields: self._emit(k, f),
                    padx=7,
                )
                button.pack(side="left", padx=(0, 4))
                surface_value = dict(fields).get("surface")
                surface = (
                    Surface(surface_value)
                    if isinstance(surface_value, str)
                    else None
                )
                self._buttons.append((button, kind, surface))

    def bind(self, command: Callable[[UiCommand], None]) -> None:
        if not callable(command):
            raise TypeError("command must be callable")
        self._ensure_initialized()
        self._command = command

    def lifecycle_action(self, action: LifecycleAction) -> None:
        self._guard.assert_current()
        if not isinstance(action, LifecycleAction):
            raise TypeError("action must be a LifecycleAction")
        self._ensure_initialized()
        {
            LifecycleAction.WINDOW_CLOSE: self._request_hide,
            LifecycleAction.TRAY_SHOW: self._tray_show,
            LifecycleAction.TRAY_QUIT: self._tray_quit,
        }[action]()

    def render(self, state: RenderState) -> None:
        self._guard.assert_current()
        self._ensure_initialized()
        if not isinstance(state, RenderState):
            raise TypeError("state must be a RenderState")
        self._state = state
        model = self._main_view.render(state)
        self._title.configure(text=model.title)
        self._status.configure(text=model.status)
        self._nodes.delete(0, "end")
        for line in model.node_lines:
            self._nodes.insert("end", line)
        for index, node in enumerate(state.nodes):
            if node.node_id == model.selected_node_id:
                self._nodes.selection_set(index)
                self._nodes.activate(index)
                self._nodes.see(index)
                break
        enabled = {
            (action.command, action.surface): action.enabled
            for action in model.actions
        }
        for button, kind, surface in self._buttons:
            if (kind, surface) in enabled:
                button.configure(
                    state="normal" if enabled[(kind, surface)] else "disabled"
                )
        self._sync_dialogs()
        self._sync_rdp_selection()
        self._tray.set_title(f"Ray Cluster Manager - {model.status}"[:127])

    def set_visibility(self, visibility: UiVisibility) -> None:
        self._guard.assert_current()
        self._ensure_initialized()
        if visibility is UiVisibility.VISIBLE:
            self._root.deiconify()
            self._root.lift()
        elif visibility is UiVisibility.MINIMIZED:
            self._root.iconify()
        elif visibility is UiVisibility.HIDDEN:
            self._root.withdraw()
        else:
            raise TypeError("visibility must be a UiVisibility")

    def call_later(self, delay_ms: int, callback: Callable[[], None]) -> object:
        self._ensure_initialized()
        return self._root.after(delay_ms, callback)

    def cancel(self, token: object) -> None:
        try:
            self._root.after_cancel(token)
        except self._tk.TclError:
            pass

    def run(self) -> int | None:
        self._guard.assert_current()
        self._ensure_initialized()
        self._tray.start()
        try:
            self._root.mainloop()
        finally:
            self._tray.stop()
        return 0

    def quit(self) -> None:
        self._guard.assert_current()
        self._ensure_initialized()
        self._root.quit()

    def dispose(self) -> None:
        self._guard.assert_current()
        if self._tk is None:
            return
        self._invalidate_rdp_preflight(clear_status=False)
        self._tray.stop()
        for dialog in tuple(self._dialogs.values()):
            if dialog.winfo_exists():
                dialog.destroy()
        self._dialogs.clear()
        if self._root.winfo_exists():
            self._root.destroy()
        with self._rdp_probe_threads_lock:
            probes = tuple(self._rdp_probe_threads)
        for probe in probes:
            probe.join(0.25)

    def _emit(
        self,
        kind: CommandKind,
        fields: Fields = (),
    ) -> None:
        if self._command is None:
            raise RuntimeError("desktop command handler is not bound")
        self._sequence += 1
        self._command(UiCommand(self._sequence, kind, fields))

    def _request_hide(self) -> None:
        self._emit(CommandKind.HIDE)

    def _select_node(self, _event: Any = None) -> None:
        selected = self._nodes.curselection()
        if len(selected) != 1:
            return
        index = int(selected[0])
        if not 0 <= index < len(self._state.nodes):
            return
        node_id = self._state.nodes[index].node_id
        if node_id != self._state.selected_node_id:
            self._rdp_probe_generation += 1
            self._emit(CommandKind.SELECT_NODE, (("node_id", node_id),))

    def _tray_show(self) -> None:
        self._root.after(0, lambda: self._emit(CommandKind.SHOW))

    def _tray_quit(self) -> None:
        self._root.after(0, lambda: self._emit(CommandKind.QUIT))

    def _sync_dialogs(self) -> None:
        wanted = set(self._state.open_surfaces)
        for surface in tuple(self._dialogs):
            if surface not in wanted:
                if surface is Surface.RDP:
                    self._invalidate_rdp_preflight(clear_status=False)
                self._dialogs.pop(surface).destroy()
                if surface is Surface.RDP:
                    self._rdp_form = None
        for surface in wanted:
            dialog = self._dialogs.get(surface)
            if dialog is None or not dialog.winfo_exists():
                if surface is Surface.RDP and self._rdp_form is not None:
                    self._invalidate_rdp_preflight(clear_status=False)
                self._dialogs[surface] = self._create_dialog(surface)

    def _create_dialog(self, surface: Surface) -> Any:
        if surface is Surface.RDP:
            return self._create_rdp_dialog()
        dialog = self._tk.Toplevel(self._root)
        dialog.title(_surface_title(surface))
        dialog.minsize(460, 300)
        text = self._tk.Text(
            dialog, wrap="word", padx=10, pady=10, font=("Segoe UI", 9),
        )
        text.pack(fill="both", expand=True)
        text.insert("1.0", self._surface_text(surface))
        text.configure(state="disabled")
        dialog.protocol(
            "WM_DELETE_WINDOW",
            lambda item=surface: self._emit(
                CommandKind.CLOSE_SURFACE,
                (("surface", item.value),),
            ),
        )
        return dialog

    def _selected_node(self) -> Any | None:
        return next(
            (
                node
                for node in self._state.nodes
                if node.node_id == self._state.selected_node_id
            ),
            None,
        )

    def _create_rdp_dialog(self) -> Any:
        tk = self._tk
        dialog = tk.Toplevel(self._root)
        dialog.title("Remote Desktop")
        dialog.minsize(540, 390)
        frame = tk.Frame(dialog, padx=14, pady=14)
        frame.pack(fill="both", expand=True)
        selected = self._selected_node()
        selected_text = tk.StringVar(
            value=(
                f"Selected node: {selected.name} ({selected.role})"
                if selected is not None
                else "Selected node: none — enter a remote address below"
            )
        )
        address = tk.StringVar(value=selected.address if selected else "")
        principal = tk.StringVar(value="")
        port = tk.StringVar(value=str(self._state.rdp_port))
        clipboard = tk.BooleanVar(value=False)
        status = tk.StringVar(value="")
        tk.Label(
            frame,
            text=(
                "RCM opens the Windows Remote Desktop client. Passwords are "
                "entered only in the Windows sign-in window and are never "
                "accepted or stored by RCM."
            ),
            justify="left",
            wraplength=500,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        tk.Label(frame, textvariable=selected_text, anchor="w").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        entries = (
            ("Remote address", address),
            ("Windows user name (optional)", principal),
            ("RDP port", port),
        )
        first_entry = None
        for row, (label, variable) in enumerate(entries, start=2):
            tk.Label(frame, text=label).grid(
                row=row, column=0, sticky="w", padx=(0, 10), pady=3
            )
            entry = tk.Entry(frame, textvariable=variable, width=38)
            entry.grid(row=row, column=1, sticky="ew", pady=3)
            if first_entry is None:
                first_entry = entry
        tk.Checkbutton(
            frame,
            text="Share clipboard with the remote PC",
            variable=clipboard,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 2))
        tk.Label(
            frame,
            text=(
                "The remote PC must support RDP hosting (normally Windows Pro "
                "or higher), have Remote Desktop enabled, and allow this user. "
                "RCM does not change the remote PC."
            ),
            justify="left",
            wraplength=500,
            fg="#404040",
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 6))
        tk.Label(
            frame,
            textvariable=status,
            justify="left",
            wraplength=500,
            fg="#800000",
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 8))
        buttons = tk.Frame(frame)
        buttons.grid(row=8, column=0, columnspan=2, sticky="e")
        connect = tk.Button(buttons, text="Check and connect", width=16)
        connect.pack(side="left", padx=(0, 6))
        anyway = tk.Button(
            buttons,
            text="Connect anyway",
            width=14,
            state="disabled",
        )
        anyway.pack(side="left", padx=(0, 6))
        close = tk.Button(
            buttons,
            text="Close",
            width=10,
            command=lambda: self._close_surface(Surface.RDP),
        )
        close.pack(side="left")
        self._rdp_form = {
            "dialog": dialog,
            "selected_text": selected_text,
            "selected_node_id": self._state.selected_node_id,
            "address": address,
            "principal": principal,
            "port": port,
            "clipboard": clipboard,
            "status": status,
            "connect": connect,
            "anyway": anyway,
            "inflight": False,
            "probe_timer": None,
        }
        for variable in (address, principal, port, clipboard):
            variable.trace_add("write", self._rdp_form_changed)
        connect.configure(command=self._begin_rdp_preflight)
        anyway.configure(command=self._launch_rdp)
        dialog.protocol(
            "WM_DELETE_WINDOW", lambda: self._close_surface(Surface.RDP)
        )
        dialog.bind("<Return>", lambda _event: self._begin_rdp_preflight())
        dialog.bind("<Escape>", lambda _event: self._close_surface(Surface.RDP))
        frame.columnconfigure(1, weight=1)
        first_entry.focus_set()
        return dialog

    def _close_surface(self, surface: Surface) -> None:
        if surface is Surface.RDP:
            self._invalidate_rdp_preflight(clear_status=False)
        self._emit(
            CommandKind.CLOSE_SURFACE,
            (("surface", surface.value),),
        )

    def _sync_rdp_selection(self) -> None:
        form = self._rdp_form
        if form is None:
            return
        selected_id = self._state.selected_node_id
        if form["selected_node_id"] == selected_id:
            return
        self._invalidate_rdp_preflight(clear_status=False)
        form["selected_node_id"] = selected_id
        selected = self._selected_node()
        if selected is None:
            form["selected_text"].set(
                "Selected node: none — enter a remote address below"
            )
        else:
            form["selected_text"].set(
                f"Selected node: {selected.name} ({selected.role})"
            )
            form["address"].set(selected.address)
        form["status"].set("")
        form["connect"].configure(state="normal")
        form["anyway"].configure(state="disabled")

    def _cancel_rdp_probe_timer(self, form: dict[str, Any]) -> None:
        token = form.get("probe_timer")
        form["probe_timer"] = None
        if token is None:
            return
        try:
            self._root.after_cancel(token)
        except Exception:
            pass

    def _invalidate_rdp_preflight(self, *, clear_status: bool = True) -> None:
        self._rdp_probe_generation += 1
        cancellation = getattr(self, "_rdp_probe_cancel", None)
        if cancellation is not None:
            cancellation.set()
        form = self._rdp_form
        if form is None:
            return
        self._cancel_rdp_probe_timer(form)
        form["inflight"] = False
        if clear_status:
            form["status"].set("")
        form["connect"].configure(state="normal")
        form["anyway"].configure(state="disabled")

    def _rdp_form_changed(self, *_args: object) -> None:
        self._invalidate_rdp_preflight()

    def _rdp_draft(self) -> RdpDraft:
        form = self._rdp_form
        if form is None:
            raise ValueError("Remote Desktop dialog is closed")
        try:
            port = int(form["port"].get().strip(), 10)
        except (AttributeError, ValueError):
            raise ValueError("RDP port must be a number from 1 to 65535") from None
        return RdpDraft(
            address=form["address"].get().strip(),
            principal=form["principal"].get().strip(),
            port=port,
            redirect_clipboard=bool(form["clipboard"].get()),
        )

    def _begin_rdp_preflight(self) -> None:
        form = self._rdp_form
        if form is None:
            return
        if form.get("inflight"):
            return
        with self._rdp_probe_threads_lock:
            active_probe = any(
                thread.is_alive() for thread in self._rdp_probe_threads
            )
        if active_probe:
            form["status"].set(
                "The previous RDP check is still finishing. Try again shortly."
            )
            form["connect"].configure(state="normal")
            form["anyway"].configure(state="disabled")
            return
        try:
            draft = self._rdp_draft()
        except (TypeError, ValueError) as exc:
            form["status"].set(str(exc))
            form["connect"].configure(state="normal")
            form["anyway"].configure(state="disabled")
            return
        self._rdp_probe_generation += 1
        generation = self._rdp_probe_generation
        form["status"].set("Checking the RDP port…")
        form["connect"].configure(state="disabled")
        form["anyway"].configure(state="disabled")
        form["inflight"] = True
        timeout = float(self._state.rdp_connect_timeout_seconds)
        cancellation = Event() if self._rdp_probe_is_default else None
        self._rdp_probe_cancel = cancellation
        form["probe_timer"] = self._root.after(
            max(1, math.ceil(timeout * 1_000)),
            lambda: self._expire_rdp_preflight(generation, draft),
        )

        def probe() -> None:
            try:
                if cancellation is None:
                    reachable = bool(
                        self._rdp_probe(draft.address, draft.port, timeout)
                    )
                else:
                    reachable = bool(self._rdp_probe(
                        draft.address,
                        draft.port,
                        timeout,
                        cancellation=cancellation,
                    ))
            except Exception:
                reachable = False
            try:
                self._root.after(
                    0,
                    lambda: self._finish_rdp_preflight(
                        generation, draft, reachable
                    ),
                )
            except Exception:
                pass
            finally:
                with self._rdp_probe_threads_lock:
                    self._rdp_probe_threads.discard(current_thread())
                    if self._rdp_probe_cancel is cancellation:
                        self._rdp_probe_cancel = None

        thread = Thread(
            target=probe,
            name="rcm-rdp-preflight",
            daemon=True,
        )
        with self._rdp_probe_threads_lock:
            self._rdp_probe_threads.add(thread)
        try:
            thread.start()
        except Exception:
            with self._rdp_probe_threads_lock:
                self._rdp_probe_threads.discard(thread)
                if self._rdp_probe_cancel is cancellation:
                    self._rdp_probe_cancel = None
            self._finish_rdp_preflight(generation, draft, False)

    def _expire_rdp_preflight(
        self,
        generation: int,
        draft: RdpDraft,
    ) -> None:
        form = self._rdp_form
        if form is None or generation != self._rdp_probe_generation:
            return
        try:
            current = self._rdp_draft()
        except (TypeError, ValueError) as exc:
            self._invalidate_rdp_preflight(clear_status=False)
            form["status"].set(str(exc))
            return
        if current != draft:
            self._invalidate_rdp_preflight(clear_status=False)
            form["status"].set(
                "Connection details changed. Check the current values again."
            )
            return
        self._rdp_probe_generation += 1
        form["probe_timer"] = None
        form["inflight"] = False
        form["connect"].configure(state="normal")
        form["anyway"].configure(state="normal")
        form["status"].set(
            "The RDP port check timed out. Check the PC, VPN, firewall, "
            "address, and port. You may still ask Windows to connect."
        )

    def _finish_rdp_preflight(
        self,
        generation: int,
        draft: RdpDraft,
        reachable: bool,
    ) -> None:
        form = self._rdp_form
        if form is None or generation != self._rdp_probe_generation:
            return
        dialog = form["dialog"]
        if not dialog.winfo_exists():
            return
        try:
            current = self._rdp_draft()
        except (TypeError, ValueError) as exc:
            self._invalidate_rdp_preflight(clear_status=False)
            form["status"].set(str(exc))
            return
        if current != draft:
            self._invalidate_rdp_preflight(clear_status=False)
            form["status"].set(
                "Connection details changed. Check the current values again."
            )
            return
        self._cancel_rdp_probe_timer(form)
        form["inflight"] = False
        form["connect"].configure(state="normal")
        if reachable:
            form["status"].set("RDP port is reachable. Opening Windows…")
            self._launch_rdp(draft)
        else:
            form["status"].set(
                "The RDP port did not answer. Check the PC, VPN, firewall, "
                "address, and port. You may still ask Windows to connect."
            )
            form["anyway"].configure(state="normal")

    def _launch_rdp(self, draft: RdpDraft | None = None) -> None:
        form = self._rdp_form
        if form is None:
            return
        try:
            selected = self._rdp_draft() if draft is None else draft
        except (TypeError, ValueError) as exc:
            form["status"].set(str(exc))
            return
        self._rdp_probe_generation += 1
        form["status"].set("Opening Windows Remote Desktop…")
        form["anyway"].configure(state="disabled")
        self._emit(
            CommandKind.OPEN_RDP,
            (
                ("address", selected.address),
                ("principal", selected.principal),
                ("port", selected.port),
                ("redirect_clipboard", selected.redirect_clipboard),
            ),
        )
        result = self._state.last_result
        if result is not None and result.code in {
            "rdp_opened",
            "rdp_unavailable",
            "rdp_request_invalid",
        }:
            form["status"].set(result.message)

    def _surface_text(self, surface: Surface) -> str:
        if surface is Surface.STATUS:
            board = self._status_view.render(self._state)
            return "\n".join((board.headline, "", *board.lines))
        if surface is Surface.SETTINGS:
            settings = self._state.settings
            return (
                "Appearance\n"
                f"Theme: {settings.theme}\nScale: {settings.scale_percent}%\n"
                f"Compact view: {settings.compact_view}\n\n"
                "Monitoring\n"
                f"Interval: {settings.monitoring_interval_ms} ms\n\n"
                "Startup\n"
                f"Start minimized: {settings.start_minimized}\n"
                f"Autostart: {settings.autostart}"
            )
        if surface is Surface.RDP:
            return (
                "Remote Desktop\n\nSelect a node or enter a remote address.\n"
                "Passwords are entered only in the Windows sign-in window.\n"
                "RCM does not configure the remote host."
            )
        if surface is Surface.CLEANUP:
            return (
                "Local Process Cleanup\n\nScan first, review identity-bound "
                "candidates, then apply only the selected rows."
            )
        if surface is Surface.NODE:
            return "\n".join(("Node details", *(
                f"{node.name}: {node.role} / {node.status}"
                for node in self._state.nodes
            )))
        document = parse_help(read_help_bytes())
        return "\n\n".join(
            (document.title, *(
                f"{section.title}\n{section.body}" for section in document.sections
            ))
        )


def _surface_title(surface: Surface) -> str:
    return {
        Surface.STATUS: "Cluster Status",
        Surface.SETTINGS: "Settings",
        Surface.NODE: "Node",
        Surface.RDP: "Remote Desktop",
        Surface.CLEANUP: "Process Cleanup",
        Surface.HELP: "Help",
        Surface.MAIN: "Ray Cluster Manager",
    }[surface]


class _PystrayTray:
    def __init__(self, icon: Any) -> None:
        self._icon = icon

    def start(self) -> None:
        self._icon.run_detached()

    def set_title(self, title: str) -> None:
        self._icon.title = title

    def stop(self) -> None:
        self._icon.stop()


def _default_tray(show: Callable[[], None], quit_: Callable[[], None]) -> _Tray:
    from PIL import Image, ImageDraw
    import pystray

    image = Image.new("RGB", (32, 32), "#c0c0c0")
    draw = ImageDraw.Draw(image)
    draw.rectangle((3, 3, 28, 28), fill="#000080", outline="black")
    draw.text((9, 8), "R", fill="white")
    icon = pystray.Icon(
        "ray_cluster_manager",
        image,
        "Ray Cluster Manager",
        pystray.Menu(
            pystray.MenuItem("Show", lambda _icon, _item: show(), default=True),
            pystray.MenuItem("Quit", lambda _icon, _item: quit_()),
        ),
    )
    return _PystrayTray(icon)


def _tcp_rdp_probe(
    address: str,
    port: int,
    timeout_seconds: float,
    *,
    cancellation: Event | None = None,
) -> bool:
    """Probe one numeric IP with a cancellable, data-free TCP connect."""

    import errno
    import ipaddress
    import select
    import socket

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("RDP probe timeout must be finite and positive")
    if cancellation is not None and not isinstance(cancellation, Event):
        raise TypeError("RDP probe cancellation must be an Event")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    endpoint: tuple[Any, ...] = (
        (str(ip), port, 0, 0) if ip.version == 6 else (str(ip), port)
    )
    pending = {
        errno.EINPROGRESS,
        errno.EWOULDBLOCK,
        errno.EALREADY,
        10035,  # WSAEWOULDBLOCK
        10036,  # WSAEINPROGRESS
        10037,  # WSAEALREADY
    }
    deadline = time.monotonic() + float(timeout_seconds)
    connection = None
    try:
        if cancellation is not None and cancellation.is_set():
            return False
        connection = socket.socket(
            family,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
        connection.setblocking(False)
        error = int(connection.connect_ex(endpoint))
        if error == 0:
            return True
        if error not in pending:
            return False
        while True:
            if cancellation is not None and cancellation.is_set():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            _readable, writable, exceptional = select.select(
                (),
                (connection,),
                (connection,),
                min(0.05, remaining),
            )
            if not writable and not exceptional:
                continue
            return int(connection.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ERROR,
            )) == 0
    except OSError:
        return False
    finally:
        if connection is not None:
            connection.close()


__all__ = (
    "ExactOwnedFallback",
    "TkDesktopHost",
    "WindowsAutostart",
    "WindowsSingleton",
)
