"""Lazy, import-safe Windows desktop adapters."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PureWindowsPath
from threading import Lock
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
        raise OSError(ctypes.get_last_error(), "CreateMutexW failed")
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
    ) -> None:
        self._root = root
        self._tk: Any | None = None
        self._guard = UiThreadGuard() if thread_guard is None else thread_guard
        self._command: Callable[[UiCommand], None] | None = None
        self._sequence = 0
        self._dialogs: dict[Surface, Any] = {}
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
        self._status = tk.Label(
            outer, text="Ready", bg="#c0c0c0", anchor="w", relief="sunken",
        )
        self._status.pack(fill="x", pady=(0, 6))
        groups = (
            (
                ("Start", CommandKind.START, ()),
                ("Stop", CommandKind.STOP, ()),
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
                tk.Button(
                    buttons,
                    text=label,
                    command=lambda k=kind, f=fields: self._emit(k, f),
                    padx=7,
                ).pack(side="left", padx=(0, 4))

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
        self._sync_dialogs()
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
        self._tray.stop()
        for dialog in tuple(self._dialogs.values()):
            if dialog.winfo_exists():
                dialog.destroy()
        self._dialogs.clear()
        if self._root.winfo_exists():
            self._root.destroy()

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

    def _tray_show(self) -> None:
        self._root.after(0, lambda: self._emit(CommandKind.SHOW))

    def _tray_quit(self) -> None:
        self._root.after(0, lambda: self._emit(CommandKind.QUIT))

    def _sync_dialogs(self) -> None:
        wanted = set(self._state.open_surfaces)
        for surface in tuple(self._dialogs):
            if surface not in wanted:
                self._dialogs.pop(surface).destroy()
        for surface in wanted:
            dialog = self._dialogs.get(surface)
            if dialog is None or not dialog.winfo_exists():
                self._dialogs[surface] = self._create_dialog(surface)

    def _create_dialog(self, surface: Surface) -> Any:
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
                "Remote Desktop\n\nSelect a node in the main window.\n"
                "Credentials are referenced by an opaque stored reference.\n"
                "Remote password entry is intentionally unavailable."
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


__all__ = (
    "ExactOwnedFallback",
    "TkDesktopHost",
    "WindowsAutostart",
    "WindowsSingleton",
)
