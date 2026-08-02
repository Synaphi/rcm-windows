from __future__ import annotations

import asyncio
import ctypes
import multiprocessing.context
import multiprocessing.process
import multiprocessing.util
import os
import socket
import subprocess
import sys
import threading
from typing import Any
from unittest import mock


if os.name == "nt":
    import _winapi
    from multiprocessing import popen_spawn_win32

    _MULTIPROCESSING_POPEN_BY_START_METHOD = {
        "spawn": popen_spawn_win32,
    }
    _PROCESS_CREATION_PRIMITIVES = (
        (_winapi, "CreatePipe"),
        (_winapi, "CreateProcess"),
    )
else:
    import _posixsubprocess
    from multiprocessing import (
        popen_fork,
        popen_forkserver,
        popen_spawn_posix,
    )

    _MULTIPROCESSING_POPEN_BY_START_METHOD = {
        "fork": popen_fork,
        "forkserver": popen_forkserver,
        "spawn": popen_spawn_posix,
    }
    _PROCESS_CREATION_PRIMITIVES = (
        (_posixsubprocess, "fork_exec"),
        (multiprocessing.util, "spawnv_passfds"),
    )


FORBIDDEN_USER_ENVIRONMENT_KEYS = frozenset(
    {
        "APPDATA",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "USERPROFILE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "XDG_STATE_HOME",
    }
)


class ForbiddenLiveAccessError(RuntimeError):
    pass


_ACTIVE_GUARDS: set[NoLiveAccessGuard] = set()
_AUDIT_HOOK_INSTALLED = False
_AUDIT_PROBE_EVENT = "rcm.fake_test_kit.guard_probe"
_AUDIT_PROBE_GENERATION = 0
_GUARD_STATE_LOCK = threading.RLock()
_FORBIDDEN_AUDIT_EVENTS = frozenset(
    {
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.putenv",
        "os.spawn",
        "os.startfile",
        "os.startfile/2",
        "os.system",
        "os.unsetenv",
        "socket.__new__",
        "socket.bind",
        "socket.connect",
        "socket.getaddrinfo",
        "socket.gethostbyaddr",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostname",
        "socket.getnameinfo",
        "socket.getservbyname",
        "socket.getservbyport",
        "socket.sendmsg",
        "socket.sendto",
        "subprocess.Popen",
    }
)


def _audit_live_access(event: str, _arguments: tuple[object, ...]) -> None:
    global _AUDIT_PROBE_GENERATION
    if event == _AUDIT_PROBE_EVENT:
        _AUDIT_PROBE_GENERATION += 1
        return
    if event not in _FORBIDDEN_AUDIT_EVENTS:
        return
    for guard in tuple(_ACTIVE_GUARDS):
        guard._deny(f"audit:{event}")


def _ensure_audit_hook() -> None:
    global _AUDIT_HOOK_INSTALLED
    before = _AUDIT_PROBE_GENERATION
    if not _AUDIT_HOOK_INSTALLED:
        # CPython audit hooks cannot be removed. Outside an active guard this
        # installed hook sees an empty set and is deliberately dormant.
        sys.addaudithook(_audit_live_access)
    sys.audit(_AUDIT_PROBE_EVENT, before)
    if _AUDIT_PROBE_GENERATION != before + 1:
        _AUDIT_HOOK_INSTALLED = False
        raise RuntimeError("no-live-access audit hook self-probe failed")
    if not _AUDIT_HOOK_INSTALLED:
        _AUDIT_HOOK_INSTALLED = True


def _environment_key_name(key: object) -> str | None:
    if isinstance(key, bytes):
        try:
            return os.fsdecode(key).upper()
        except UnicodeError:
            return None
    if isinstance(key, str):
        return key.upper()
    return None


class NoLiveAccessGuard:
    def __init__(self) -> None:
        self.violations: list[str] = []
        self._patchers: list[Any] = []
        self._active = False
        self._environment = os.environ
        self._environment_type = type(self._environment)
        self._environment_getitem = self._environment_type.__getitem__
        self._environment_setitem = self._environment_type.__setitem__
        self._environment_delitem = self._environment_type.__delitem__
        self._saved_environment: list[tuple[object, object]] = []

    @property
    def active(self) -> bool:
        return self._active

    def _deny(self, label: str) -> None:
        self.violations.append(label)
        raise ForbiddenLiveAccessError(
            f"deterministic tests forbid {label}"
        )

    def _blocked(self, label: str) -> Any:
        def blocked(*_args: Any, **_kwargs: Any) -> Any:
            self._deny(label)

        return blocked

    def _check_environment_key(self, key: object) -> None:
        name = _environment_key_name(key)
        if name in FORBIDDEN_USER_ENVIRONMENT_KEYS:
            self._deny(f"environment:{name}")

    def _guarded_environment_getitem(
        self,
        environment: object,
        key: object,
    ) -> str:
        self._check_environment_key(key)
        return self._environment_getitem(environment, key)

    def _guarded_environment_setitem(
        self,
        environment: object,
        key: object,
        value: object,
    ) -> None:
        self._check_environment_key(key)
        self._environment_setitem(environment, key, value)

    def _guarded_environment_delitem(
        self,
        environment: object,
        key: object,
    ) -> None:
        self._check_environment_key(key)
        self._environment_delitem(environment, key)

    def _strip_forbidden_environment(self) -> None:
        self._saved_environment.clear()
        for key in list(self._environment):
            if _environment_key_name(key) in FORBIDDEN_USER_ENVIRONMENT_KEYS:
                value = self._environment_getitem(self._environment, key)
                self._saved_environment.append((key, value))
                self._environment_delitem(self._environment, key)

    def _restore_forbidden_environment(self) -> None:
        pending = list(self._saved_environment)
        first_error: BaseException | None = None
        for _attempt in range(3):
            retry = []
            for key, value in pending:
                try:
                    self._environment_setitem(self._environment, key, value)
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                    retry.append((key, value))
            pending = retry
            if not pending:
                self._saved_environment.clear()
                return
        self._saved_environment = pending
        raise RuntimeError(
            "no-live-access guard could not restore environment"
        ) from first_error

    def _build_patchers(self) -> list[Any]:
        def guarded_environment_getitem(
            environment: object,
            key: object,
        ) -> str:
            return self._guarded_environment_getitem(environment, key)

        def guarded_environment_setitem(
            environment: object,
            key: object,
            value: object,
        ) -> None:
            self._guarded_environment_setitem(environment, key, value)

        def guarded_environment_delitem(
            environment: object,
            key: object,
        ) -> None:
            self._guarded_environment_delitem(environment, key)

        patchers = [
            mock.patch.object(socket, "socket", self._blocked("socket")),
            mock.patch.object(
                socket,
                "create_connection",
                self._blocked("socket.create_connection"),
            ),
            mock.patch.object(
                subprocess,
                "Popen",
                self._blocked("subprocess.Popen"),
            ),
            mock.patch.object(
                subprocess,
                "run",
                self._blocked("subprocess.run"),
            ),
            mock.patch.object(
                subprocess,
                "call",
                self._blocked("subprocess.call"),
            ),
            mock.patch.object(
                subprocess,
                "check_call",
                self._blocked("subprocess.check_call"),
            ),
            mock.patch.object(
                subprocess,
                "check_output",
                self._blocked("subprocess.check_output"),
            ),
            mock.patch.object(os, "system", self._blocked("os.system")),
            mock.patch.object(os, "popen", self._blocked("os.popen")),
            mock.patch.object(
                multiprocessing.process.BaseProcess,
                "start",
                self._blocked("multiprocessing.Process.start"),
            ),
            mock.patch.object(
                asyncio,
                "create_subprocess_exec",
                self._blocked("asyncio.create_subprocess_exec"),
            ),
            mock.patch.object(
                asyncio,
                "create_subprocess_shell",
                self._blocked("asyncio.create_subprocess_shell"),
            ),
            mock.patch.object(
                self._environment_type,
                "__getitem__",
                guarded_environment_getitem,
            ),
            mock.patch.object(
                self._environment_type,
                "__setitem__",
                guarded_environment_setitem,
            ),
            mock.patch.object(
                self._environment_type,
                "__delitem__",
                guarded_environment_delitem,
            ),
        ]
        if hasattr(ctypes, "WinDLL"):
            patchers.append(
                mock.patch.object(
                    ctypes,
                    "WinDLL",
                    self._blocked("ctypes.WinDLL"),
                )
            )
        if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "LoadLibrary"):
            patchers.append(
                mock.patch.object(
                    ctypes.windll,
                    "LoadLibrary",
                    self._blocked("ctypes.windll.LoadLibrary"),
                )
            )
        for name in (
            "create_server",
            "getaddrinfo",
            "gethostbyaddr",
            "gethostbyname",
            "gethostbyname_ex",
            "gethostname",
            "getnameinfo",
            "getservbyname",
            "getservbyport",
            "socketpair",
        ):
            if hasattr(socket, name):
                patchers.append(
                    mock.patch.object(
                        socket,
                        name,
                        self._blocked(f"socket.{name}"),
                    )
                )
        process_classes = []
        for name in (
            "Process",
            "SpawnProcess",
            "ForkProcess",
            "ForkServerProcess",
        ):
            process_class = getattr(multiprocessing.context, name, None)
            if (
                process_class is not None
                and process_class not in process_classes
                and hasattr(process_class, "_Popen")
            ):
                process_classes.append(process_class)
        for process_class in process_classes:
            patchers.append(
                mock.patch.object(
                    process_class,
                    "_Popen",
                    staticmethod(
                        self._blocked(
                            f"multiprocessing.{process_class.__name__}._Popen"
                        )
                    ),
                )
            )
        for method, popen_module in sorted(
            _MULTIPROCESSING_POPEN_BY_START_METHOD.items()
        ):
            patchers.append(
                mock.patch.object(
                    popen_module,
                    "Popen",
                    self._blocked(f"multiprocessing.{method}.Popen"),
                )
            )
        for module, name in _PROCESS_CREATION_PRIMITIVES:
            patchers.append(
                mock.patch.object(
                    module,
                    name,
                    self._blocked(f"process-primitive.{name}"),
                )
            )
        for name in (
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "fork",
            "forkpty",
            "pipe",
            "pipe2",
            "posix_spawn",
            "posix_spawnp",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
            "startfile",
            "putenv",
            "unsetenv",
        ):
            if hasattr(os, name):
                patchers.append(
                    mock.patch.object(
                        os,
                        name,
                        self._blocked(f"os.{name}"),
                    )
                )
        return patchers

    def __enter__(self) -> NoLiveAccessGuard:
        with _GUARD_STATE_LOCK:
            if self._active:
                raise RuntimeError("no-live-access guard is not reentrant")
            if _ACTIVE_GUARDS:
                raise RuntimeError("no-live-access guards must not overlap")
            _ensure_audit_hook()
            self.violations.clear()
            started = []
            try:
                self._strip_forbidden_environment()
                self._patchers = self._build_patchers()
                _ACTIVE_GUARDS.add(self)
                for patcher in self._patchers:
                    patcher.start()
                    started.append(patcher)
            except BaseException as primary_error:
                _ACTIVE_GUARDS.discard(self)
                cleanup_error: BaseException | None = None
                for patcher in reversed(started):
                    try:
                        patcher.stop()
                    except BaseException as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                self._patchers.clear()
                try:
                    self._restore_forbidden_environment()
                except BaseException as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
                self._active = False
                if cleanup_error is not None:
                    raise cleanup_error from primary_error
                raise
            self._active = True
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object | None,
    ) -> bool:
        with _GUARD_STATE_LOCK:
            _ACTIVE_GUARDS.discard(self)
            first_error: BaseException | None = None
            for patcher in reversed(self._patchers):
                try:
                    patcher.stop()
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
            self._patchers.clear()
            try:
                self._restore_forbidden_environment()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            self._active = False
        if first_error is not None:
            raise first_error
        return False

    def resource_count(self) -> int:
        return len(self._patchers) + len(self._saved_environment)
