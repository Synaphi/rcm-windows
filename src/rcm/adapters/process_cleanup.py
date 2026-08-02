"""Lazy psutil adapter for the local cleanup facade."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Any, Callable

from ..cleanup import ProcessIdentity, ProcessObservation
from ..core import ConflictError, PermissionDeniedError, UnavailableError


def owner_token(
    principal: str, *, case_sensitive: bool | None = None,
) -> str:
    """Return a process-local comparison token for a local principal."""
    if type(principal) is not str or not principal:
        raise ValueError("principal must be a non-empty string")
    if case_sensitive is None:
        import sys
        case_sensitive = sys.platform != "win32"
    if type(case_sensitive) is not bool:
        raise TypeError("case_sensitive must be a bool or None")
    normalized = principal if case_sensitive else principal.casefold()
    encoded = normalized.encode("utf-8", errors="strict")
    return hashlib.sha256(encoded).hexdigest()


def command_fingerprint(arguments: tuple[str, ...]) -> str:
    """Hash argv without retaining or returning command text."""

    if (type(arguments) is not tuple or not arguments
            or any(type(argument) is not str for argument in arguments)):
        raise ValueError("arguments must be a non-empty tuple of strings")
    digest = hashlib.sha256()
    for argument in arguments:
        encoded = argument.encode("utf-8", errors="surrogatepass")
        digest.update(struct.pack(">Q", len(encoded)))
        digest.update(encoded)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class LocalCleanupContext:
    owner_token: str
    session_id: int


class PsutilProcessCleanupBackend:
    """PID-specific process operations with lazy host-library access."""

    def __init__(
        self, *, local_context: LocalCleanupContext,
        psutil_module: Any | None = None,
        session_reader: Callable[[int], int] | None = None,
    ) -> None:
        self._local_context = local_context
        self._psutil_module = psutil_module
        self._session_reader = session_reader

    @classmethod
    def for_current_session(
        cls, *, psutil_module: Any | None = None,
        session_reader: Callable[[int], int] | None = None,
    ) -> PsutilProcessCleanupBackend:
        if psutil_module is None:
            import psutil as psutil_module
        import os

        reader = session_reader or _native_session_id
        process = psutil_module.Process()
        try:
            principal = process.username()
            session_id = reader(os.getpid())
        except psutil_module.AccessDenied:
            raise PermissionDeniedError(
                "permission is required to identify the local process session"
            ) from None
        except (OSError, RuntimeError):
            raise UnavailableError("the local process session is unavailable") from None
        return cls(
            local_context=LocalCleanupContext(
                owner_token=owner_token(principal),
                session_id=session_id,
            ),
            psutil_module=psutil_module,
            session_reader=reader,
        )

    @property
    def local_context(self) -> LocalCleanupContext:
        return self._local_context

    def _psutil(self) -> Any:
        if self._psutil_module is None:
            import psutil

            self._psutil_module = psutil
        return self._psutil_module

    def _session(self, pid: int) -> int:
        reader = self._session_reader or _native_session_id
        return reader(pid)

    def scan(self, limit: int) -> tuple[ProcessObservation, ...]:
        if type(limit) is not int or limit <= 0:
            raise ValueError("limit must be a positive integer")
        psutil = self._psutil()
        observations: list[ProcessObservation] = []
        attributes = ("pid", "create_time", "name", "username", "cmdline")
        try:
            processes = psutil.process_iter(attrs=attributes)
            for process in processes:
                try:
                    info = process.info
                    principal = info.get("username")
                    if (type(principal) is not str or owner_token(principal)
                            != self._local_context.owner_token):
                        continue
                    pid = info.get("pid")
                    if type(pid) is not int:
                        continue
                    session_id = self._session(pid)
                    if session_id != self._local_context.session_id:
                        continue
                    arguments = info.get("cmdline")
                    if not isinstance(arguments, (list, tuple)) or not arguments:
                        continue
                    argv = tuple(arguments)
                    if any(type(argument) is not str for argument in argv):
                        continue
                    connection_reader = getattr(
                        process, "net_connections", None
                    ) or process.connections
                    connections = connection_reader(kind="inet")
                    identity = _identity_from_info(
                        info, owner=owner_token(principal), session_id=session_id
                    )
                    observations.append(
                        ProcessObservation(
                            identity=identity,
                            command_fingerprint=command_fingerprint(argv),
                            connection_count=len(connections),
                        )
                    )
                    if len(observations) >= limit:
                        break
                except (
                    psutil.NoSuchProcess, psutil.ZombieProcess,
                    psutil.AccessDenied, OSError,
                ):
                    continue
        except (OSError, RuntimeError):
            raise UnavailableError("local process scan is unavailable") from None
        return tuple(observations)

    def inspect(self, pid: int) -> ProcessIdentity | None:
        if type(pid) is not int or pid <= 0:
            raise ValueError("pid must be a positive integer")
        psutil = self._psutil()
        try:
            process = psutil.Process(pid)
            return self._identity(process, pid)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except psutil.AccessDenied:
            raise PermissionDeniedError(
                "permission is required to inspect the process"
            ) from None
        except (OSError, RuntimeError):
            raise UnavailableError("process identity is unavailable") from None

    def request_graceful(self, expected: ProcessIdentity) -> bool:
        return self._signal(expected, force=False)

    def force(self, expected: ProcessIdentity) -> bool:
        return self._signal(expected, force=True)

    def _signal(self, expected: ProcessIdentity, *, force: bool) -> bool:
        if not isinstance(expected, ProcessIdentity):
            raise TypeError("expected must be a ProcessIdentity")
        psutil = self._psutil()
        try:
            process = psutil.Process(expected.pid)
            if self._identity(process, expected.pid) != expected:
                raise ConflictError("process identity changed")
            if force:
                process.kill()
            else:
                process.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return False
        except psutil.AccessDenied:
            raise PermissionDeniedError(
                "permission is required for the process operation"
            ) from None
        except (OSError, RuntimeError):
            raise UnavailableError("process operation is unavailable") from None

    def _identity(self, process: Any, pid: int) -> ProcessIdentity:
        principal = process.username()
        return ProcessIdentity(
            pid=pid,
            create_time=process.create_time(),
            image_name=_basename(process.name()),
            owner_token=owner_token(principal),
            session_id=self._session(pid),
        )

    def wait(self, pid: int, timeout_seconds: float) -> bool:
        if type(pid) is not int or pid <= 0:
            raise ValueError("pid must be a positive integer")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or timeout_seconds < 0):
            raise ValueError("timeout_seconds must be non-negative")
        psutil = self._psutil()
        try:
            psutil.Process(pid).wait(timeout=timeout_seconds)
            return True
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return True
        except psutil.TimeoutExpired:
            return False
        except psutil.AccessDenied:
            raise PermissionDeniedError(
                "permission is required to wait for the process"
            ) from None
        except (OSError, RuntimeError):
            raise UnavailableError("process wait is unavailable") from None


def _identity_from_info(
    info: dict[str, object], *, owner: str, session_id: int
) -> ProcessIdentity:
    pid = info.get("pid")
    create_time = info.get("create_time")
    name = info.get("name")
    if type(pid) is not int:
        raise ValueError("process id is unavailable")
    if not isinstance(create_time, (int, float)):
        raise ValueError("process create time is unavailable")
    if type(name) is not str or not name:
        raise ValueError("process image name is unavailable")
    return ProcessIdentity(
        pid=pid,
        create_time=float(create_time),
        image_name=_basename(name),
        owner_token=owner,
        session_id=session_id,
    )


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _native_session_id(pid: int) -> int:
    import sys

    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        session_id = wintypes.DWORD()
        if not ctypes.windll.kernel32.ProcessIdToSessionId(
            wintypes.DWORD(pid),
            ctypes.byref(session_id),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "ProcessIdToSessionId failed")
        return int(session_id.value)

    import os

    return int(os.getsid(pid))


__all__ = [
    "LocalCleanupContext", "PsutilProcessCleanupBackend",
    "command_fingerprint", "owner_token",
]
