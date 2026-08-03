"""Lazy Windows host adapters."""

from __future__ import annotations

import ntpath
from pathlib import PureWindowsPath
import re
from typing import Any, Callable

from ..core import (
    Capability,
    CapabilityState,
    UnavailableError,
    UnsupportedError,
)
from ..rdp import RdpLaunchPlan, RdpLaunchReceipt
from ..ports import FileKind, FileStat, Filesystem


_OWNED_RDP_FILE = re.compile(r"rcm_rdp_[0-9a-f]{32}\.rdp")


def _absolute_local_windows_path(value: str, *, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} must be a safe non-empty path")
    path = PureWindowsPath(value)
    folded = value.replace("/", "\\").casefold()
    if (
        not path.is_absolute()
        or path.anchor.startswith("\\\\")
        or folded.startswith(("\\\\?\\", "\\\\.\\", "\\??\\"))
        or any(part == ".." for part in path.parts)
        or any(":" in part for part in path.parts[1:])
        or any(part.endswith((" ", ".")) for part in path.parts[1:])
    ):
        raise ValueError(f"{label} must be one absolute local path")
    return str(path)


class LocalRdpFilesystem:
    """Restrict artifact I/O to the application's dedicated RDP directory."""

    def __init__(self, directory: str) -> None:
        self._directory = _absolute_local_windows_path(
            directory, label="RDP directory"
        )

    def _path(self, value: str) -> str:
        normalized = _absolute_local_windows_path(value, label="RDP artifact")
        if (
            ntpath.dirname(normalized).casefold() != self._directory.casefold()
            or _OWNED_RDP_FILE.fullmatch(ntpath.basename(normalized)) is None
        ):
            raise ValueError("RDP artifact is outside the owned directory")
        return normalized

    def stat(self, path: str) -> FileStat:
        import os

        owned = self._path(path)
        value = os.stat(owned, follow_symlinks=False)
        kind = FileKind.FILE if os.path.isfile(owned) else FileKind.OTHER
        return FileStat(
            owned,
            kind,
            value.st_size,
            value.st_mtime_ns,
            f"{value.st_dev}:{value.st_ino}",
        )

    def read_bytes(self, path: str, *, limit: int) -> bytes:
        if type(limit) is not int or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        with open(self._path(path), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("RDP artifact exceeds the read limit")
        return data

    def write_bytes(self, path: str, data: bytes) -> None:
        import os

        if not isinstance(data, bytes):
            raise TypeError("RDP artifact data must be bytes")
        with open(self._path(path), "xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def replace(self, source: str, destination: str) -> None:
        import os

        os.replace(self._path(source), self._path(destination))

    def unlink(self, path: str, *, missing_ok: bool = False) -> None:
        import os

        try:
            os.unlink(self._path(path))
        except FileNotFoundError:
            if not missing_ok:
                raise

    def listdir(self, path: str) -> tuple[str, ...]:
        import os

        normalized = _absolute_local_windows_path(path, label="RDP directory")
        if normalized.casefold() != self._directory.casefold():
            raise ValueError("RDP directory is outside the owned directory")
        return tuple(sorted(os.listdir(normalized)))


class WindowsRdpLauncher:
    """Launch ``mstsc.exe`` with an argv tuple and no credential material."""

    def __init__(
        self,
        *,
        filesystem: Filesystem,
        directory: str,
        executable: str | None = None,
        process_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._filesystem = filesystem
        self._directory = _absolute_local_windows_path(
            directory, label="RDP directory"
        )
        self._executable = (
            None
            if executable is None
            else _absolute_local_windows_path(
                executable, label="Remote Desktop executable"
            )
        )
        if self._executable is not None and (
            ntpath.basename(self._executable).casefold() != "mstsc.exe"
        ):
            raise ValueError("Remote Desktop executable must be mstsc.exe")
        self._process_factory = process_factory
        self._issued: dict[int, RdpLaunchReceipt] = {}
        self._residual_paths: set[str] = set()
        self._inventory_unavailable = False
        self._cleanup_ready = True

    def _mstsc_path(self) -> str:
        if self._executable is not None:
            return self._executable
        import ctypes
        from ctypes import wintypes

        buffer = ctypes.create_unicode_buffer(32_768)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_directory = kernel32.GetSystemDirectoryW
        get_directory.argtypes = (wintypes.LPWSTR, wintypes.UINT)
        get_directory.restype = wintypes.UINT
        length = get_directory(buffer, len(buffer))
        if not length or length >= len(buffer):
            raise OSError(ctypes.get_last_error(), "GetSystemDirectoryW failed")
        return _absolute_local_windows_path(
            ntpath.join(buffer.value, "mstsc.exe"),
            label="Remote Desktop executable",
        )

    def capability(self) -> Capability:
        import sys

        if sys.platform != "win32":
            return Capability(
                "rdp",
                CapabilityState.UNSUPPORTED,
                "windows_only",
            )
        if not self._cleanup_ready:
            return Capability(
                "rdp",
                CapabilityState.UNAVAILABLE,
                "artifact_cleanup_failed",
            )
        import os

        try:
            executable = self._mstsc_path()
        except Exception:
            executable = ""
        if not executable or not os.path.isfile(executable):
            return Capability(
                "rdp",
                CapabilityState.UNAVAILABLE,
                "native_client_missing",
            )
        return Capability("rdp", CapabilityState.AVAILABLE)

    def launch(self, plan: RdpLaunchPlan) -> RdpLaunchReceipt:
        if not isinstance(plan, RdpLaunchPlan):
            raise TypeError("plan must be an RdpLaunchPlan")
        if not self._cleanup_ready:
            raise UnavailableError("the RDP artifact directory is unavailable")
        factory = self._process_factory
        if factory is None:
            import sys

            if sys.platform != "win32":
                raise UnsupportedError(
                    "the native RDP launcher is available only on Windows"
                )
            import subprocess

            factory = subprocess.Popen
        artifact_path = ntpath.join(self._directory, plan.file_name)
        if any(
            receipt.artifact_path.casefold() == artifact_path.casefold()
            for receipt in self._issued.values()
        ):
            raise UnavailableError("the RDP launch identity is already active")
        try:
            executable = self._mstsc_path()
            self._filesystem.write_bytes(artifact_path, plan.file_bytes)
            process = factory(
                (executable, artifact_path),
                close_fds=True,
            )
            receipt = RdpLaunchReceipt(
                process_id=getattr(process, "pid", None),
                artifact_path=artifact_path,
            )
        except Exception:
            try:
                self._filesystem.unlink(artifact_path, missing_ok=True)
            except Exception:
                self._residual_paths.add(artifact_path)
                self._cleanup_ready = False
                raise UnavailableError(
                    "the RDP launch failed and its artifact could not be removed"
                ) from None
            raise UnavailableError(
                "the native RDP client could not be launched"
            ) from None
        self._issued[id(receipt)] = receipt
        return receipt

    def cleanup(self, receipt: RdpLaunchReceipt) -> None:
        if not isinstance(receipt, RdpLaunchReceipt):
            raise TypeError("receipt must be an RdpLaunchReceipt")
        if self._issued.get(id(receipt)) is not receipt:
            return
        try:
            self._filesystem.unlink(
                receipt.artifact_path,
                missing_ok=True,
            )
        except Exception:
            self._cleanup_ready = False
            raise UnavailableError(
                "the RDP launch artifact could not be removed"
            ) from None
        self._issued.pop(id(receipt), None)

    def cleanup_all(self) -> None:
        failed = False
        for receipt in tuple(self._issued.values()):
            try:
                self.cleanup(receipt)
            except UnavailableError:
                failed = True
        for path in tuple(self._residual_paths):
            try:
                self._filesystem.unlink(path, missing_ok=True)
            except Exception:
                self._cleanup_ready = False
                failed = True
            else:
                self._residual_paths.discard(path)
        if self._inventory_unavailable and not self._cleanup_stale_owned():
            failed = True
        if failed:
            raise UnavailableError(
                "one or more RDP launch artifacts could not be removed")

    def _cleanup_stale_owned(self) -> bool:
        try:
            names = self._filesystem.listdir(self._directory)
        except Exception:
            self._inventory_unavailable = True
            return False
        self._inventory_unavailable = False
        failed = False
        for name in names:
            if _OWNED_RDP_FILE.fullmatch(name) is None:
                continue
            path = ntpath.join(self._directory, name)
            try:
                self._filesystem.unlink(path, missing_ok=True)
            except Exception:
                self._residual_paths.add(path)
                failed = True
            else:
                self._residual_paths.discard(path)
        return not failed

    def start(self, cancellation: Any) -> None:
        cancellation.raise_if_cancelled()
        if not self._cleanup_stale_owned():
            self._cleanup_ready = False

    def stop(self, timeout_seconds: float) -> None:
        del timeout_seconds
        self.cleanup_all()

    def join(self, timeout_seconds: float) -> bool:
        del timeout_seconds
        return (
            not self._issued
            and not self._residual_paths
            and not self._inventory_unavailable
        )


def compose_native_rdp(
    directory: str,
    fallback: Callable[[Any], Any],
) -> tuple[Any, Any]:
    """Build the standard-user RDP command and cleanup runtime boundary."""

    from ..rdp import RdpService
    from ..runtime import RuntimeCoordinator, RuntimeUnit
    from ..ui.app import RdpCommandHandler
    from .windows_credentials import WindowsCredentialStore

    launcher = WindowsRdpLauncher(
        filesystem=LocalRdpFilesystem(directory),
        directory=directory,
    )
    handler = RdpCommandHandler(
        RdpService(
            credentials=WindowsCredentialStore(()),
            launcher=launcher,
        ),
        fallback=fallback,
    )
    runtime = RuntimeCoordinator((RuntimeUnit("rdp-artifacts", launcher),))
    return handler, runtime


__all__ = [
    "LocalRdpFilesystem",
    "WindowsRdpLauncher",
    "compose_native_rdp",
]
