"""Lazy Windows host adapters."""

from __future__ import annotations

import ntpath
from pathlib import Path, PureWindowsPath
import re
from typing import Any, Callable, NamedTuple

from ..core import (
    Capability,
    CapabilityState,
    UnavailableError,
    UnsupportedError,
)
from ..rdp import RdpLaunchPlan, RdpLaunchReceipt
from ..ports import FileKind, FileStat, Filesystem


_OWNED_RDP_FILE = re.compile(r"rcm_rdp_[0-9a-f]{32}\.rdp")
_OWNED_RDP_FILE_ATTRIBUTES = 0x00000002 | 0x00000004 | 0x00000100
_OWNED_RDP_FORBIDDEN_FILE_ATTRIBUTES = 0x00000010 | 0x00000040 | 0x00000400
_MAX_OWNED_RDP_FILE_BYTES = 65_536


class _WindowsLocalFileDetails(NamedTuple):
    file_attributes: int
    size: int
    modified_ns: int
    volume_serial_number: int
    number_of_links: int
    file_index: int


def _owned_rdp_file_details_are_valid(
    details: _WindowsLocalFileDetails,
) -> bool:
    return (
        details.file_attributes & _OWNED_RDP_FILE_ATTRIBUTES
        == _OWNED_RDP_FILE_ATTRIBUTES
        and not (
            details.file_attributes
            & _OWNED_RDP_FORBIDDEN_FILE_ATTRIBUTES
        )
        and details.number_of_links == 1
        and details.size <= _MAX_OWNED_RDP_FILE_BYTES
    )


class _OwnedArtifactCleanupError(OSError):
    pass


class _OwnedRdpArtifact:
    __slots__ = ("identity", "handle", "directory_lease")

    def __init__(
        self,
        identity: str,
        handle: int | None,
        directory_lease: Any,
    ) -> None:
        self.identity = identity
        self.handle = handle
        self.directory_lease = directory_lease


def _open_windows_local_file(
    path: str,
    *,
    access: int,
    creation: int,
    file_attributes: int = 0x00000080,
) -> int:
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        path,
        access,
        0x00000001,  # share read only; deny concurrent write/delete mutation
        None,
        creation,
        file_attributes | 0x00200000,  # attributes | OPEN_REPARSE_POINT
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def _close_windows_local_file(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    close_handle(handle)


def _windows_local_file_details(handle: int) -> _WindowsLocalFileDetails:
    import ctypes
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("file_attributes", wintypes.DWORD),
            ("creation_time_low", wintypes.DWORD),
            ("creation_time_high", wintypes.DWORD),
            ("access_time_low", wintypes.DWORD),
            ("access_time_high", wintypes.DWORD),
            ("write_time_low", wintypes.DWORD),
            ("write_time_high", wintypes.DWORD),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        )

    get_information = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    information = ByHandleFileInformation()
    if not get_information(handle, ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    size = information.file_size_low | (information.file_size_high << 32)
    modified = information.write_time_low | (
        information.write_time_high << 32
    )
    identity = information.file_index_low | (
        information.file_index_high << 32
    )
    unix_ticks = max(0, modified - 116_444_736_000_000_000)
    return _WindowsLocalFileDetails(
        file_attributes=information.file_attributes,
        size=size,
        modified_ns=unix_ticks * 100,
        volume_serial_number=information.volume_serial_number,
        number_of_links=information.number_of_links,
        file_index=identity,
    )


def _windows_local_file_information(handle: int) -> tuple[int, int, int, int]:
    details = _windows_local_file_details(handle)
    if details.file_attributes & (0x10 | 0x400):
        raise OSError("RDP artifact must be one real regular file")
    return (
        details.size,
        details.modified_ns,
        details.volume_serial_number,
        details.file_index,
    )


def _mark_windows_local_file_for_delete(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class FileDispositionInformation(ctypes.Structure):
        _fields_ = (("delete_file", wintypes.BOOL),)

    set_information = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).SetFileInformationByHandle
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    set_information.restype = wintypes.BOOL
    information = FileDispositionInformation(True)
    if not set_information(
        handle,
        4,  # FileDispositionInfo
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise ctypes.WinError(ctypes.get_last_error())


def _write_windows_local_file(handle: int, data: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    write_file = kernel32.WriteFile
    write_file.argtypes = (
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    write_file.restype = wintypes.BOOL
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 1_048_576]
        buffer = ctypes.create_string_buffer(chunk)
        written = wintypes.DWORD()
        if not write_file(
            handle,
            buffer,
            len(chunk),
            ctypes.byref(written),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not written.value:
            raise OSError("the RDP artifact write did not make progress")
        offset += written.value
    flush = kernel32.FlushFileBuffers
    flush.argtypes = (wintypes.HANDLE,)
    flush.restype = wintypes.BOOL
    if not flush(handle):
        raise ctypes.WinError(ctypes.get_last_error())


def _read_windows_local_file(handle: int, limit: int) -> bytes:
    import ctypes
    from ctypes import wintypes

    read_file = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).ReadFile
    read_file.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    read_file.restype = wintypes.BOOL
    capacity = limit + 1
    buffer = ctypes.create_string_buffer(capacity)
    read = wintypes.DWORD()
    if capacity and not read_file(
        handle,
        buffer,
        capacity,
        ctypes.byref(read),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.raw[:read.value]


def _rewind_windows_local_file(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    set_pointer = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).SetFilePointerEx
    set_pointer.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    set_pointer.restype = wintypes.BOOL
    if not set_pointer(handle, 0, None, 0):
        raise ctypes.WinError(ctypes.get_last_error())


def _write_exclusive_local_file(path: str, data: bytes) -> str:
    import os

    if len(data) > _MAX_OWNED_RDP_FILE_BYTES:
        raise ValueError("RDP artifact exceeds the owned-file limit")
    if os.name != "nt":
        created = False
        try:
            with open(path, "xb") as stream:
                created = True
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                details = os.fstat(stream.fileno())
        except FileExistsError:
            raise
        except Exception:
            if created:
                try:
                    os.unlink(path)
                except Exception:
                    raise _OwnedArtifactCleanupError(
                        "the partial RDP artifact could not be removed"
                    ) from None
            raise
        return f"{details.st_dev}:{details.st_ino}"
    handle = _open_windows_local_file(
        path,
        access=0x80000000 | 0x40000000 | 0x00010000,
        creation=1,  # CREATE_NEW
        file_attributes=_OWNED_RDP_FILE_ATTRIBUTES,
    )
    try:
        details = _windows_local_file_details(handle)
        if not _owned_rdp_file_details_are_valid(details):
            raise OSError("RDP artifact ownership marker is unavailable")
        _write_windows_local_file(handle, data)
        return f"{details.volume_serial_number}:{details.file_index}"
    except Exception:
        try:
            _mark_windows_local_file_for_delete(handle)
        except Exception:
            raise _OwnedArtifactCleanupError(
                "the partial RDP artifact could not be removed"
            ) from None
        raise
    finally:
        _close_windows_local_file(handle)


def _unlink_local_file(path: str, expected_identity: str) -> None:
    import os

    if os.name != "nt":
        details = os.stat(path, follow_symlinks=False)
        if f"{details.st_dev}:{details.st_ino}" != expected_identity:
            raise OSError("RDP artifact ownership changed")
        os.unlink(path)
        return
    handle = _open_windows_local_file(
        path,
        access=0x0080 | 0x00010000,
        creation=3,  # OPEN_EXISTING
    )
    try:
        details = _windows_local_file_details(handle)
        identity = (
            f"{details.volume_serial_number}:{details.file_index}"
        )
        if (
            identity != expected_identity
            or not _owned_rdp_file_details_are_valid(details)
        ):
            raise OSError("RDP artifact ownership changed")
        _mark_windows_local_file_for_delete(handle)
    finally:
        _close_windows_local_file(handle)


def _recover_stale_local_file(path: str) -> None:
    """Delete one prior-process artifact only through its validated handle."""

    import os

    if os.name != "nt":
        raise OSError("stale RDP recovery requires Windows")
    handle = _open_windows_local_file(
        path,
        access=0x0080 | 0x00010000,
        creation=3,  # OPEN_EXISTING
    )
    try:
        details = _windows_local_file_details(handle)
        if not _owned_rdp_file_details_are_valid(details):
            raise OSError("RDP artifact ownership marker is unavailable")
        _mark_windows_local_file_for_delete(handle)
    finally:
        _close_windows_local_file(handle)


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
        self._owned_artifacts: dict[str, _OwnedRdpArtifact] = {}
        self._validate_directory()

    def _validate_directory(self) -> None:
        from ..setup import _assert_local_metadata_root

        _assert_local_metadata_root(Path(self._directory))

    def _locked_directory(self) -> Any:
        from ..setup import _locked_local_metadata_directory

        return _locked_local_metadata_directory(Path(self._directory))

    def _acquire_directory(self) -> Any:
        from ..setup import _acquire_local_metadata_directory

        return _acquire_local_metadata_directory(Path(self._directory))

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
        state = self._owned_artifacts.get(owned.casefold())
        if os.name == "nt" and state is not None and state.handle is not None:
            details = _windows_local_file_details(state.handle)
            identity = (
                f"{details.volume_serial_number}:{details.file_index}"
            )
            if (
                identity != state.identity
                or not _owned_rdp_file_details_are_valid(details)
            ):
                raise OSError("RDP artifact ownership changed")
            return FileStat(
                owned,
                FileKind.FILE,
                details.size,
                details.modified_ns,
                state.identity,
            )
        if os.name != "nt":
            with self._locked_directory():
                value = os.stat(owned, follow_symlinks=False)
                kind = FileKind.FILE if os.path.isfile(owned) else FileKind.OTHER
            return FileStat(
                owned,
                kind,
                value.st_size,
                value.st_mtime_ns,
                f"{value.st_dev}:{value.st_ino}",
            )
        with self._locked_directory():
            handle = _open_windows_local_file(
                owned,
                access=0x0080,
                creation=3,
            )
            try:
                size, modified, volume, identity = (
                    _windows_local_file_information(handle)
                )
            finally:
                _close_windows_local_file(handle)
        return FileStat(
            owned,
            FileKind.FILE,
            size,
            modified,
            f"{volume}:{identity}",
        )

    def read_bytes(self, path: str, *, limit: int) -> bytes:
        if type(limit) is not int or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        import os

        owned = self._path(path)
        state = self._owned_artifacts.get(owned.casefold())
        if os.name == "nt" and state is not None and state.handle is not None:
            details = _windows_local_file_details(state.handle)
            if not _owned_rdp_file_details_are_valid(details):
                raise OSError("RDP artifact ownership changed")
            _rewind_windows_local_file(state.handle)
            data = _read_windows_local_file(state.handle, limit)
            if len(data) > limit:
                raise ValueError("RDP artifact exceeds the read limit")
            return data
        with self._locked_directory():
            if os.name == "nt":
                handle = _open_windows_local_file(
                    owned,
                    access=0x80000000,
                    creation=3,
                )
                try:
                    _windows_local_file_information(handle)
                    data = _read_windows_local_file(handle, limit)
                finally:
                    _close_windows_local_file(handle)
            else:
                with open(owned, "rb") as stream:
                    data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("RDP artifact exceeds the read limit")
        return data

    def write_bytes(self, path: str, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError("RDP artifact data must be bytes")
        owned = self._path(path)
        key = owned.casefold()
        directory_lease = self._acquire_directory()
        guard_handle: int | None = None
        identity: str | None = None
        try:
            identity = _write_exclusive_local_file(owned, data)
            import os

            if os.name == "nt":
                guard_handle = _open_windows_local_file(
                    owned,
                    access=0x80000000,
                    creation=3,
                )
                details = _windows_local_file_details(guard_handle)
                observed_identity = (
                    f"{details.volume_serial_number}:{details.file_index}"
                )
                if (
                    observed_identity != identity
                    or not _owned_rdp_file_details_are_valid(details)
                ):
                    raise OSError("RDP artifact ownership changed")
                observed = _read_windows_local_file(guard_handle, len(data))
                if observed != data:
                    raise OSError("RDP artifact contents changed")
                _rewind_windows_local_file(guard_handle)
            self._owned_artifacts[key] = _OwnedRdpArtifact(
                identity,
                guard_handle,
                directory_lease,
            )
        except Exception:
            if guard_handle is not None:
                _close_windows_local_file(guard_handle)
            if identity is not None:
                try:
                    _unlink_local_file(owned, identity)
                except FileNotFoundError:
                    pass
                except Exception:
                    directory_lease.close()
                    raise _OwnedArtifactCleanupError(
                        "the RDP artifact guard could not be established"
                    ) from None
            directory_lease.close()
            raise

    def replace(self, source: str, destination: str) -> None:
        del source, destination
        raise OSError("RDP artifact replacement is not supported")

    def unlink(self, path: str, *, missing_ok: bool = False) -> None:
        owned = self._path(path)
        key = owned.casefold()
        state = self._owned_artifacts.get(key)
        if state is None:
            raise OSError("RDP artifact ownership is unavailable")
        if state.handle is not None:
            details = _windows_local_file_details(state.handle)
            identity = (
                f"{details.volume_serial_number}:{details.file_index}"
            )
            if (
                identity != state.identity
                or not _owned_rdp_file_details_are_valid(details)
            ):
                raise OSError("RDP artifact ownership changed")
            _close_windows_local_file(state.handle)
            state.handle = None
        try:
            _unlink_local_file(owned, state.identity)
        except FileNotFoundError:
            if not missing_ok:
                raise
            state.directory_lease.close()
            self._owned_artifacts.pop(key, None)
        else:
            state.directory_lease.close()
            self._owned_artifacts.pop(key, None)

    def recover_stale(self, path: str, *, missing_ok: bool = False) -> None:
        """Recover a marked prior-process artifact without in-memory identity."""

        owned = self._path(path)
        with self._locked_directory():
            try:
                _recover_stale_local_file(owned)
            except FileNotFoundError:
                if not missing_ok:
                    raise

    def listdir(self, path: str) -> tuple[str, ...]:
        import os

        normalized = _absolute_local_windows_path(path, label="RDP directory")
        if normalized.casefold() != self._directory.casefold():
            raise ValueError("RDP directory is outside the owned directory")
        with self._locked_directory():
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
        self._stale_residual_paths: set[str] = set()
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
        except Exception:
            raise UnavailableError(
                "the native RDP client could not be launched"
            ) from None
        try:
            self._filesystem.write_bytes(artifact_path, plan.file_bytes)
        except FileExistsError:
            # Exclusive creation means this path predates this launch.  Never
            # delete an artifact that this launcher instance did not create.
            raise UnavailableError(
                "the native RDP client could not be launched"
            ) from None
        except _OwnedArtifactCleanupError:
            self._stale_residual_paths.add(artifact_path)
            self._cleanup_ready = False
            raise UnavailableError(
                "the RDP launch failed and its artifact could not be removed"
            ) from None
        except Exception:
            # A failed write does not prove exclusive creation.  The concrete
            # filesystem owns partial-write cleanup; the launcher must never
            # guess that a pre-existing path belongs to this attempt.
            raise UnavailableError(
                "the native RDP client could not be launched"
            ) from None
        try:
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
        for path in tuple(self._stale_residual_paths):
            try:
                self._filesystem.recover_stale(path, missing_ok=True)  # type: ignore[attr-defined]
            except Exception:
                self._cleanup_ready = False
                failed = True
            else:
                self._stale_residual_paths.discard(path)
        if self._inventory_unavailable and not self._cleanup_stale_owned():
            failed = True
        if failed:
            raise UnavailableError(
                "one or more RDP launch artifacts could not be removed")
        self._cleanup_ready = True

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
                self._filesystem.recover_stale(path, missing_ok=True)  # type: ignore[attr-defined]
            except Exception:
                self._stale_residual_paths.add(path)
                failed = True
            else:
                self._stale_residual_paths.discard(path)
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
            and not self._stale_residual_paths
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


def compose_local_ray(config: Any, fallback: Callable[[Any], Any]) -> Any:
    """Build the explicit, local-only Ray desktop command boundary."""

    import os
    from pathlib import PureWindowsPath

    from ..adapters.ray_cli import (
        LocalRayProcessRunner,
        RayCliAdapter,
        RayCliSettings,
    )
    from ..config.schema import Config
    from ..ui.app import LocalRayCommandHandler

    if not isinstance(config, Config) or not callable(fallback):
        raise TypeError("local Ray composition dependencies are invalid")
    if not config.ray.enabled:
        return LocalRayCommandHandler(config, None, fallback=fallback)
    local_id = config.nodes.local_node_id.casefold()
    local = next(
        (
            item
            for item in config.nodes.items
            if local_id and item.node_id.casefold() == local_id
        ),
        None,
    )
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    local_app_path = PureWindowsPath(local_app_data)
    local_temp_path = local_app_path / "Temp" / "RayClusterManager" / "ray"
    temp_path_valid = (
        bool(local_app_data)
        and local_app_path.is_absolute()
        and not local_app_path.anchor.startswith("\\\\")
        and not any(
            part in {"", ".", ".."} or ":" in part
            for part in local_app_path.parts[1:]
        )
    )
    if (
        local is None
        or not config.ray.executable_path
        or not temp_path_valid
    ):
        return LocalRayCommandHandler(config, None, fallback=fallback)
    cpu_count = local.cpu_count or config.ray.cpu_count or None
    settings = RayCliSettings(
        executable=config.ray.executable_path,
        local_node_id=local.node_id,
        cluster_port=config.ray.client_port,
        num_cpus=cpu_count,
        temp_dir=str(local_temp_path),
        dashboard_host=("127.0.0.1" if local.role == "head" else None),
        dashboard_port=(
            config.ray.dashboard_port if local.role == "head" else None
        ),
        start_timeout_seconds=config.ray.startup_timeout_seconds,
    )
    adapter = RayCliAdapter(
        settings,
        LocalRayProcessRunner(config.ray.executable_path),
    )
    return LocalRayCommandHandler(config, adapter, fallback=fallback)


__all__ = [
    "LocalRdpFilesystem",
    "WindowsRdpLauncher",
    "compose_local_ray",
    "compose_native_rdp",
]
