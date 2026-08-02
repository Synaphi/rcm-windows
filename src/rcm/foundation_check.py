"""Side-effect-bounded verification for a frozen PR-05 package candidate.

This module is imported only for the explicit ``--foundation-check`` command.
Normal package import and the compatibility launcher do not inspect the host.
The check validates only public, bundled build inputs and read-only display
facts.  It denies socket and child-process creation while the check runs.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from typing import Iterator, Mapping

from . import __version__


class FoundationCheckError(RuntimeError):
    """The frozen package does not match its reviewed build metadata."""


class _DuplicateKeyError(ValueError):
    pass


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _read_manifest(path: Path) -> Mapping[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FoundationCheckError("vendor manifest is unavailable") from exc
    try:
        decoded = raw.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid constant: {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise FoundationCheckError("vendor manifest is not strict JSON") from exc
    if not isinstance(value, dict):
        raise FoundationCheckError("vendor manifest root must be an object")
    return value


def _safe_bundle_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise FoundationCheckError("vendor destination must be a string")
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if (
        normalized.startswith("/")
        or ":" in normalized
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0] != "lhm"
    ):
        raise FoundationCheckError("vendor destination is outside lhm")
    candidate = root.joinpath(*parts)
    if candidate.is_symlink():
        raise FoundationCheckError("vendor payload cannot be a symbolic link")
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise FoundationCheckError("vendor payload is unreadable") from exc
    return digest.hexdigest()


def _validate_vendor_payload(root: Path) -> tuple[int, int]:
    manifest = _read_manifest(root / "build-metadata" / "vendor-data.json")
    if manifest.get("schema_version") != 1:
        raise FoundationCheckError("vendor manifest schema is unsupported")
    records = manifest.get("files")
    if not isinstance(records, list) or len(records) != 10:
        raise FoundationCheckError("vendor manifest must select ten files")
    destinations: set[str] = set()
    total_size = 0
    for record in records:
        if not isinstance(record, dict):
            raise FoundationCheckError("vendor record must be an object")
        if set(record) != {
            "source_name",
            "destination",
            "kind",
            "size",
            "sha256",
        }:
            raise FoundationCheckError("vendor record schema is not exact")
        destination = record["destination"]
        if destination in destinations:
            raise FoundationCheckError("vendor destination is duplicated")
        destinations.add(str(destination))
        size = record["size"]
        expected_hash = record["sha256"]
        if (
            type(size) is not int
            or size < 1
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
        ):
            raise FoundationCheckError("vendor identity is malformed")
        path = _safe_bundle_path(root, destination)
        try:
            actual_size = path.stat().st_size
        except OSError as exc:
            raise FoundationCheckError("vendor payload is missing") from exc
        if actual_size != size or _sha256(path) != expected_hash:
            raise FoundationCheckError("vendor payload identity mismatch")
        total_size += actual_size
    notice = root / "THIRD_PARTY_NOTICES.md"
    if not notice.is_file() or notice.is_symlink():
        raise FoundationCheckError("third-party notice is missing")
    return len(records), total_size


@contextmanager
def _deny_network_and_children() -> Iterator[dict[str, int]]:
    counters = {
        "socket_attempts": 0,
        "subprocess_attempts": 0,
        "os_system_attempts": 0,
        "startfile_attempts": 0,
    }
    original_socket = socket.socket
    original_create_connection = socket.create_connection
    original_create_server = getattr(socket, "create_server", None)
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex
    original_gethostbyaddr = socket.gethostbyaddr
    original_popen = subprocess.Popen
    original_system = os.system
    original_startfile = getattr(os, "startfile", None)

    def deny_socket_operation(*args: object, **kwargs: object) -> object:
        counters["socket_attempts"] += 1
        raise FoundationCheckError("network access is denied")

    class DeniedSocket(original_socket):
        def bind(self, *args: object, **kwargs: object) -> object:
            counters["socket_attempts"] += 1
            raise FoundationCheckError("network access is denied")

        connect = bind
        connect_ex = bind
        listen = bind
        accept = bind
        sendto = bind
        sendmsg = bind

    class DeniedPopen(original_popen):
        def __init__(self, *args: object, **kwargs: object) -> None:
            counters["subprocess_attempts"] += 1
            raise FoundationCheckError("child process creation is denied")

    def denied_system(*args: object, **kwargs: object) -> object:
        counters["os_system_attempts"] += 1
        raise FoundationCheckError("OS command execution is denied")

    def denied_startfile(*args: object, **kwargs: object) -> object:
        counters["startfile_attempts"] += 1
        raise FoundationCheckError("shell activation is denied")

    socket.socket = DeniedSocket
    socket.create_connection = deny_socket_operation
    if original_create_server is not None:
        socket.create_server = deny_socket_operation
    socket.getaddrinfo = deny_socket_operation
    socket.gethostbyname = deny_socket_operation
    socket.gethostbyname_ex = deny_socket_operation
    socket.gethostbyaddr = deny_socket_operation
    subprocess.Popen = DeniedPopen
    os.system = denied_system
    if original_startfile is not None:
        os.startfile = denied_startfile  # type: ignore[attr-defined]
    try:
        yield counters
    finally:
        socket.socket = original_socket  # type: ignore[assignment]
        socket.create_connection = original_create_connection
        if original_create_server is not None:
            socket.create_server = original_create_server
        socket.getaddrinfo = original_getaddrinfo
        socket.gethostbyname = original_gethostbyname
        socket.gethostbyname_ex = original_gethostbyname_ex
        socket.gethostbyaddr = original_gethostbyaddr
        subprocess.Popen = original_popen  # type: ignore[assignment]
        os.system = original_system
        if original_startfile is not None:
            os.startfile = original_startfile  # type: ignore[attr-defined]


def _display_facts() -> dict[str, int | None]:
    if os.name != "nt":
        return {"width": None, "height": None, "dpi": None}
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    width = int(user32.GetSystemMetrics(0))
    height = int(user32.GetSystemMetrics(1))
    dpi_function = getattr(user32, "GetDpiForSystem", None)
    dpi = int(dpi_function()) if dpi_function is not None else 96
    return {"width": width, "height": height, "dpi": dpi}


def _verify_runtime_imports() -> tuple[str, ...]:
    modules = (
        "PIL.Image",
        "clr",
        "psutil",
        "pystray",
        "rcm.config",
        "rcm.config.migrations",
        "rcm.config.schema",
        "rcm.config.store",
        "requests",
    )
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception as exc:
            raise FoundationCheckError(
                f"locked runtime import failed: {name}"
            ) from exc
    return modules


def _resource_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if not getattr(sys, "frozen", False) or not isinstance(frozen_root, str):
        raise FoundationCheckError("foundation check requires a frozen package")
    return Path(frozen_root)


def foundation_report(
    *,
    resource_root: Path | None = None,
    verify_runtime_imports: bool = True,
) -> dict[str, object]:
    """Return one canonical, privacy-safe package verification report."""

    with _deny_network_and_children() as counters:
        root = _resource_root() if resource_root is None else resource_root
        file_count, total_size = _validate_vendor_payload(root)
        runtime_modules = (
            _verify_runtime_imports() if verify_runtime_imports else ()
        )
        display = _display_facts()
    # urllib3 performs one import-time IPv6 capability bind probe.  The guard
    # denies it before an endpoint exists.  No other network, child, or shell
    # attempt is part of the reviewed runtime-import closure.
    if (
        counters["socket_attempts"] not in ({0, 1} if verify_runtime_imports else {0})
        or counters["subprocess_attempts"] != 0
        or counters["os_system_attempts"] != 0
        or counters["startfile_attempts"] != 0
    ):
        raise FoundationCheckError("runtime imports exceeded the denied side-effect budget")
    loaded_legacy = sorted(
        name
        for name in sys.modules
        if name == "ray_monitor"
        or name
        in {
            "process_cleanup",
            "process_cleanup_ui",
            "sensor_poller",
            "temps_server",
        }
    )
    if loaded_legacy:
        raise FoundationCheckError("legacy application modules loaded during check")
    return {
        "schema_version": 1,
        "application": "RayClusterManager",
        "version": __version__,
        "platform": platform.system(),
        "architecture": platform.machine(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "vendor_files": file_count,
        "vendor_bytes": total_size,
        "runtime_modules": runtime_modules,
        "display": display,
        "network_connections": 0,
        "network_listeners": 0,
        "child_processes": 0,
        "shutdown_action": "none",
        "denied_side_effect_attempts": counters,
    }


def print_foundation_report() -> int:
    """Write a stable single-line report for the package verifier."""

    report = foundation_report()
    print(
        json.dumps(
            report,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0
