#!/usr/bin/env python3
"""Build the PR-07 Windows candidate from reviewed offline inputs only."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import runpy
import socket
import subprocess
import sys
import tarfile
import threading
from typing import Mapping, NoReturn, Sequence

try:
    import _winapi as _winapi_module
except ImportError:  # pragma: no cover - Windows-only build path
    _winapi_module = None


ARTIFACT_NAME = "RayClusterManager-PR07.exe"
WINDOWS_VERSION_RESOURCE = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(2, 8, 5, 1),
    prodvers=(2, 8, 5, 1),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0),
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'Synaphi'),
          StringStruct('FileDescription', 'Ray Cluster Manager Windows preview'),
          StringStruct('FileVersion', '2.' + '8.' + '5.' + '1'),
          StringStruct('InternalName', 'RayClusterManager'),
          StringStruct('OriginalFilename', 'RCM-2.08.05a-windows-x64.exe'),
          StringStruct('ProductName', 'Ray Cluster Manager'),
          StringStruct('ProductVersion', '2.08.05a'),
        ],
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])]),
  ],
)
"""
EXPECTED_PYTHON_VERSION = "3.12.10"
EXPECTED_PIP_VERSION = "25.0.1"
OFFLINE_SITECUSTOMIZE = (
    "from scripts.build_windows_package import _install_offline_guards\n"
    "_install_offline_guards(allow_pyinstaller_child=False)\n"
)
HIDDEN_IMPORTS = (
    "PIL",
    "PIL.Image",
    "clr",
    "process_cleanup",
    "process_cleanup_ui",
    "psutil",
    "pystray",
    "ray_monitor",
    "rcm.adapters.local",
    "rcm.adapters.windows",
    "rcm.adapters.windows_admin",
    "rcm.adapters.windows_broker",
    "rcm.adapters.windows_credentials",
    "rcm.adapters.windows_desktop",
    "rcm.adapters.ray_cli",
    "rcm.app",
    "rcm.cluster",
    "rcm.config",
    "rcm.config.migrations",
    "rcm.config.schema",
    "rcm.config.store",
    "rcm.desktop",
    "src.rcm.legacy_compat",
    "rcm.local_admin",
    "rcm.privilege",
    "rcm.ports",
    "rcm.ray",
    "rcm.replacement",
    "rcm.rdp",
    "rcm.resources",
    "rcm.setup",
    "rcm.ui",
    "rcm.ui.app",
    "rcm.ui.cleanup_dialog",
    "rcm.ui.geometry",
    "rcm.ui.help",
    "rcm.ui.main_window",
    "rcm.ui.node_dialog",
    "rcm.ui.rdp_dialog",
    "rcm.ui.scheduler",
    "rcm.ui.settings",
    "rcm.ui.state",
    "rcm.ui.status_board",
    "rcm.ui.status_content",
    "release_info",
    "requests",
    "sensor_poller",
    "status_board_content",
    "temps_server",
    "windows_credentials",
)
REQUIRED_FROZEN_MODULES = (
    "rcm",
    "rcm.__main__",
    "rcm.bootstrap",
    "rcm.adapters.local",
    "rcm.adapters.windows",
    "rcm.adapters.windows_admin",
    "rcm.adapters.windows_broker",
    "rcm.adapters.windows_credentials",
    "rcm.adapters.windows_desktop",
    "rcm.adapters.ray_cli",
    "rcm.app",
    "rcm.cluster",
    "rcm.config",
    "rcm.config.migrations",
    "rcm.config.schema",
    "rcm.config.store",
    "rcm.desktop",
    "rcm.foundation_check",
    "rcm.identity",
    "src.rcm.legacy_compat",
    "rcm.local_admin",
    "rcm.paths",
    "rcm.privilege",
    "rcm.ports",
    "rcm.ray",
    "rcm.replacement",
    "rcm.rdp",
    "rcm.resources",
    "rcm.setup",
    "rcm.ui",
    "rcm.ui.app",
    "rcm.ui.cleanup_dialog",
    "rcm.ui.geometry",
    "rcm.ui.help",
    "rcm.ui.main_window",
    "rcm.ui.node_dialog",
    "rcm.ui.rdp_dialog",
    "rcm.ui.scheduler",
    "rcm.ui.settings",
    "rcm.ui.state",
    "rcm.ui.status_board",
    "rcm.ui.status_content",
)


class BuildInputError(RuntimeError):
    """An explicit build input violates the locked package contract."""


class OfflineNetworkError(RuntimeError):
    """A build subprocess attempted to use a network endpoint."""


def _deny_network(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise OfflineNetworkError("offline Python subprocess attempted networking")


_ORIGINAL_POPEN = subprocess.Popen
_ORIGINAL_CREATE_PROCESS = (
    getattr(_winapi_module, "CreateProcess", None)
    if _winapi_module is not None
    else None
)
_CREATE_PROCESS_GATE = threading.local()


def _deny_child_process(*args: object, **kwargs: object) -> NoReturn:
    del args, kwargs
    raise OfflineNetworkError(
        "offline Python subprocess attempted child process creation"
    )


def _guarded_create_process(*args: object, **kwargs: object) -> object:
    if (
        _ORIGINAL_CREATE_PROCESS is None
        or not getattr(_CREATE_PROCESS_GATE, "reviewed_popen", False)
    ):
        _deny_child_process()
    return _ORIGINAL_CREATE_PROCESS(*args, **kwargs)


def _allowed_pyinstaller_child(
    command: object,
    environment: object,
) -> bool:
    if (
        not isinstance(command, (list, tuple))
        or len(command) < 2
        or not all(isinstance(item, str) for item in command[:2])
        or not isinstance(environment, dict)
        or environment.get("RCM_BUILD_NETWORK_POLICY") != "deny"
    ):
        return False
    expected_child = (
        Path(sys.prefix)
        / "Lib"
        / "site-packages"
        / "PyInstaller"
        / "isolated"
        / "_child.py"
    )
    guard_root = os.environ.get("RCM_OFFLINE_GUARD_ROOT", "")
    python_path = environment.get("PYTHONPATH", "")
    try:
        return (
            Path(command[0]).resolve() == Path(sys.executable).resolve()
            and Path(command[1]).resolve() == expected_child.resolve()
            and guard_root
            and Path(guard_root).resolve()
            in {
                Path(item).resolve()
                for item in str(python_path).split(os.pathsep)
                if item
            }
        )
    except OSError:
        return False


def _guarded_popen_type(
    *,
    allow_pyinstaller_child: bool,
) -> type[subprocess.Popen[object]]:
    class GuardedPopen(_ORIGINAL_POPEN):  # type: ignore[type-arg]
        def __init__(
            self,
            command: object,
            *args: object,
            **kwargs: object,
        ) -> None:
            if allow_pyinstaller_child and _allowed_pyinstaller_child(
                command,
                kwargs.get("env"),
            ):
                previous = getattr(
                    _CREATE_PROCESS_GATE,
                    "reviewed_popen",
                    False,
                )
                _CREATE_PROCESS_GATE.reviewed_popen = True
                try:
                    super().__init__(command, *args, **kwargs)
                finally:
                    _CREATE_PROCESS_GATE.reviewed_popen = previous
                return
            _deny_child_process()

    return GuardedPopen


def _install_offline_guards(*, allow_pyinstaller_child: bool) -> None:
    socket_methods = (
        "accept",
        "accept_into",
        "bind",
        "connect",
        "connect_ex",
        "listen",
        "recv",
        "recv_into",
        "recvfrom",
        "recvfrom_into",
        "recvmsg",
        "recvmsg_into",
        "send",
        "sendall",
        "sendmsg",
        "sendto",
        "shutdown",
    )
    for name in socket_methods:
        if hasattr(socket.socket, name):
            setattr(socket.socket, name, _deny_network)
    for name in (
        "create_connection",
        "create_server",
        "fromfd",
        "fromshare",
        "getaddrinfo",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
        "getnameinfo",
        "socketpair",
    ):
        if hasattr(socket, name):
            setattr(socket, name, _deny_network)

    subprocess.Popen = _guarded_popen_type(  # type: ignore[assignment,misc]
        allow_pyinstaller_child=allow_pyinstaller_child
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
        "popen",
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
        "system",
    ):
        if hasattr(os, name):
            setattr(os, name, _deny_child_process)
    if _winapi_module is not None:
        _winapi_module.CreateProcess = _guarded_create_process


def _run_offline_module(module: str, arguments: Sequence[str]) -> int:
    if module not in {"pip", "PyInstaller"}:
        raise BuildInputError("offline module name is invalid")
    _install_offline_guards(allow_pyinstaller_child=module == "PyInstaller")
    sys.argv = [module, *arguments]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
    return 0


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolved(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise BuildInputError(f"unable to resolve path: {path}") from exc


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_external_path(
    path: Path,
    *,
    root: Path,
    label: str,
    must_exist: bool,
) -> Path:
    if not path.is_absolute():
        raise BuildInputError(f"{label} must be an absolute path")
    resolved = _resolved(path)
    repository = _resolved(root)
    if resolved == repository or _is_within(resolved, repository):
        raise BuildInputError(f"{label} must be outside the repository")
    if must_exist:
        if not resolved.is_dir() or resolved.is_symlink():
            raise BuildInputError(f"{label} must be an existing regular directory")
    elif resolved.exists():
        raise BuildInputError(f"{label} must not already exist")
    return resolved


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
) -> None:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=None if environment is None else dict(environment),
        check=False,
    )
    if completed.returncode != 0:
        raise BuildInputError(
            f"build command failed with exit code {completed.returncode}"
        )


def _capture(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=None if environment is None else dict(environment),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BuildInputError("unable to capture reviewed source identity")
    return completed.stdout.strip()


def _minimal_environment(
    *,
    source_date_epoch: int,
    cache_root: Path,
    offline_guard_root: Path,
) -> dict[str, str]:
    allowed = (
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    )
    environment = {
        key: os.environ[key]
        for key in allowed
        if key in os.environ
    }
    environment.update(
        {
            "PIP_CACHE_DIR": str(cache_root),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYINSTALLER_CONFIG_DIR": str(cache_root.parent / "pyinstaller-cache"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "RCM_BUILD_NETWORK_POLICY": "deny",
            "RCM_OFFLINE_GUARD_ROOT": str(offline_guard_root),
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
        }
    )
    return environment


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strict_json(path: Path) -> dict[str, object]:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise BuildInputError(f"duplicate JSON key in {path.name}")
            value[key] = item
        return value

    try:
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(value)
            ),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise BuildInputError(f"invalid JSON input: {path.name}") from exc
    if not isinstance(decoded, dict):
        raise BuildInputError(f"JSON root must be an object: {path.name}")
    return decoded


def _require_clean_commit(root: Path) -> tuple[str, str, int]:
    status = _capture(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=root,
    )
    if status:
        raise BuildInputError("package build requires a clean reviewed commit")
    commit = _capture(("git", "rev-parse", "HEAD"), cwd=root)
    tree = _capture(("git", "rev-parse", "HEAD^{tree}"), cwd=root)
    epoch_text = _capture(("git", "show", "-s", "--format=%ct", "HEAD"), cwd=root)
    if len(commit) != 40 or len(tree) != 40 or not epoch_text.isdigit():
        raise BuildInputError("reviewed Git identity is malformed")
    return commit, tree, int(epoch_text)


def _export_source_snapshot(
    *,
    repository: Path,
    commit: str,
    destination: Path,
) -> None:
    completed = subprocess.run(
        ("git", "archive", "--format=tar", commit),
        cwd=repository,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise BuildInputError("unable to export reviewed Git source")
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(completed.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            relative = Path(member.name)
            if (
                not member.name
                or relative.is_absolute()
                or ".." in relative.parts
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise BuildInputError("reviewed Git archive contains an unsafe entry")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise BuildInputError("reviewed Git archive entry is unreadable")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(source.read())


def _snapshot_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BuildInputError("reviewed source snapshot contains a link")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _public_snapshot_sha256(root: Path) -> str:
    allowlist = root / "policy" / "public-export-allowlist.txt"
    try:
        destinations = [
            line.strip()
            for line in allowlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError) as exc:
        raise BuildInputError("public source allowlist is unreadable") from exc
    mapping: dict[str, str] = {}
    source_map = root / "policy" / "public-export-source-map.json"
    if source_map.is_file():
        document = _strict_json(source_map)
        rows = document.get("mappings")
        if not isinstance(rows, list):
            raise BuildInputError("public source mapping is malformed")
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"source", "destination"}
                or not isinstance(row.get("source"), str)
                or not isinstance(row.get("destination"), str)
            ):
                raise BuildInputError("public source mapping is malformed")
            mapping[str(row["destination"])] = str(row["source"])
    digest = hashlib.sha256()
    for destination in sorted(destinations, key=str.casefold):
        source = mapping.get(destination, destination)
        path = root / Path(source)
        if not path.is_file() or path.is_symlink():
            raise BuildInputError("public source snapshot is incomplete")
        encoded = destination.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _write_offline_guard(destination: Path) -> str:
    destination.mkdir(parents=True)
    path = destination / "sitecustomize.py"
    encoded = OFFLINE_SITECUSTOMIZE.encode("utf-8")
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(encoded).hexdigest()


def _write_windows_version_resource(destination: Path) -> str:
    encoded = WINDOWS_VERSION_RESOURCE.encode("utf-8")
    with destination.open("xb") as stream:
        stream.write(encoded)
    return hashlib.sha256(encoded).hexdigest()


def _frozen_modules(output: Path) -> tuple[str, ...]:
    toc = (
        output
        / "work"
        / ARTIFACT_NAME.removesuffix(".exe")
        / "PYZ-00.toc"
    )
    try:
        value = ast.literal_eval(toc.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
        raise BuildInputError("PyInstaller module table is unreadable") from exc
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or not isinstance(value[1], list)
    ):
        raise BuildInputError("PyInstaller module table is malformed")
    modules = tuple(
        sorted(
            record[0]
            for record in value[1]
            if isinstance(record, tuple)
            and record
            and isinstance(record[0], str)
        )
    )
    missing = sorted(set(REQUIRED_FROZEN_MODULES) - set(modules))
    if missing:
        raise BuildInputError(
            "PyInstaller omitted required application modules: "
            + ", ".join(missing)
        )
    return modules


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def pyinstaller_command(
    *,
    python: Path,
    root: Path,
    output: Path,
    offline_guard: Path,
    version_file: Path,
    staged_vendor: Path,
    vendor_records: Sequence[Mapping[str, object]],
) -> list[str]:
    command = [
        str(python),
        "-I",
        str(root / "scripts" / "build_windows_package.py"),
        "--offline-module",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--noupx",
        "--version-file",
        str(version_file),
        "--name",
        ARTIFACT_NAME.removesuffix(".exe"),
        "--distpath",
        str(output / "dist"),
        "--workpath",
        str(output / "work"),
        "--specpath",
        str(output / "spec"),
        "--paths",
        str(offline_guard),
        "--paths",
        str(root),
        "--paths",
        str(root / "src"),
    ]
    for module in HIDDEN_IMPORTS:
        command.extend(("--hidden-import", module))
    for record in vendor_records:
        destination = record.get("destination")
        if not isinstance(destination, str) or not destination.startswith("lhm/"):
            raise BuildInputError("vendor destination is malformed")
        source = staged_vendor / destination
        command.extend(("--add-data", f"{source};lhm"))
    command.extend(
        (
            "--add-data",
            f"{root / 'packaging' / 'vendor-data.json'};build-metadata",
            "--add-data",
            f"{root / 'THIRD_PARTY_NOTICES.md'};.",
            "--add-data",
            f"{root / 'src' / 'rcm' / 'resources' / 'help.json'};rcm/resources",
            str(root / "packaging" / "entrypoint.py"),
        )
    )
    return command


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _write_package_manifest(
    *,
    root: Path,
    output: Path,
    artifact: Path,
    source_date_epoch: int,
    public_source_snapshot_sha256: str,
    network_guard_sha256: str,
    windows_version_resource_sha256: str,
    pip_version: str,
    bundled_modules: Sequence[str],
    vendor_records: Sequence[Mapping[str, object]],
) -> Path:
    locks = {
        name: _sha256(root / "requirements" / name)
        for name in (
            "runtime-win-x86_64.lock",
            "build-win-x86_64.lock",
            "dev.lock",
        )
    }
    bundled = sorted(
        str(record["destination"])
        for record in vendor_records
    ) + [
        "THIRD_PARTY_NOTICES.md",
        "build-metadata/vendor-data.json",
        "rcm/resources/help.json",
    ]
    manifest = {
        "schema_version": 1,
        "candidate": {
            "path": f"dist/{artifact.name}",
            "size": artifact.stat().st_size,
            "sha256": _sha256(artifact),
        },
        "source": {
            "public_snapshot_sha256": public_source_snapshot_sha256,
            "repository_clean": True,
        },
        "build": {
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "pip": pip_version,
            "source_date_epoch": source_date_epoch,
            "network_access": False,
            "network_policy": "python_socket_and_child_deny",
            "network_guard_sha256": network_guard_sha256,
            "windows_version_resource_sha256": windows_version_resource_sha256,
            "output_inside_repository": False,
            "signing": False,
            "public_source_snapshot_sha256": public_source_snapshot_sha256,
        },
        "inputs": {
            "dependency_provenance_sha256": _sha256(
                root / "policy" / "dependency-provenance.json"
            ),
            "vendor_manifest_sha256": _sha256(
                root / "packaging" / "vendor-data.json"
            ),
            "third_party_notices_sha256": _sha256(
                root / "THIRD_PARTY_NOTICES.md"
            ),
            "lock_sha256": locks,
        },
        "bundled_files": bundled,
        "required_modules": list(REQUIRED_FROZEN_MODULES),
        "bundled_module_count": len(bundled_modules),
    }
    destination = output / "package-manifest.json"
    destination.write_bytes(_canonical_bytes(manifest))
    return destination


def build(
    *,
    wheelhouse: Path,
    vendor_root: Path,
    output_root: Path,
) -> Path:
    repository = repository_root()
    wheelhouse = validate_external_path(
        wheelhouse,
        root=repository,
        label="wheelhouse",
        must_exist=True,
    )
    vendor_root = validate_external_path(
        vendor_root,
        root=repository,
        label="vendor root",
        must_exist=True,
    )
    output = validate_external_path(
        output_root,
        root=repository,
        label="output root",
        must_exist=False,
    )
    if (
        os.name != "nt"
        or platform.machine().upper() not in {"AMD64", "X86_64"}
        or platform.python_version() != EXPECTED_PYTHON_VERSION
    ):
        raise BuildInputError(
            f"build requires CPython {EXPECTED_PYTHON_VERSION} on Windows x86-64"
        )
    source_commit, source_tree, source_date_epoch = _require_clean_commit(
        repository
    )
    output.mkdir(parents=True)
    root = output / "source-snapshot"
    _export_source_snapshot(
        repository=repository,
        commit=source_commit,
        destination=root,
    )
    source_snapshot_sha256 = _snapshot_sha256(root)
    public_source_snapshot_sha256 = _public_snapshot_sha256(root)
    offline_guard = output / "offline-guard"
    network_guard_sha256 = _write_offline_guard(offline_guard)
    version_file = output / "windows-version-info.txt"
    windows_version_resource_sha256 = _write_windows_version_resource(
        version_file
    )
    environment = _minimal_environment(
        source_date_epoch=source_date_epoch,
        cache_root=output / "pip-cache",
        offline_guard_root=offline_guard,
    )

    _run(
        (
            sys.executable,
            "-I",
            str(root / "scripts" / "check_dependency_lock.py"),
            "--require-reviewed-notices",
            "--wheelhouse",
            str(wheelhouse),
        ),
        cwd=root,
        environment=environment,
    )
    _run(
        (
            sys.executable,
            "-I",
            str(root / "scripts" / "check_bundle_manifest.py"),
        ),
        cwd=root,
        environment=environment,
    )
    vendor_manifest = _strict_json(root / "packaging" / "vendor-data.json")
    raw_records = vendor_manifest.get("files")
    if not isinstance(raw_records, list) or len(raw_records) != 10:
        raise BuildInputError("vendor manifest selection is not exact")
    records: list[Mapping[str, object]] = []
    for record in raw_records:
        if not isinstance(record, dict):
            raise BuildInputError("vendor manifest record is malformed")
        records.append(record)

    staged_vendor = output / "staged-vendor"
    _run(
        (
            sys.executable,
            "-I",
            str(root / "scripts" / "stage_vendor_data.py"),
            "--vendor-root",
            str(vendor_root),
            "--destination",
            str(staged_vendor),
        ),
        cwd=root,
        environment=environment,
    )
    venv = output / "build-venv"
    _run(
        (sys.executable, "-I", "-m", "venv", str(venv)),
        cwd=root,
        environment=environment,
    )
    python = _venv_python(venv)
    offline_runner = root / "scripts" / "build_windows_package.py"
    pip_output = _capture(
        (
            str(python),
            "-I",
            str(offline_runner),
            "--offline-module",
            "pip",
            "--version",
        ),
        cwd=root,
        environment=environment,
    )
    if not pip_output.startswith(f"pip {EXPECTED_PIP_VERSION} from "):
        raise BuildInputError("venv pip identity is not the reviewed version")
    _run(
        (
            str(python),
            "-I",
            str(offline_runner),
            "--offline-module",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "--require-hashes",
            "--only-binary",
            ":all:",
            "-r",
            str(root / "requirements" / "runtime-win-x86_64.lock"),
            "-r",
            str(root / "requirements" / "build-win-x86_64.lock"),
        ),
        cwd=root,
        environment=environment,
    )
    _run(
        pyinstaller_command(
            python=python,
            root=root,
            output=output,
            offline_guard=offline_guard,
            version_file=version_file,
            staged_vendor=staged_vendor,
            vendor_records=records,
        ),
        cwd=root,
        environment=environment,
    )
    artifact = output / "dist" / ARTIFACT_NAME
    if not artifact.is_file() or artifact.is_symlink():
        raise BuildInputError("PyInstaller did not create the exact candidate")
    bundled_modules = _frozen_modules(output)
    final_commit, final_tree, final_epoch = _require_clean_commit(repository)
    if (
        (final_commit, final_tree, final_epoch)
        != (source_commit, source_tree, source_date_epoch)
        or _snapshot_sha256(root) != source_snapshot_sha256
    ):
        raise BuildInputError("reviewed source identity changed during the build")
    manifest = _write_package_manifest(
        root=root,
        output=output,
        artifact=artifact,
        source_date_epoch=source_date_epoch,
        public_source_snapshot_sha256=public_source_snapshot_sha256,
        network_guard_sha256=network_guard_sha256,
        windows_version_resource_sha256=windows_version_resource_sha256,
        pip_version=EXPECTED_PIP_VERSION,
        bundled_modules=bundled_modules,
        vendor_records=records,
    )
    print(f"PASS: offline Windows candidate {artifact.name}")
    print("manifest: package-manifest.json")
    print(f"sha256: {_sha256(artifact)}")
    return manifest


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--offline-module":
        try:
            return _run_offline_module(sys.argv[2], sys.argv[3:])
        except (BuildInputError, OfflineNetworkError) as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(
        description="Build the reviewed PR-07 Windows package offline."
    )
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--vendor-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        build(
            wheelhouse=arguments.wheelhouse,
            vendor_root=arguments.vendor_root,
            output_root=arguments.output_root,
        )
    except BuildInputError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
