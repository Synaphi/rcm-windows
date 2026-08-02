#!/usr/bin/env python3
"""Exercise the repository-anchored PR-07 Windows lifecycle candidate."""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Mapping


SCENARIO_COUNTS = {
    "visible-quit": 50,
    "close-show-quit": 25,
    "minimized-show-quit": 25,
}
RUN_COUNT = sum(SCENARIO_COUNTS.values())
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_PYTHON_VERSION = "3.12.10"
EXPECTED_PIP_VERSION = "25.0.1"
EXPECTED_REQUIRED_MODULES = [
    "rcm",
    "rcm.__main__",
    "rcm.bootstrap",
    "rcm.adapters.local",
    "rcm.adapters.windows_admin",
    "rcm.adapters.windows_broker",
    "rcm.adapters.windows_credentials",
    "rcm.adapters.windows_desktop",
    "rcm.app",
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
    "rcm.replacement",
    "rcm.resources",
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
]
MAIN_WINDOW_TITLE = "Ray Cluster Manager"
MAIN_WINDOW_CLASS = "TkTopLevel"
VALIDATION_MUTEX_NAME = (
    "Local\\RayClusterManager_"
    "preview_validation_singleton"
)
WINDOW_ABSENT = "ABSENT"
WINDOW_HIDDEN = "HIDDEN"
WINDOW_MINIMIZED = "MINIMIZED"
WINDOW_VISIBLE = "VISIBLE"
WINDOW_STATES = (
    WINDOW_ABSENT,
    WINDOW_HIDDEN,
    WINDOW_MINIMIZED,
    WINDOW_VISIBLE,
)
CLAIM_ASSERTIONS = {
    "live_system_access": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_no_operational_adapter",
    },
    "live_system_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_no_operational_adapter",
    },
    "production_config_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_config_io_disabled",
    },
    "official_artifact_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "candidate_locked_read_only",
    },
    "mutex_residue": {
        "status": "MEASURED",
        "basis": "post_exit_mutex_probe",
    },
    "named_pipe_residue": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_no_named_pipe",
    },
    "temporary_artifact_residue": {
        "status": "MEASURED",
        "basis": "run_temp_empty_after_exit",
    },
    "elevated_token_activity": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "uac_prompt_activity": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "helper_process_residue": {
        "status": "MEASURED",
        "basis": "pid_lineage_zero_after_exit",
    },
    "startup_entry_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_config_io_disabled",
    },
    "scheduled_task_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "rdp_host_configuration_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "firewall_rule_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "network_location_awareness_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "credential_material_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_command_unavailable",
    },
    "ray_runtime_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_runtime_empty",
    },
    "tailscale_runtime_mutation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_runtime_empty",
    },
    "production_state_preservation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_identity_no_config_io",
    },
    "development_state_preservation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_identity_no_config_io",
    },
    "stale_owner_preservation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_runtime_empty",
    },
    "sentinel_state_preservation": {
        "status": "NOT_APPLICABLE",
        "basis": "validation_runtime_empty",
    },
}


class CandidateError(RuntimeError):
    """The external package candidate failed the frozen verification gate."""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.stat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & 0x400)


@contextmanager
def _hold_windows_file(path: Path) -> object:
    """Deny replacement and writes while a reviewed path is consumed."""

    if os.name != "nt":
        raise CandidateError("candidate verification requires Windows")
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
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
    close = ctypes.windll.kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ; deny write/delete/replacement
        None,
        3,  # OPEN_EXISTING
        0x00000080,  # FILE_ATTRIBUTE_NORMAL
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise CandidateError("unable to lock candidate input identity")
    try:
        yield handle
    finally:
        if not close(handle):
            raise CandidateError("unable to release candidate input identity")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path, *, label: str) -> dict[str, object]:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise CandidateError(f"duplicate JSON key in {label}")
            value[key] = item
        return value

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise CandidateError(f"invalid JSON: {label}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"JSON root is not an object: {label}")
    return value


def _decode_json_bytes(raw: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=lambda pairs: _unique_pairs(pairs, label=label),
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeError, ValueError) as exc:
        raise CandidateError(f"invalid reviewed JSON: {label}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"reviewed JSON root is not an object: {label}")
    return value


def _unique_pairs(
    pairs: list[tuple[str, object]],
    *,
    label: str,
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key in {label}")
        value[key] = item
    return value


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


def _git_bytes(arguments: tuple[str, ...], *, root: Path) -> bytes:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise CandidateError("unable to resolve reviewed Git identity")
    return completed.stdout


def _git_text(arguments: tuple[str, ...], *, root: Path) -> str:
    return _git_bytes(arguments, root=root).decode("utf-8").strip()


def _git_file(root: Path, commit: str, path: str) -> bytes:
    return _git_bytes(("show", f"{commit}:{path}"), root=root)


def _git_public_snapshot_sha256(root: Path, commit: str) -> str:
    try:
        allowlist = _git_file(
            root, commit, "policy/public-export-allowlist.txt"
        ).decode("utf-8")
    except UnicodeError as exc:
        raise CandidateError("public source allowlist is unreadable") from exc
    destinations = [
        line.strip()
        for line in allowlist.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    source_map_result = subprocess.run(
        (
            "git",
            "show",
            f"{commit}:policy/public-export-source-map.json",
        ),
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    mapping: dict[str, str] = {}
    if source_map_result.returncode == 0:
        document = _decode_json_bytes(
            source_map_result.stdout,
            label="public source mapping",
        )
        rows = document.get("mappings")
        if not isinstance(rows, list):
            raise CandidateError("public source mapping is malformed")
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"source", "destination"}
                or not isinstance(row.get("source"), str)
                or not isinstance(row.get("destination"), str)
            ):
                raise CandidateError("public source mapping is malformed")
            mapping[str(row["destination"])] = str(row["source"])
    digest = hashlib.sha256()
    for destination in sorted(destinations, key=str.casefold):
        source = mapping.get(destination, destination)
        encoded = destination.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(hashlib.sha256(_git_file(root, commit, source)).digest())
    return digest.hexdigest()


def _load_contract(root: Path) -> dict[str, object]:
    bundle = _read_json(
        root / "packaging" / "bundle-data.json",
        label="tracked bundle contract",
    )
    if set(bundle) != {
        "schema_version",
        "package",
        "source_root",
        "release",
        "allowed_data_files",
        "required_notice_files",
        "candidate",
    } or (
        bundle.get("schema_version") != 4
        or bundle.get("package") != "rcm"
        or bundle.get("source_root") != "src/rcm"
    ):
        raise CandidateError("tracked bundle contract schema is not exact")
    if bundle.get("release") != {
        "channel": "preview",
        "package_version": "2.2026.8.2a1",
        "display_version": "2.08.02a",
        "release_id": "rcm-2-2026-08-02-a",
        "tag": "v2.2026.08.02a",
        "sequence": 2026080201,
        "asset": "RCM-2.2026.08.02a-windows-x64.exe",
        "windows_version": "2.2026.802.1",
        "windows_tuple": [2, 2026, 802, 1],
        "architecture": "x86_64",
        "prerelease": True,
        "authenticode": False,
    }:
        raise CandidateError("tracked preview release identity is not exact")
    if (
        bundle.get("allowed_data_files")
        != ["src/rcm/resources/help.json"]
        or bundle.get("required_notice_files") != ["THIRD_PARTY_NOTICES.md"]
    ):
        raise CandidateError("tracked bundle data closure is not exact")
    candidate = bundle.get("candidate")
    if not isinstance(candidate, dict) or set(candidate) != {
        "state",
        "file",
        "size",
        "sha256",
        "public_source_snapshot_sha256",
        "package_manifest_sha256",
        "local_admin_elevation_enabled",
        "verification",
        "blockers",
    }:
        raise CandidateError("tracked candidate contract schema is not exact")
    if candidate.get("local_admin_elevation_enabled") is not False:
        raise CandidateError("tracked local admin capability is not exact")
    verification = candidate.get("verification")
    if not isinstance(verification, dict) or set(verification) != {
        "visible_quit_cycles",
        "hidden_show_quit_cycles",
        "minimized_show_quit_cycles",
        "passed_cycles",
        "evidence_sha256",
    }:
        raise CandidateError("tracked verification contract schema is not exact")
    state = candidate.get("state")
    passed = verification.get("passed_cycles")
    evidence_sha256 = verification.get("evidence_sha256")
    blockers = candidate.get("blockers")
    if (
        state not in {"built_unverified", "frozen"}
        or candidate.get("file") != "RayClusterManager-PR07.exe"
        or not isinstance(candidate.get("size"), int)
        or isinstance(candidate.get("size"), bool)
        or candidate.get("size", 0) <= 0
        or not isinstance(candidate.get("sha256"), str)
        or SHA256.fullmatch(str(candidate.get("sha256"))) is None
        or not isinstance(candidate.get("public_source_snapshot_sha256"), str)
        or SHA256.fullmatch(str(candidate.get("public_source_snapshot_sha256")))
        is None
        or not isinstance(candidate.get("package_manifest_sha256"), str)
        or SHA256.fullmatch(str(candidate.get("package_manifest_sha256")))
        is None
        or verification.get("visible_quit_cycles") != 50
        or verification.get("hidden_show_quit_cycles") != 25
        or verification.get("minimized_show_quit_cycles") != 25
        or not isinstance(blockers, list)
    ):
        raise CandidateError("tracked PR-07 candidate contract is not executable")
    if state == "built_unverified":
        if passed is not None or evidence_sha256 is not None or not blockers:
            raise CandidateError("unverified candidate contract is not fail-closed")
    elif (
        passed != RUN_COUNT
        or not isinstance(evidence_sha256, str)
        or SHA256.fullmatch(evidence_sha256) is None
        or blockers
    ):
        raise CandidateError("frozen candidate evidence contract is not exact")
    return candidate


def _validate_repository_source(
    *,
    root: Path,
    contract: Mapping[str, object],
    manifest: Mapping[str, object],
) -> tuple[str, int]:
    status = _git_text(
        ("status", "--porcelain=v1", "--untracked-files=all"),
        root=root,
    )
    if status:
        raise CandidateError("candidate verification requires a clean repository")
    source = manifest.get("source")
    build = manifest.get("build")
    digest = str(contract["public_source_snapshot_sha256"])
    if source != {"public_snapshot_sha256": digest, "repository_clean": True}:
        raise CandidateError("package source snapshot identity is not exact")
    epoch_value = build.get("source_date_epoch") if isinstance(build, dict) else None
    if type(epoch_value) is not int or epoch_value <= 0:
        raise CandidateError("package source epoch is malformed")
    commits = _git_text(("rev-list", "HEAD"), root=root).splitlines()
    matches: list[str] = []
    for commit in commits:
        if GIT_ID.fullmatch(commit) is None:
            raise CandidateError("reviewed Git history identity is malformed")
        if _git_public_snapshot_sha256(root, commit) == digest:
            matches.append(commit)
    if len(matches) != 1:
        raise CandidateError("package source snapshot is not one exact ancestor")
    return matches[0], epoch_value


def _expected_inputs(root: Path, commit: str) -> dict[str, object]:
    locks = {
        name: hashlib.sha256(
            _git_file(root, commit, f"requirements/{name}")
        ).hexdigest()
        for name in (
            "runtime-win-x86_64.lock",
            "build-win-x86_64.lock",
            "dev.lock",
        )
    }
    return {
        "dependency_provenance_sha256": hashlib.sha256(
            _git_file(root, commit, "policy/dependency-provenance.json")
        ).hexdigest(),
        "vendor_manifest_sha256": hashlib.sha256(
            _git_file(root, commit, "packaging/vendor-data.json")
        ).hexdigest(),
        "third_party_notices_sha256": hashlib.sha256(
            _git_file(root, commit, "THIRD_PARTY_NOTICES.md")
        ).hexdigest(),
        "lock_sha256": locks,
    }


def _expected_network_guard_sha256(root: Path, commit: str) -> str:
    try:
        tree = ast.parse(
            _git_file(root, commit, "scripts/build_windows_package.py")
        )
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("reviewed build script is not parseable") from exc
    for node in tree.body:
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if (
            isinstance(target, ast.Name)
            and target.id == "OFFLINE_SITECUSTOMIZE"
        ):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError) as exc:
                raise CandidateError(
                    "reviewed offline guard is not a literal"
                ) from exc
            if not isinstance(value, str):
                break
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
    raise CandidateError("reviewed offline guard identity is missing")


def _expected_windows_version_resource_sha256(
    root: Path,
    commit: str,
) -> str:
    try:
        tree = ast.parse(
            _git_file(root, commit, "scripts/build_windows_package.py")
        )
    except (SyntaxError, ValueError) as exc:
        raise CandidateError("reviewed build script is not parseable") from exc
    for node in tree.body:
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            target = node.target
        if (
            isinstance(target, ast.Name)
            and target.id == "WINDOWS_VERSION_RESOURCE"
        ):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError) as exc:
                raise CandidateError(
                    "reviewed version resource is not a literal"
                ) from exc
            if not isinstance(value, str):
                break
            return hashlib.sha256(value.encode("utf-8")).hexdigest()
    raise CandidateError("reviewed version resource identity is missing")


def _expected_bundled_files(root: Path, commit: str) -> tuple[list[str], int]:
    vendor = _decode_json_bytes(
        _git_file(root, commit, "packaging/vendor-data.json"),
        label="packaging/vendor-data.json",
    )
    records = vendor.get("files")
    if not isinstance(records, list) or len(records) != 10:
        raise CandidateError("reviewed vendor selection is not exact")
    destinations: list[str] = []
    total_size = 0
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("destination"), str)
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
        ):
            raise CandidateError("reviewed vendor record is malformed")
        destinations.append(str(record["destination"]))
        total_size += int(record["size"])
    return sorted(destinations) + [
        "THIRD_PARTY_NOTICES.md",
        "build-metadata/vendor-data.json",
        "rcm/resources/help.json",
    ], total_size


def _validate_manifest(
    *,
    manifest: Mapping[str, object],
    root: Path,
    commit: str,
    epoch: int,
    contract: Mapping[str, object],
) -> int:
    if set(manifest) != {
        "schema_version",
        "candidate",
        "source",
        "build",
        "inputs",
        "bundled_files",
        "required_modules",
        "bundled_module_count",
    } or manifest.get("schema_version") != 1:
        raise CandidateError("package manifest schema is not exact")
    candidate = manifest.get("candidate")
    source = manifest.get("source")
    build = manifest.get("build")
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"path", "size", "sha256"}
        or candidate.get("path") != "dist/RayClusterManager-PR07.exe"
        or candidate.get("size") != contract.get("size")
        or candidate.get("sha256") != contract.get("sha256")
    ):
        raise CandidateError("package manifest candidate identity is not exact")
    if (
        not isinstance(source, dict)
        or set(source) != {"public_snapshot_sha256", "repository_clean"}
        or source
        != {
            "public_snapshot_sha256": contract.get(
                "public_source_snapshot_sha256"
            ),
            "repository_clean": True,
        }
    ):
        raise CandidateError("package manifest source identity is not exact")
    if (
        not isinstance(build, dict)
        or set(build)
        != {
            "platform",
            "architecture",
            "python",
            "pip",
            "source_date_epoch",
            "network_access",
            "network_policy",
            "network_guard_sha256",
            "windows_version_resource_sha256",
            "output_inside_repository",
            "signing",
            "public_source_snapshot_sha256",
        }
        or not isinstance(build.get("platform"), str)
        or not str(build.get("platform")).startswith("Windows-")
        or str(build.get("architecture")).upper() not in {"AMD64", "X86_64"}
        or build.get("python") != EXPECTED_PYTHON_VERSION
        or build.get("pip") != EXPECTED_PIP_VERSION
        or build.get("source_date_epoch") != epoch
        or build.get("network_access") is not False
        or build.get("network_policy") != "python_socket_and_child_deny"
        or build.get("network_guard_sha256")
        != _expected_network_guard_sha256(root, commit)
        or build.get("windows_version_resource_sha256")
        != _expected_windows_version_resource_sha256(root, commit)
        or build.get("output_inside_repository") is not False
        or build.get("signing") is not False
        or build.get("public_source_snapshot_sha256")
        != contract.get("public_source_snapshot_sha256")
    ):
        raise CandidateError("package manifest build provenance is not exact")
    if manifest.get("inputs") != _expected_inputs(root, commit):
        raise CandidateError("package manifest input identities are not exact")
    expected_files, vendor_bytes = _expected_bundled_files(root, commit)
    if manifest.get("bundled_files") != expected_files:
        raise CandidateError("package manifest bundled-file closure is not exact")
    if manifest.get("required_modules") != EXPECTED_REQUIRED_MODULES:
        raise CandidateError("package manifest module closure is not exact")
    count = manifest.get("bundled_module_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < len(
        EXPECTED_REQUIRED_MODULES
    ):
        raise CandidateError("package manifest module count is invalid")
    return vendor_bytes


def _validate_identity(
    executable: Path,
    package_manifest: Path,
) -> tuple[Mapping[str, object], Mapping[str, object], int]:
    if not executable.is_absolute() or not package_manifest.is_absolute():
        raise CandidateError("candidate paths must be absolute")
    if (
        not executable.is_file()
        or _is_link_or_reparse(executable)
        or not package_manifest.is_file()
        or _is_link_or_reparse(package_manifest)
    ):
        raise CandidateError("candidate inputs must be regular non-link files")
    root = repository_root().resolve()
    if _is_within(executable.resolve(), root) or _is_within(
        package_manifest.resolve(),
        root,
    ):
        raise CandidateError("candidate inputs must remain outside the repository")
    contract = _load_contract(root)
    if (
        executable.name != contract["file"]
        or executable.stat().st_size != contract["size"]
        or _sha256(executable) != contract["sha256"]
        or _sha256(package_manifest) != contract["package_manifest_sha256"]
    ):
        raise CandidateError("candidate inputs do not match the tracked contract")
    manifest = _read_json(package_manifest, label="package manifest")
    commit, epoch = _validate_repository_source(
        root=root,
        contract=contract,
        manifest=manifest,
    )
    vendor_bytes = _validate_manifest(
        manifest=manifest,
        root=root,
        commit=commit,
        epoch=epoch,
        contract=contract,
    )
    return manifest, contract, vendor_bytes


def _load_psutil() -> object:
    try:
        module = importlib.import_module("psutil")
    except ImportError as exc:
        raise CandidateError(
            "candidate execution requires locked psutil 5.9.8"
        ) from exc
    if getattr(module, "__version__", None) != "5.9.8":
        raise CandidateError("candidate execution requires locked psutil 5.9.8")
    return module


def _network_counts(
    processes: list[object],
    psutil_module: object,
) -> tuple[int, int]:
    count = listeners = 0
    access_denied = getattr(psutil_module, "AccessDenied", ())
    process_gone = tuple(
        item
        for item in (
            getattr(psutil_module, "NoSuchProcess", None),
            getattr(psutil_module, "ZombieProcess", None),
        )
        if isinstance(item, type) and issubclass(item, BaseException)
    )
    listen_status = getattr(psutil_module, "CONN_LISTEN", "LISTEN")
    for process in processes:
        try:
            reader = getattr(process, "net_connections", None)
            if reader is None:
                reader = getattr(process, "connections")
            records = reader(kind="inet")
        except access_denied as exc:
            raise CandidateError(
                "network observation was denied"
            ) from exc
        except process_gone:
            # The process identity and executable were checked immediately
            # before this call. A clean exit between those observations and
            # the socket query has no remaining socket state to count.
            continue
        except Exception as exc:
            raise CandidateError("network observation failed") from exc
        count += len(records)
        listeners += sum(
            getattr(record, "status", None) == listen_status
            for record in records
        )
    return count, listeners


def _process_identity(process: object) -> tuple[int, float]:
    try:
        pid = getattr(process, "pid")
        created = process.create_time()
    except Exception as exc:
        raise CandidateError("process identity observation failed") from exc
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or isinstance(created, bool)
        or not isinstance(created, (int, float))
        or not math.isfinite(created)
        or created < 0
    ):
        raise CandidateError("process identity observation was malformed")
    return pid, float(created)


def _require_candidate_image(process: object, executable: Path) -> None:
    try:
        image = process.exe()
        matches = (
            isinstance(image, str)
            and bool(image)
            and os.path.samefile(image, executable)
        )
    except (OSError, RuntimeError) as exc:
        raise CandidateError("process image observation failed") from exc
    except Exception as exc:
        raise CandidateError("process image observation failed") from exc
    if not matches:
        raise CandidateError("onefile process image is not the reviewed candidate")


def _approved_onefile_processes(
    root_process: object,
    descendants: list[object],
    *,
    executable: Path,
    root_identity: tuple[int, float],
    bound_child: tuple[int, float] | None,
) -> tuple[tuple[object, ...], tuple[int, float] | None]:
    if len(descendants) > 1:
        raise CandidateError("onefile process lineage has extra descendants")
    if not descendants:
        return (root_process,), bound_child
    child = descendants[0]
    child_identity = _process_identity(child)
    try:
        parent_pid = child.ppid()
    except Exception as exc:
        try:
            exited = not child.is_running()
        except Exception:
            exited = False
        if exited and bound_child == child_identity:
            return (root_process,), bound_child
        raise CandidateError("onefile parent observation failed") from exc
    if (
        isinstance(parent_pid, bool)
        or parent_pid != root_identity[0]
        or child_identity[1] < root_identity[1]
    ):
        raise CandidateError("onefile child is not directly bound to the bootloader")
    try:
        _require_candidate_image(child, executable)
    except CandidateError:
        try:
            exited = not child.is_running()
        except Exception:
            exited = False
        if exited and bound_child == child_identity:
            return (root_process,), bound_child
        raise
    if bound_child is not None and child_identity != bound_child:
        raise CandidateError("onefile application child identity changed")
    return (root_process, child), child_identity


def _terminate_tree(
    process: subprocess.Popen[str],
    root_process: object,
    psutil_module: object,
    observed_processes: Mapping[int, object],
) -> None:
    try:
        descendants = root_process.children(recursive=True)
    except Exception:
        descendants = []
    targets_by_pid = dict(observed_processes)
    for target in [*descendants, root_process]:
        pid = getattr(target, "pid", None)
        if isinstance(pid, int):
            targets_by_pid[pid] = target
    targets = list(targets_by_pid.values())
    for target in targets:
        try:
            target.terminate()
        except Exception:
            continue
    try:
        _, alive = psutil_module.wait_procs(targets, timeout=2)
    except Exception:
        alive = targets
    for target in alive:
        try:
            target.kill()
        except Exception:
            continue
    try:
        psutil_module.wait_procs(alive, timeout=2)
    except Exception:
        pass
    if process.poll() is None:
        process.kill()
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def _residue_pids(
    observed_identities: Mapping[int, float],
    psutil_module: object,
) -> list[int]:
    residue: list[int] = []
    for pid, created in sorted(observed_identities.items()):
        try:
            process = psutil_module.Process(pid)
            if float(process.create_time()) != created:
                continue
            if process.status() != psutil_module.STATUS_ZOMBIE:
                residue.append(pid)
        except (
            psutil_module.NoSuchProcess,
            psutil_module.ZombieProcess,
        ):
            continue
        except psutil_module.AccessDenied:
            # Inability to prove cleanup is residue, not a reason to pass.
            residue.append(pid)
        except Exception:
            residue.append(pid)
    return residue


def _await_no_residue(
    observed_identities: Mapping[int, float],
    psutil_module: object,
    *,
    timeout_seconds: float = 1.0,
) -> list[int]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        residue = _residue_pids(observed_identities, psutil_module)
        if not residue or time.monotonic() >= deadline:
            return residue
        time.sleep(0.01)


def _classify_main_windows(
    records: list[tuple[int, int, str, str, bool, bool]],
    pids: set[int],
) -> str:
    matches = [
        record
        for record in records
        if record[1] in pids
        and record[2] == MAIN_WINDOW_TITLE
        and record[3] == MAIN_WINDOW_CLASS
    ]
    if not matches:
        return WINDOW_ABSENT
    if len(matches) != 1:
        raise CandidateError("candidate main-window identity is ambiguous")
    _, _, _, _, visible, iconic = matches[0]
    if not visible:
        return WINDOW_HIDDEN
    return WINDOW_MINIMIZED if iconic else WINDOW_VISIBLE


def _main_window_state(pids: set[int]) -> str:
    if os.name != "nt":
        raise CandidateError("window observation requires Windows")
    import ctypes
    from ctypes import wintypes

    records: list[tuple[int, int, str, str, bool, bool]] = []
    failure: list[str] = []
    enum_windows = ctypes.windll.user32.EnumWindows
    get_pid = ctypes.windll.user32.GetWindowThreadProcessId
    get_title = ctypes.windll.user32.GetWindowTextW
    get_class = ctypes.windll.user32.GetClassNameW
    is_visible = ctypes.windll.user32.IsWindowVisible
    is_iconic = ctypes.windll.user32.IsIconic
    get_pid.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    get_pid.restype = wintypes.DWORD
    get_title.argtypes = (
        wintypes.HWND,
        wintypes.LPWSTR,
        ctypes.c_int,
    )
    get_title.restype = ctypes.c_int
    get_class.argtypes = get_title.argtypes
    get_class.restype = ctypes.c_int
    is_visible.argtypes = (wintypes.HWND,)
    is_visible.restype = wintypes.BOOL
    is_iconic.argtypes = (wintypes.HWND,)
    is_iconic.restype = wintypes.BOOL

    callback_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HWND,
        wintypes.LPARAM,
    )

    @callback_type
    def observe(hwnd: int, _parameter: int) -> bool:
        pid = wintypes.DWORD()
        if not get_pid(hwnd, ctypes.byref(pid)):
            failure.append("unable to identify enumerated window owner")
            return False
        if int(pid.value) not in pids:
            return True
        title = ctypes.create_unicode_buffer(256)
        window_class = ctypes.create_unicode_buffer(256)
        get_title(hwnd, title, len(title))
        if not get_class(hwnd, window_class, len(window_class)):
            failure.append("unable to identify candidate window class")
            return False
        records.append(
            (
                int(hwnd),
                int(pid.value),
                title.value,
                window_class.value,
                bool(is_visible(hwnd)),
                bool(is_iconic(hwnd)),
            )
        )
        return True

    enum_windows.argtypes = (callback_type, wintypes.LPARAM)
    enum_windows.restype = wintypes.BOOL
    if not enum_windows(observe, 0) or failure:
        raise CandidateError("unable to enumerate candidate windows")
    return _classify_main_windows(records, pids)


def _coalesced_window_states(observations: list[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in observations:
        if not result or result[-1] != value:
            result.append(value)
    return tuple(result)


def _window_sequence_passes(
    scenario: str,
    observations: list[str],
) -> bool:
    expected = {
        "visible-quit": (WINDOW_VISIBLE,),
        "close-show-quit": (
            WINDOW_VISIBLE,
            WINDOW_HIDDEN,
            WINDOW_VISIBLE,
        ),
        "minimized-show-quit": (WINDOW_MINIMIZED, WINDOW_VISIBLE),
    }.get(scenario)
    if expected is None:
        return False
    sequence = list(_coalesced_window_states(observations))
    if sequence and sequence[0] == WINDOW_ABSENT:
        sequence.pop(0)
    if sequence and sequence[0] == WINDOW_HIDDEN:
        sequence.pop(0)
    if tuple(sequence[: len(expected)]) != expected:
        return False
    tail = tuple(sequence[len(expected) :])
    return tail in {
        (),
        (WINDOW_HIDDEN,),
        (WINDOW_ABSENT,),
        (WINDOW_HIDDEN, WINDOW_ABSENT),
    }


def _validation_mutex_residue() -> int:
    if os.name != "nt":
        raise CandidateError("validation mutex probe requires Windows")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateMutexW
    create.argtypes = (ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR)
    create.restype = wintypes.HANDLE
    close = kernel32.CloseHandle
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    ctypes.set_last_error(0)
    handle = create(None, False, VALIDATION_MUTEX_NAME)
    if not handle:
        raise CandidateError("unable to probe validation mutex residue")
    existed = ctypes.get_last_error() == 183
    if not close(handle):
        raise CandidateError("unable to close validation mutex probe")
    return int(existed)


def _run_once(
    executable: Path,
    *,
    scenario: str,
    psutil_module: object,
    expected_size: int,
    expected_sha256: str,
) -> tuple[dict[str, object], list[int]]:
    with tempfile.TemporaryDirectory(
        prefix="rcm-preview-lifecycle-"
    ) as temporary:
        temporary_root = Path(temporary)
        if _is_link_or_reparse(temporary_root):
            raise CandidateError("run-owned temporary root is not regular")
        return _run_once_isolated(
            executable,
            scenario=scenario,
            psutil_module=psutil_module,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            temporary_root=temporary_root,
        )


def _run_once_isolated(
    executable: Path,
    *,
    scenario: str,
    psutil_module: object,
    expected_size: int,
    expected_sha256: str,
    temporary_root: Path,
) -> tuple[dict[str, object], list[int]]:
    if scenario not in SCENARIO_COUNTS:
        raise CandidateError("lifecycle scenario is not reviewed")
    if (
        executable.stat().st_size != expected_size
        or _sha256(executable) != expected_sha256
    ):
        raise CandidateError("locked candidate identity changed before execution")
    environment = {
        key: os.environ.get(key, "")
        for key in (
            "COMSPEC",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "WINDIR",
        )
    }
    environment.update(
        {
            "RCM_NETWORK_POLICY": "deny",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "TEMP": str(temporary_root),
            "TMP": str(temporary_root),
        }
    )
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            (str(executable), "--lifecycle-check", scenario),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=environment,
            creationflags=flags,
        )
    except OSError as exc:
        raise CandidateError("unable to start reviewed candidate") from exc
    maximum_connections = 0
    maximum_listeners = 0
    maximum_descendants = 0
    window_states: list[str] = []
    first_ready: float | None = None
    try:
        root_process = psutil_module.Process(process.pid)
        root_identity = _process_identity(root_process)
        if root_identity[0] != process.pid:
            raise CandidateError("bootloader process identity is not exact")
        _require_candidate_image(root_process, executable)
    except Exception as exc:
        process.kill()
        process.communicate()
        raise CandidateError("unable to observe candidate process") from exc
    observed_processes: dict[int, object] = {process.pid: root_process}
    observed_identities = {root_identity[0]: root_identity[1]}
    bound_child: tuple[int, float] | None = None
    try:
        deadline = started + 10.0
        while process.poll() is None:
            observed_at = time.monotonic()
            if observed_at >= deadline:
                raise CandidateError("candidate lifecycle check timed out")
            try:
                descendants = root_process.children(recursive=True)
            except (
                psutil_module.NoSuchProcess,
                psutil_module.ZombieProcess,
            ) as exc:
                if process.poll() is None:
                    raise CandidateError(
                        "process exited during descendant observation"
                    ) from exc
                break
            except psutil_module.AccessDenied as exc:
                raise CandidateError(
                    "descendant observation was denied"
                ) from exc
            except Exception as exc:
                raise CandidateError(
                    "descendant observation failed"
                ) from exc
            active, bound_child = _approved_onefile_processes(
                root_process,
                descendants,
                executable=executable,
                root_identity=root_identity,
                bound_child=bound_child,
            )
            active_identities = tuple(_process_identity(item) for item in active)
            for identity, item in zip(active_identities, active, strict=True):
                previous = observed_identities.get(identity[0])
                if previous is not None and previous != identity[1]:
                    raise CandidateError("observed process identity was reused")
                observed_identities[identity[0]] = identity[1]
                observed_processes[identity[0]] = item
            maximum_descendants = max(maximum_descendants, len(descendants))
            connections, listeners = _network_counts(
                list(active),
                psutil_module,
            )
            maximum_connections = max(maximum_connections, connections)
            maximum_listeners = max(maximum_listeners, listeners)
            window_state = _main_window_state(
                {identity[0] for identity in active_identities}
            )
            window_states.append(window_state)
            expected_ready = (
                WINDOW_MINIMIZED
                if scenario == "minimized-show-quit"
                else WINDOW_VISIBLE
            )
            if window_state == expected_ready and first_ready is None:
                first_ready = observed_at
            time.sleep(0.005)
        stdout, stderr = process.communicate(timeout=5)
        if process.returncode != 0:
            raise CandidateError(
                f"candidate exited with code {process.returncode}"
            )
        if stderr.strip():
            raise CandidateError("candidate wrote unexpected standard error")
        if stdout.strip():
            raise CandidateError("candidate wrote unexpected standard output")
        finished = time.monotonic()
        if (
            first_ready is None
            or first_ready - started > 5.0
            or finished - first_ready > 5.0
            or not _window_sequence_passes(scenario, window_states)
            or maximum_connections != 0
            or maximum_listeners != 0
            or maximum_descendants != 1
            or bound_child is None
        ):
            reason = next(
                label
                for failed, label in (
                    (first_ready is None, "window_absent"),
                    (first_ready is not None and first_ready - started > 5.0,
                     "startup_timeout"),
                    (first_ready is not None and finished - first_ready > 5.0,
                     "shutdown_timeout"),
                    (not _window_sequence_passes(scenario, window_states),
                     "window_sequence"),
                    (maximum_connections != 0, "network_connection"),
                    (maximum_listeners != 0, "network_listener"),
                    (maximum_descendants != 1, "process_lineage"),
                    (bound_child is None, "child_unbound"),
                )
                if failed
            )
            raise CandidateError(
                f"candidate lifecycle observation failed: {reason}"
            )
    except BaseException as exc:
        _terminate_tree(
            process,
            root_process,
            psutil_module,
            observed_processes,
        )
        if _await_no_residue(observed_identities, psutil_module):
            raise CandidateError(
                "candidate cleanup left process residue"
            ) from exc
        raise
    if (
        executable.stat().st_size != expected_size
        or _sha256(executable) != expected_sha256
    ):
        _terminate_tree(
            process,
            root_process,
            psutil_module,
            observed_processes,
        )
        if _await_no_residue(observed_identities, psutil_module):
            raise CandidateError("candidate cleanup left process residue")
        raise CandidateError("locked candidate identity changed during execution")
    residue = _await_no_residue(observed_identities, psutil_module)
    if residue:
        _terminate_tree(
            process,
            root_process,
            psutil_module,
            observed_processes,
        )
        if _await_no_residue(observed_identities, psutil_module):
            raise CandidateError("candidate cleanup left process residue")
    temporary_residue = sum(1 for _path in temporary_root.rglob("*"))
    mutex_residue = _validation_mutex_residue()
    if temporary_residue or mutex_residue:
        reason = (
            "temporary_artifact_residue"
            if temporary_residue
            else "mutex_residue"
        )
        raise CandidateError(
            f"candidate lifecycle observation failed: {reason}"
        )
    receipt = {
        "scenario": scenario,
        "duration_ms": int(round((finished - started) * 1000)),
        "ready_ms": int(round((first_ready - started) * 1000)),
        "window_states": list(_coalesced_window_states(window_states)),
        "maximum_network_connections": maximum_connections,
        "maximum_network_listeners": maximum_listeners,
        "maximum_descendants": maximum_descendants,
        "temporary_artifact_residue": temporary_residue,
        "mutex_residue": mutex_residue,
        "exit_code": process.returncode,
    }
    return receipt, residue


def _validate_evidence_path(evidence: Path, *, must_exist: bool) -> Path:
    if not evidence.is_absolute():
        raise CandidateError("evidence path must be absolute")
    if must_exist and (
        not evidence.is_file() or _is_link_or_reparse(evidence)
    ):
        raise CandidateError("frozen evidence must be a regular non-link file")
    resolved = evidence.resolve(strict=False)
    if _is_within(resolved, repository_root().resolve()):
        raise CandidateError("evidence must remain outside the repository")
    if not must_exist and resolved.exists():
        raise CandidateError("evidence path must not already exist")
    current = resolved.parent
    while not current.exists():
        if current == current.parent:
            break
        current = current.parent
    if _is_link_or_reparse(current):
        raise CandidateError("evidence path cannot traverse a link or reparse point")
    return resolved


def _evidence_value(
    *,
    manifest: Mapping[str, object],
    receipts: list[dict[str, object]],
    vendor_bytes: int,
    residue_count: int,
) -> dict[str, object]:
    scenarios = {
        scenario: sum(item["scenario"] == scenario for item in receipts)
        for scenario in SCENARIO_COUNTS
    }
    claims = {
        name: dict(assertion)
        for name, assertion in CLAIM_ASSERTIONS.items()
    }
    return {
        "schema_version": 5,
        "candidate": manifest["candidate"],
        "source": manifest["source"],
        "lifecycle": {
            "requested": RUN_COUNT,
            "passed": len(receipts),
            "failed": 0,
            "not_run": RUN_COUNT - len(receipts),
            "scenarios": scenarios,
            "receipts": receipts,
        },
        "observations": {
            "maximum_ready_ms": max(
                int(item["ready_ms"]) for item in receipts
            ),
            "maximum_duration_ms": max(
                int(item["duration_ms"]) for item in receipts
            ),
            "maximum_network_connections": max(
                int(item["maximum_network_connections"]) for item in receipts
            ),
            "maximum_network_listeners": max(
                int(item["maximum_network_listeners"]) for item in receipts
            ),
            "maximum_descendants": max(
                int(item["maximum_descendants"]) for item in receipts
            ),
            "process_residue": residue_count,
            "temporary_artifact_residue": max(
                int(item["temporary_artifact_residue"])
                for item in receipts
            ),
            "mutex_residue": max(
                int(item["mutex_residue"]) for item in receipts
            ),
            "vendor_bytes": vendor_bytes,
            "claims": claims,
            "blockers": [],
        },
    }


def _validate_frozen_evidence(
    *,
    evidence: Path,
    manifest: Mapping[str, object],
    contract: Mapping[str, object],
    vendor_bytes: int,
) -> str:
    try:
        raw = evidence.read_bytes()
    except OSError as exc:
        raise CandidateError("unable to read frozen evidence") from exc
    expected_digest = str(
        dict(contract["verification"])["evidence_sha256"]
    )
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_digest:
        raise CandidateError("frozen evidence hash does not match contract")
    value = _decode_json_bytes(raw, label="frozen evidence")
    if raw != _canonical_bytes(value):
        raise CandidateError("frozen evidence is not canonical JSON")
    if (
        set(value)
        != {"schema_version", "candidate", "source", "lifecycle", "observations"}
        or value.get("schema_version") != 5
        or value.get("candidate") != manifest["candidate"]
        or value.get("source") != manifest["source"]
    ):
        raise CandidateError("frozen evidence identity is not exact")
    lifecycle = value.get("lifecycle")
    if not isinstance(lifecycle, dict) or set(lifecycle) != {
        "requested",
        "passed",
        "failed",
        "not_run",
        "scenarios",
        "receipts",
    }:
        raise CandidateError("frozen lifecycle evidence schema is not exact")
    receipts = lifecycle.get("receipts")
    if (
        any(
            type(lifecycle.get(name)) is not int
            for name in ("requested", "passed", "failed", "not_run")
        )
        or lifecycle.get("requested") != RUN_COUNT
        or lifecycle.get("passed") != RUN_COUNT
        or lifecycle.get("failed") != 0
        or lifecycle.get("not_run") != 0
        or lifecycle.get("scenarios") != SCENARIO_COUNTS
        or not isinstance(receipts, list)
        or len(receipts) != RUN_COUNT
    ):
        raise CandidateError("frozen lifecycle evidence is incomplete")
    scenario_results = dict.fromkeys(SCENARIO_COUNTS, 0)
    for receipt in receipts:
        if not isinstance(receipt, dict) or set(receipt) != {
            "scenario",
            "duration_ms",
            "ready_ms",
            "window_states",
            "maximum_network_connections",
            "maximum_network_listeners",
            "maximum_descendants",
            "temporary_artifact_residue",
            "mutex_residue",
            "exit_code",
        }:
            raise CandidateError("frozen lifecycle receipt schema is not exact")
        scenario = receipt.get("scenario")
        ready = receipt.get("ready_ms")
        duration = receipt.get("duration_ms")
        states = receipt.get("window_states")
        if (
            scenario not in SCENARIO_COUNTS
            or type(ready) is not int
            or type(duration) is not int
            or ready < 0
            or ready > 5000
            or duration < ready
            or duration - ready > 5000
            or not isinstance(states, list)
            or not all(isinstance(item, str) for item in states)
            or any(item not in WINDOW_STATES for item in states)
            or states != list(_coalesced_window_states(states))
            or not _window_sequence_passes(str(scenario), states)
            or any(
                type(receipt.get(name)) is not int
                for name in (
                    "maximum_network_connections",
                    "maximum_network_listeners",
                    "maximum_descendants",
                    "temporary_artifact_residue",
                    "mutex_residue",
                    "exit_code",
                )
            )
            or receipt.get("maximum_network_connections") != 0
            or receipt.get("maximum_network_listeners") != 0
            or receipt.get("maximum_descendants") != 1
            or receipt.get("temporary_artifact_residue") != 0
            or receipt.get("mutex_residue") != 0
            or receipt.get("exit_code") != 0
        ):
            raise CandidateError("frozen lifecycle receipt assertion failed")
        scenario_results[str(scenario)] += 1
    observations = value.get("observations")
    complete_claims = {
        name: dict(assertion)
        for name, assertion in CLAIM_ASSERTIONS.items()
    }
    expected_observations = {
        "maximum_ready_ms": max(int(item["ready_ms"]) for item in receipts),
        "maximum_duration_ms": max(
            int(item["duration_ms"]) for item in receipts
        ),
        "maximum_network_connections": 0,
        "maximum_network_listeners": 0,
        "maximum_descendants": 1,
        "process_residue": 0,
        "temporary_artifact_residue": 0,
        "mutex_residue": 0,
        "vendor_bytes": vendor_bytes,
        "claims": complete_claims,
        "blockers": [],
    }
    claims = (
        observations.get("claims")
        if isinstance(observations, dict)
        else None
    )
    if (
        scenario_results != SCENARIO_COUNTS
        or not isinstance(observations, dict)
        or any(
            type(observations.get(name)) is not int
            for name in (
                "maximum_ready_ms",
                "maximum_duration_ms",
                "maximum_network_connections",
                "maximum_network_listeners",
                "maximum_descendants",
                "process_residue",
                "temporary_artifact_residue",
                "mutex_residue",
                "vendor_bytes",
            )
        )
        or not isinstance(claims, dict)
        or claims != complete_claims
        or observations != expected_observations
    ):
        raise CandidateError("frozen evidence aggregate assertion failed")
    return digest


def verify(
    *,
    executable: Path,
    package_manifest: Path,
    evidence: Path,
    supplemental_evidence: Path | None = None,
) -> Path:
    with _hold_windows_file(executable), _hold_windows_file(package_manifest):
        manifest, contract, vendor_bytes = _validate_identity(
            executable,
            package_manifest,
        )
        if contract["state"] == "frozen":
            frozen_evidence = _validate_evidence_path(
                evidence,
                must_exist=True,
            )
            digest = _validate_frozen_evidence(
                evidence=frozen_evidence,
                manifest=manifest,
                contract=contract,
                vendor_bytes=vendor_bytes,
            )
            if supplemental_evidence is None:
                print(f"PASS: frozen lifecycle evidence ({RUN_COUNT} cycles)")
                print(f"evidence_sha256: {digest}")
                print("evidence_validated=true")
                return frozen_evidence
            resolved_evidence = _validate_evidence_path(
                supplemental_evidence,
                must_exist=False,
            )
        else:
            if supplemental_evidence is not None:
                raise CandidateError(
                    "supplemental evidence requires a frozen candidate"
                )
            resolved_evidence = _validate_evidence_path(
                evidence,
                must_exist=False,
            )
        psutil_module = _load_psutil()
        receipts: list[dict[str, object]] = []
        residue: set[int] = set()
        for scenario, count in SCENARIO_COUNTS.items():
            for _ in range(count):
                receipt, run_residue = _run_once(
                    executable,
                    scenario=scenario,
                    psutil_module=psutil_module,
                    expected_size=int(contract["size"]),
                    expected_sha256=str(contract["sha256"]),
                )
                receipts.append(receipt)
                residue.update(run_residue)
    if len(receipts) != RUN_COUNT or residue:
        raise CandidateError("candidate lifecycle count or process residue failed")
    evidence_value = _evidence_value(
        manifest=manifest,
        receipts=receipts,
        vendor_bytes=vendor_bytes,
        residue_count=len(residue),
    )
    if evidence_value["lifecycle"]["scenarios"] != SCENARIO_COUNTS:
        raise CandidateError("candidate lifecycle scenario partition is not exact")
    evidence_bytes = _canonical_bytes(evidence_value)
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    resolved_evidence.parent.mkdir(parents=True, exist_ok=True)
    with resolved_evidence.open("xb") as stream:
        stream.write(evidence_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    prefix = (
        "SUPPLEMENTAL OBSERVED"
        if contract["state"] == "frozen"
        else "LIFECYCLE OBSERVED"
    )
    print(f"{prefix}: {RUN_COUNT}/{RUN_COUNT} packaged lifecycle cycles")
    observations = evidence_value["observations"]
    print(
        "connections="
        f"{observations['maximum_network_connections']} "
        f"listeners={observations['maximum_network_listeners']} "
        f"descendants={observations['maximum_descendants']} "
        f"process_residue={observations['process_residue']}"
    )
    print("blockers=0")
    print(f"evidence_sha256: {evidence_digest}")
    print("evidence_created=true")
    return resolved_evidence


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the repository-anchored PR-07 candidate lifecycle."
    )
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--supplemental-evidence", type=Path)
    arguments = parser.parse_args()
    try:
        verify(
            executable=arguments.executable,
            package_manifest=arguments.package_manifest,
            evidence=arguments.evidence,
            supplemental_evidence=arguments.supplemental_evidence,
        )
    except CandidateError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except OSError:
        print("FAIL: candidate verification I/O failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
