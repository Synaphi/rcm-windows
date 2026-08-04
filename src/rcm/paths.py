"""Pure runtime path planning for Ray Cluster Manager."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Protocol, TypeAlias

from .identity import ApplicationIdentity, DeploymentKind


PathValue: TypeAlias = str | PurePath

_WINDOWS_NAMESPACE_PREFIXES = (
    "//?/",
    "//./",
    "/??/",
    "/device/",
)


def _portable_text(value: PathValue, *, label: str) -> str:
    if not isinstance(value, (str, PurePath)):
        raise TypeError(f"{label} must be a string or pure path")
    text = str(value)
    if not text:
        raise ValueError(f"{label} must not be empty")
    if "\x00" in text:
        raise ValueError(f"{label} contains a null byte")
    return text


def _reject_remote_or_namespace(text: str, *, label: str) -> None:
    portable = text.replace("\\", "/")
    folded = portable.casefold()
    if portable.startswith("//") or folded.startswith(
        _WINDOWS_NAMESPACE_PREFIXES
    ):
        raise ValueError(f"{label} must be a local, non-namespace path")


def _pure_path(value: PathValue, *, label: str) -> PurePath:
    text = _portable_text(value, label=label)
    _reject_remote_or_namespace(text, label=label)

    windows = PureWindowsPath(text)
    if windows.drive or "\\" in text:
        return windows
    return PurePosixPath(text)


def absolute_local_path(value: PathValue, *, label: str = "path") -> PurePath:
    """Validate and return an absolute local path without touching the host."""

    path = _pure_path(value, label=label)
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if any(part == ".." for part in path.parts):
        raise ValueError(f"{label} must not contain traversal segments")
    return path


def safe_relative_path(
    value: PathValue,
    *,
    label: str = "relative path",
) -> PurePath:
    """Validate an application-relative path.

    Absolute, drive-qualified, UNC, device/namespace, traversal, and NTFS
    alternate-data-stream syntax are rejected before any joining occurs.
    """

    text = _portable_text(value, label=label)
    _reject_remote_or_namespace(text, label=label)
    portable = text.replace("\\", "/")
    windows = PureWindowsPath(text)
    if (
        portable.startswith("/")
        or windows.drive
        or windows.root
        or ":" in portable
    ):
        raise ValueError(f"{label} must be relative and drive-free")

    parts = portable.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"{label} contains an unsafe path segment")
    return PurePosixPath(*parts)


def join_relative(root: PathValue, relative: PathValue) -> PurePath:
    """Join a validated relative path to a validated local root."""

    base = absolute_local_path(root, label="root")
    child = safe_relative_path(relative)
    return base.joinpath(*child.parts)


def _paths_overlap(first: PurePath, second: PurePath) -> bool:
    """Return whether either lexical path contains the other."""

    def key(path: PurePath) -> tuple[str, ...]:
        if isinstance(path, PureWindowsPath):
            return tuple(part.casefold() for part in path.parts)
        return tuple(path.parts)

    left = key(first)
    right = key(second)
    return (
        left == right[:len(left)]
        or right == left[:len(right)]
    )


@dataclass(frozen=True, slots=True)
class KnownFolders:
    """Windows Known Folder values supplied by a platform adapter."""

    local_app_data: PurePath

    def __init__(self, *, local_app_data: PathValue) -> None:
        object.__setattr__(
            self,
            "local_app_data",
            absolute_local_path(
                local_app_data,
                label="LocalAppData known folder",
            ),
        )


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """Resolved application paths; constructing this object performs no I/O."""

    application_root: PurePath
    resource_root: PurePath
    current_binary: PurePath
    config_directory: PurePath
    log_directory: PurePath
    rdp_directory: PurePath
    config_file: PurePath
    application_log: PurePath
    trouble_log: PurePath
    process_cleanup_log: PurePath

    def resource(self, relative: PathValue) -> PurePath:
        return join_relative(self.resource_root, relative)


def plan_runtime_paths(
    *,
    identity: ApplicationIdentity,
    known_folders: KnownFolders,
    application_root: PathValue,
    resource_root: PathValue,
    current_binary: PathValue,
) -> RuntimePaths:
    """Resolve dev, portable, or installed paths without probing the host."""

    if not isinstance(identity, ApplicationIdentity):
        raise TypeError("identity must be an ApplicationIdentity")
    if not isinstance(known_folders, KnownFolders):
        raise TypeError("known_folders must be KnownFolders")

    app_root = absolute_local_path(
        application_root,
        label="application root",
    )
    resources = absolute_local_path(resource_root, label="resource root")
    binary = absolute_local_path(current_binary, label="current binary")

    if identity.deployment is DeploymentKind.PORTABLE:
        config_directory = app_root / "data"
    else:
        config_directory = (
            known_folders.local_app_data / identity.config_namespace
        )
    log_directory = config_directory / "logs"
    rdp_directory = (
        known_folders.local_app_data / identity.config_namespace / "rdp"
    )
    if (
        identity.deployment is DeploymentKind.PORTABLE
        and (
            _paths_overlap(app_root, rdp_directory)
            or _paths_overlap(binary.parent, rdp_directory)
        )
    ):
        raise ValueError(
            "portable RDP artifacts require separate per-user LocalAppData"
        )

    return RuntimePaths(
        application_root=app_root,
        resource_root=resources,
        current_binary=binary,
        config_directory=config_directory,
        log_directory=log_directory,
        rdp_directory=rdp_directory,
        config_file=config_directory / "config.json",
        application_log=log_directory / "ray_monitor.log",
        trouble_log=log_directory / "trouble_log.log",
        process_cleanup_log=log_directory / "process_cleanup.log",
    )


@dataclass(frozen=True, slots=True)
class EnsureDirectory:
    """A directory creation operation that has not been applied yet."""

    path: PurePath
    parents: bool = True
    exist_ok: bool = True


def directory_plan(paths: RuntimePaths) -> tuple[EnsureDirectory, ...]:
    """Return the deterministic startup directory plan."""

    if not isinstance(paths, RuntimePaths):
        raise TypeError("paths must be RuntimePaths")
    return (
        EnsureDirectory(paths.config_directory),
        EnsureDirectory(paths.log_directory),
        EnsureDirectory(paths.rdp_directory),
    )


class DirectoryFilesystem(Protocol):
    """Minimal filesystem capability required to apply a directory plan."""

    def mkdir(
        self,
        path: str,
        *,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        """Create one directory."""


def ensure_directories(
    operations: tuple[EnsureDirectory, ...],
    filesystem: DirectoryFilesystem,
) -> None:
    """Explicitly apply a previously inspected directory plan."""

    for operation in operations:
        if not isinstance(operation, EnsureDirectory):
            raise TypeError("operations must contain EnsureDirectory values")
        filesystem.mkdir(
            str(operation.path),
            parents=operation.parents,
            exist_ok=operation.exist_ok,
        )
