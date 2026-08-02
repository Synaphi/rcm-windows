"""Import-safe application bootstrap planning and launcher seams."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import import_module
from types import MappingProxyType
from typing import Any, Protocol

from .identity import ApplicationIdentity, DeploymentKind, identity_for
from .paths import (
    DirectoryFilesystem,
    EnsureDirectory,
    KnownFolders,
    PathValue,
    RuntimePaths,
    directory_plan,
    ensure_directories,
    plan_runtime_paths,
)


RUNTIME_MODE_ENVIRONMENT_KEY = "RCM_RUNTIME_MODE"
PORTABLE_ENVIRONMENT_KEY = "RCM_PORTABLE"


@dataclass(frozen=True, slots=True)
class Environment:
    """Immutable, explicitly supplied environment values.

    Keys are normalized case-insensitively to match Windows environment
    semantics.  Constructing this value never reads ``os.environ``.
    """

    _values: Mapping[str, str]

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        copied: dict[str, str] = {}
        for key, value in (values or {}).items():
            if not isinstance(key, str) or not key:
                raise ValueError("environment keys must be non-empty strings")
            if not isinstance(value, str):
                raise ValueError("environment values must be strings")
            copied[key.upper()] = value
        object.__setattr__(self, "_values", MappingProxyType(copied))

    def get(self, key: str, default: str | None = None) -> str | None:
        if not isinstance(key, str) or not key:
            raise ValueError("environment key must be a non-empty string")
        return self._values.get(key.upper(), default)


def select_deployment(
    environment: Environment,
    *,
    frozen: bool,
) -> DeploymentKind:
    """Select a layout from injected process facts.

    ``RCM_RUNTIME_MODE`` is the canonical override.  ``RCM_PORTABLE=1`` is a
    narrow compatibility flag.  Without either, frozen applications are
    installed and source runs are development.
    """

    if not isinstance(environment, Environment):
        raise TypeError("environment must be an Environment")
    if not isinstance(frozen, bool):
        raise TypeError("frozen must be a bool")

    explicit = environment.get(RUNTIME_MODE_ENVIRONMENT_KEY)
    portable_flag = environment.get(PORTABLE_ENVIRONMENT_KEY)
    if portable_flag not in (None, "", "0", "1"):
        raise ValueError("RCM_PORTABLE must be 0 or 1")

    if explicit is not None and explicit.strip():
        normalized = explicit.strip().casefold()
        aliases = {
            "dev": DeploymentKind.DEVELOPMENT,
            "development": DeploymentKind.DEVELOPMENT,
            "portable": DeploymentKind.PORTABLE,
            "installed": DeploymentKind.INSTALLED,
        }
        try:
            selected = aliases[normalized]
        except KeyError as exc:
            raise ValueError("RCM_RUNTIME_MODE is not supported") from exc
        if portable_flag == "1" and selected is not DeploymentKind.PORTABLE:
            raise ValueError("runtime mode conflicts with RCM_PORTABLE=1")
        return selected

    if portable_flag == "1":
        return DeploymentKind.PORTABLE
    return (
        DeploymentKind.INSTALLED
        if frozen
        else DeploymentKind.DEVELOPMENT
    )


@dataclass(frozen=True, slots=True)
class BootstrapRequest:
    """All host-derived facts needed to plan startup."""

    environment: Environment
    known_folders: KnownFolders
    application_root: PathValue
    resource_root: PathValue
    current_binary: PathValue
    frozen: bool


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    """A complete startup plan with no applied side effects."""

    identity: ApplicationIdentity
    paths: RuntimePaths
    directories: tuple[EnsureDirectory, ...]


def plan_bootstrap(request: BootstrapRequest) -> BootstrapPlan:
    """Build a deterministic bootstrap plan from injected facts."""

    if not isinstance(request, BootstrapRequest):
        raise TypeError("request must be a BootstrapRequest")
    deployment = select_deployment(
        request.environment,
        frozen=request.frozen,
    )
    identity = identity_for(deployment)
    paths = plan_runtime_paths(
        identity=identity,
        known_folders=request.known_folders,
        application_root=request.application_root,
        resource_root=request.resource_root,
        current_binary=request.current_binary,
    )
    return BootstrapPlan(
        identity=identity,
        paths=paths,
        directories=directory_plan(paths),
    )


def ensure_bootstrap_directories(
    plan: BootstrapPlan,
    filesystem: DirectoryFilesystem,
) -> None:
    """Apply only the directory operations in *plan*."""

    if not isinstance(plan, BootstrapPlan):
        raise TypeError("plan must be a BootstrapPlan")
    ensure_directories(plan.directories, filesystem)


class Launcher(Protocol):
    def __call__(self) -> object:
        """Start an application and optionally return an exit code."""


@dataclass(frozen=True, slots=True)
class CompatibilityLauncher:
    """Lazy bridge to the unchanged 1.x entrypoint."""

    module_name: str = "ray_monitor"
    entrypoint_name: str = "main"
    importer: Callable[[str], Any] = import_module

    def __call__(self) -> object:
        module = self.importer(self.module_name)
        entrypoint = getattr(module, self.entrypoint_name, None)
        if not callable(entrypoint):
            raise RuntimeError(
                f"{self.module_name!r} has no callable "
                f"{self.entrypoint_name!r}"
            )
        return entrypoint()


def run_launcher(launcher: Launcher) -> int:
    """Run an injected launcher and normalize its process exit code."""

    if not callable(launcher):
        raise TypeError("launcher must be callable")
    result = launcher()
    if result is None:
        return 0
    if isinstance(result, bool) or not isinstance(result, int):
        raise TypeError("launcher result must be an integer or None")
    return result
