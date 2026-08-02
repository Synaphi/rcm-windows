from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
import re


_SAFE_ENDPOINT = re.compile(r"[A-Za-z0-9_.:\[\]-]+\Z")


class RayMode(StrEnum):
    HEAD = "head"
    WORKER = "worker"
    DRIVER_ONLY = "driver_only"


class RayCommandKind(StrEnum):
    START = "start"
    STOP = "stop"
    STATUS = "status"


def _text(
    value: object,
    *,
    field: str,
    endpoint: bool = False,
) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} contains a control character")
    if endpoint and (
        value.startswith("-") or _SAFE_ENDPOINT.fullmatch(value) is None
    ):
        raise ValueError(f"{field} contains an unsupported character")
    return value


def _port(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not 1 <= value <= 65_535:
        raise ValueError(f"{field} must be between 1 and 65535")
    return value


def _cpu_count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("num_cpus must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RayStartSpec:
    executable: str
    mode: RayMode
    address: str | None = None
    node_ip_address: str | None = None
    port: int | None = None
    dashboard_host: str | None = None
    dashboard_port: int | None = None
    num_cpus: int | None = None
    temp_dir: str | None = None
    node_manager_port: int | None = None
    object_manager_port: int | None = None
    runtime_env_agent_port: int | None = None
    dashboard_agent_grpc_port: int | None = None
    dashboard_agent_listen_port: int | None = None
    metrics_export_port: int | None = None
    min_worker_port: int | None = None
    max_worker_port: int | None = None
    node_name: str | None = None
    block: bool = False

    def __post_init__(self) -> None:
        _text(self.executable, field="executable")
        if not isinstance(self.mode, RayMode):
            raise ValueError("mode must be a RayMode")
        if self.address is not None:
            _text(self.address, field="address", endpoint=True)
        if self.node_ip_address is not None:
            _text(
                self.node_ip_address,
                field="node_ip_address",
                endpoint=True,
            )
        if self.dashboard_host is not None:
            _text(
                self.dashboard_host,
                field="dashboard_host",
                endpoint=True,
            )
        if self.temp_dir is not None:
            _text(self.temp_dir, field="temp_dir")
            if self.temp_dir.startswith("-"):
                raise ValueError("temp_dir must not look like an option")
        if self.node_name is not None:
            _text(self.node_name, field="node_name", endpoint=True)
        port_fields = (
            "port",
            "dashboard_port",
            "node_manager_port",
            "object_manager_port",
            "runtime_env_agent_port",
            "dashboard_agent_grpc_port",
            "dashboard_agent_listen_port",
            "metrics_export_port",
            "min_worker_port",
            "max_worker_port",
        )
        for field in port_fields:
            value = getattr(self, field)
            if value is not None:
                _port(value, field=field)
        if (
            self.min_worker_port is not None
            and self.max_worker_port is not None
            and self.min_worker_port > self.max_worker_port
        ):
            raise ValueError(
                "min_worker_port must not exceed max_worker_port"
            )
        if self.num_cpus is not None:
            _cpu_count(self.num_cpus)
        if not isinstance(self.block, bool):
            raise ValueError("block must be a bool")

        if self.mode in (RayMode.WORKER, RayMode.DRIVER_ONLY):
            if self.address is None:
                raise ValueError("worker modes require an address")
            if self.port is not None:
                raise ValueError("worker modes do not accept a head port")
            if self.dashboard_host is not None:
                raise ValueError(
                    "worker modes do not accept a dashboard host"
                )
            if self.dashboard_port is not None:
                raise ValueError(
                    "worker modes do not accept a dashboard port"
                )
        elif self.address is not None:
            raise ValueError("head modes do not accept an address")

        if self.mode is RayMode.DRIVER_ONLY:
            if self.num_cpus not in (None, 0):
                raise ValueError("driver-only mode requires num_cpus zero")


@dataclass(frozen=True, slots=True, repr=False)
class RayStopSpec:
    executable: str
    force: bool = False
    grace_period_seconds: float | None = None

    def __post_init__(self) -> None:
        _text(self.executable, field="executable")
        if not isinstance(self.force, bool):
            raise ValueError("force must be a bool")
        if self.grace_period_seconds is not None:
            value = self.grace_period_seconds
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(
                    "grace_period_seconds must be finite and non-negative"
                )


@dataclass(frozen=True, slots=True, repr=False)
class RayStatusSpec:
    executable: str
    address: str | None = None

    def __post_init__(self) -> None:
        _text(self.executable, field="executable")
        if self.address is not None:
            _text(self.address, field="address", endpoint=True)


@dataclass(frozen=True, slots=True, repr=False)
class RayCommand:
    kind: RayCommandKind
    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RayCommandKind):
            raise ValueError("kind must be a RayCommandKind")
        if (
            not isinstance(self.arguments, tuple)
            or not self.arguments
            or any(not isinstance(item, str) or not item for item in self.arguments)
        ):
            raise ValueError("arguments must be a non-empty tuple of strings")


class RayCommandBuilder:
    """Builds argv only; it never imports Ray or starts a process."""

    def start(self, spec: RayStartSpec) -> RayCommand:
        if not isinstance(spec, RayStartSpec):
            raise TypeError("spec must be a RayStartSpec")
        arguments = [spec.executable, "start"]
        if spec.mode is RayMode.HEAD:
            arguments.append("--head")
        else:
            arguments.extend(("--address", spec.address))
        if spec.node_ip_address is not None:
            arguments.extend(
                ("--node-ip-address", spec.node_ip_address)
            )
        if spec.port is not None:
            arguments.extend(("--port", str(spec.port)))
        if spec.dashboard_host is not None:
            arguments.extend(("--dashboard-host", spec.dashboard_host))
        if spec.dashboard_port is not None:
            arguments.extend(
                ("--dashboard-port", str(spec.dashboard_port))
            )
        num_cpus = 0 if spec.mode is RayMode.DRIVER_ONLY else spec.num_cpus
        if num_cpus is not None:
            arguments.extend(("--num-cpus", str(num_cpus)))
        if spec.temp_dir is not None:
            arguments.extend(("--temp-dir", spec.temp_dir))
        fixed_ports = (
            "node_manager_port",
            "object_manager_port",
            "runtime_env_agent_port",
            "dashboard_agent_grpc_port",
            "dashboard_agent_listen_port",
            "metrics_export_port",
            "min_worker_port",
            "max_worker_port",
        )
        for field in fixed_ports:
            value = getattr(spec, field)
            if value is not None:
                arguments.extend(
                    (f"--{field.replace('_', '-')}", str(value))
                )
        if spec.node_name is not None:
            arguments.extend(("--node-name", spec.node_name))
        if spec.block:
            arguments.append("--block")
        return RayCommand(RayCommandKind.START, tuple(arguments))

    def stop(self, spec: RayStopSpec) -> RayCommand:
        if not isinstance(spec, RayStopSpec):
            raise TypeError("spec must be a RayStopSpec")
        arguments = [spec.executable, "stop"]
        if spec.force:
            arguments.append("--force")
        if spec.grace_period_seconds is not None:
            arguments.extend(
                ("--grace-period", f"{spec.grace_period_seconds:g}")
            )
        return RayCommand(RayCommandKind.STOP, tuple(arguments))

    def status(self, spec: RayStatusSpec) -> RayCommand:
        if not isinstance(spec, RayStatusSpec):
            raise TypeError("spec must be a RayStatusSpec")
        arguments = [spec.executable, "status"]
        if spec.address is not None:
            arguments.extend(("--address", spec.address))
        return RayCommand(RayCommandKind.STATUS, tuple(arguments))
