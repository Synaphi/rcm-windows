from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import re
from threading import RLock
from typing import Protocol

from ..core import (
    ActionResult, ActionStatus, Node, RejectedError, StaleError, UnsupportedError,
)
from ..ports import CancellationToken, ProcessRequest, ProcessResult, ProcessRunner
from ..ray import (
    RayCommand, RayCommandBuilder, RayMode, RayStartSpec, RayStatusSpec, RayStopSpec,
)


_START_OPTION_FIELDS = (
    "num_cpus",
    "temp_dir",
    "node_manager_port",
    "object_manager_port",
    "runtime_env_agent_port",
    "dashboard_agent_grpc_port",
    "dashboard_agent_listen_port",
    "metrics_export_port",
    "min_worker_port",
    "max_worker_port",
)


class ManifestSink(Protocol):
    def push(self, node: Node, manifest_digest: str, *, epoch: int,
             cancellation: CancellationToken | None = None) -> ActionResult: ...


def _positive_seconds(value: object, *, field: str) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0):
        raise ValueError(f"{field} must be finite and positive")
    return float(value)


def _valid_epoch(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("epoch must be a non-negative integer")


def _endpoint(address: str, port: int) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"{address}:{port}"
    host = f"[{parsed.compressed}]" if parsed.version == 6 else parsed.compressed
    return f"{host}:{port}"


@dataclass(frozen=True, slots=True, repr=False)
class RayCliSettings:
    executable: str
    local_node_id: str
    cluster_port: int
    num_cpus: int | None = None
    driver_only: bool = False
    temp_dir: str | None = None
    dashboard_host: str | None = None
    dashboard_port: int | None = None
    node_manager_port: int | None = None
    object_manager_port: int | None = None
    runtime_env_agent_port: int | None = None
    dashboard_agent_grpc_port: int | None = None
    dashboard_agent_listen_port: int | None = None
    metrics_export_port: int | None = None
    min_worker_port: int | None = None
    max_worker_port: int | None = None
    start_timeout_seconds: float = 90.0
    stop_timeout_seconds: float = 45.0
    status_timeout_seconds: float = 30.0
    max_output_bytes: int = 65_536

    def start_options(self) -> dict[str, object]:
        return {
            field: value
            for field in _START_OPTION_FIELDS
            if (value := getattr(self, field)) is not None
        }

    def __post_init__(self) -> None:
        if not isinstance(self.local_node_id, str) or not self.local_node_id:
            raise ValueError("local_node_id must be non-empty")
        if any(ord(character) < 33 for character in self.local_node_id):
            raise ValueError("local_node_id must be a safe token")
        if (isinstance(self.cluster_port, bool)
                or not isinstance(self.cluster_port, int)
                or not 1 <= self.cluster_port <= 65_535):
            raise ValueError("cluster_port must be between 1 and 65535")
        if not isinstance(self.driver_only, bool):
            raise ValueError("driver_only must be a bool")
        if self.driver_only and (self.dashboard_host is not None
                                 or self.dashboard_port is not None):
            raise ValueError("driver-only workers do not accept dashboard settings")
        for field in (
            "start_timeout_seconds",
            "stop_timeout_seconds",
            "status_timeout_seconds",
        ):
            _positive_seconds(getattr(self, field), field=field)
        if (isinstance(self.max_output_bytes, bool)
                or not isinstance(self.max_output_bytes, int)
                or not 1 <= self.max_output_bytes <= 16_777_216):
            raise ValueError("max_output_bytes must be between 1 and 16777216")
        if self.driver_only:
            RayStartSpec(
                executable=self.executable,
                mode=RayMode.DRIVER_ONLY,
                address=f"synthetic-head:{self.cluster_port}",
                node_ip_address="synthetic-node",
                **self.start_options(),
            )
        else:
            RayStartSpec(
                executable=self.executable,
                mode=RayMode.HEAD,
                node_ip_address="synthetic-node",
                port=self.cluster_port,
                dashboard_host=self.dashboard_host,
                dashboard_port=self.dashboard_port,
                **self.start_options(),
            )


class RayCliAdapter:
    """Local Ray CLI adapter; remote dispatch is deliberately unsupported."""

    def __init__(self, settings: RayCliSettings, process_runner: ProcessRunner, *,
                 manifest_sink: ManifestSink | None = None,
                 builder: RayCommandBuilder | None = None) -> None:
        if not isinstance(settings, RayCliSettings):
            raise TypeError("settings must be RayCliSettings")
        if not callable(getattr(process_runner, "run", None)):
            raise TypeError("process_runner must provide run()")
        self._settings = settings
        self._process_runner = process_runner
        self._manifest_sink = manifest_sink
        self._builder = builder or RayCommandBuilder()
        self._last_epoch = -1
        self._epoch_lock = RLock()

    def _local_failure(self, node: Node) -> ActionResult | None:
        if not isinstance(node, Node):
            raise TypeError("node must be a Node")
        if node.node_id != self._settings.local_node_id:
            return RejectedError(
                "the local Ray adapter cannot control a remote node").to_result()
        if not node.enabled:
            return RejectedError("the local Ray node is disabled").to_result()
        return None

    def _epoch_failure(self, epoch: int) -> ActionResult | None:
        _valid_epoch(epoch)
        with self._epoch_lock:
            if epoch < self._last_epoch:
                return StaleError("Ray adapter epoch is stale").to_result()
            self._last_epoch = epoch
        return None

    def _run(self, command: RayCommand, *, timeout_seconds: float,
             cancellation: CancellationToken | None,
             success_code: str) -> ActionResult:
        if cancellation is not None:
            cancellation.raise_if_cancelled()
        request = ProcessRequest(
            command.arguments, timeout_seconds=timeout_seconds,
            max_output_bytes=self._settings.max_output_bytes)
        try:
            result = self._process_runner.run(request, cancellation=cancellation)
        except Exception:
            if cancellation is not None and cancellation.cancelled:
                return ActionResult(
                    ActionStatus.CANCELLED, "ray.cancelled", retryable=True)
            return ActionResult(
                ActionStatus.FAILED, "ray.runner_error", retryable=True)
        if not isinstance(result, ProcessResult):
            return ActionResult(ActionStatus.FAILED, "ray.invalid_result")
        if result.cancelled:
            return ActionResult(
                ActionStatus.CANCELLED, "ray.cancelled", retryable=True)
        if result.timed_out:
            return ActionResult(
                ActionStatus.FAILED, "ray.timeout", retryable=True)
        if result.exit_code != 0:
            return ActionResult(
                ActionStatus.FAILED, "ray.exit_nonzero", retryable=True)
        return ActionResult.success(success_code)

    def preflight(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        failure = self._local_failure(node)
        if failure is not None:
            return failure
        if failure := self._epoch_failure(epoch):
            return failure
        if cancellation is not None:
            cancellation.raise_if_cancelled()
        return ActionResult.success("ray.preflight_ready")

    def stop(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        failure = self._local_failure(node)
        if failure is not None:
            return failure
        if failure := self._epoch_failure(epoch):
            return failure
        command = self._builder.stop(
            RayStopSpec(self._settings.executable)
        )
        return self._run(
            command,
            timeout_seconds=self._settings.stop_timeout_seconds,
            cancellation=cancellation,
            success_code="ray.stopped",
        )

    def push_manifest(
        self,
        node: Node,
        manifest_digest: str,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        failure = self._local_failure(node)
        if failure is not None:
            return failure
        if failure := self._epoch_failure(epoch):
            return failure
        if (
            not isinstance(manifest_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest_digest)
        ):
            raise ValueError("manifest_digest must be lowercase SHA-256")
        if self._manifest_sink is None:
            return UnsupportedError(
                "no manifest sink was configured"
            ).to_result()
        try:
            return self._manifest_sink.push(
                node,
                manifest_digest,
                epoch=epoch,
                cancellation=cancellation,
            )
        except Exception:
            if cancellation is not None and cancellation.cancelled:
                return ActionResult(
                    ActionStatus.CANCELLED,
                    "ray.cancelled",
                    retryable=True,
                )
            return ActionResult(
                ActionStatus.FAILED,
                "ray.manifest_error",
                retryable=True,
            )

    def start_head(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        failure = self._local_failure(node)
        if failure is not None:
            return failure
        if self._settings.driver_only:
            return RejectedError(
                "a driver-only Ray worker cannot become the head"
            ).to_result()
        if failure := self._epoch_failure(epoch):
            return failure
        settings = self._settings
        command = self._builder.start(
            RayStartSpec(
                settings.executable,
                RayMode.HEAD,
                node_ip_address=node.address,
                port=settings.cluster_port,
                dashboard_host=settings.dashboard_host,
                dashboard_port=settings.dashboard_port,
                **settings.start_options(),
            )
        )
        return self._run(
            command,
            timeout_seconds=settings.start_timeout_seconds,
            cancellation=cancellation,
            success_code="ray.head_started",
        )

    def join_worker(
        self,
        node: Node,
        head: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        failure = self._local_failure(node)
        if failure is not None:
            return failure
        if not isinstance(head, Node):
            raise TypeError("head must be a Node")
        if failure := self._epoch_failure(epoch):
            return failure
        settings = self._settings
        address = _endpoint(head.address, settings.cluster_port)
        command = self._builder.start(
            RayStartSpec(
                settings.executable,
                RayMode.DRIVER_ONLY
                if settings.driver_only
                else RayMode.WORKER,
                address=address,
                node_ip_address=node.address,
                node_name=node.node_id,
                **settings.start_options(),
            )
        )
        return self._run(
            command,
            timeout_seconds=settings.start_timeout_seconds,
            cancellation=cancellation,
            success_code="ray.worker_joined",
        )

    def verify(
        self,
        nodes: tuple[Node, ...],
        head: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult:
        if (
            not isinstance(nodes, tuple)
            or not nodes
            or any(not isinstance(node, Node) for node in nodes)
        ):
            raise ValueError("nodes must be a non-empty tuple of Node values")
        failure = self._local_failure(head)
        if failure is not None:
            return failure
        node_ids = tuple(node.node_id for node in nodes)
        if len(set(node_ids)) != len(node_ids) or head.node_id not in node_ids:
            raise ValueError("verified nodes must uniquely include the head")
        if len(nodes) != 1:
            return UnsupportedError(
                "local Ray status cannot prove exact multi-node membership"
            ).to_result()
        if failure := self._epoch_failure(epoch):
            return failure
        command = self._builder.status(
            RayStatusSpec(
                self._settings.executable,
                _endpoint(head.address, self._settings.cluster_port),
            )
        )
        return self._run(
            command,
            timeout_seconds=self._settings.status_timeout_seconds,
            cancellation=cancellation,
            success_code="ray.verified",
        )


__all__ = [
    "ManifestSink",
    "RayCliAdapter",
    "RayCliSettings",
]
