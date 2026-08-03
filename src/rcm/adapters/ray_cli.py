from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import ntpath
from pathlib import PureWindowsPath
import re
from threading import Lock, RLock, Thread
import time
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
SUPPORTED_RAY_VERSION = "2.55.1"
_RAY_VERSION = re.compile(
    r"(?:^|\s)ray,\s+version\s+(\d+\.\d+\.\d+)(?:\s|$)",
    re.I,
)
_START_VALUE_OPTIONS = frozenset({
    "--address",
    "--node-ip-address",
    "--port",
    "--dashboard-host",
    "--dashboard-port",
    "--num-cpus",
    "--temp-dir",
    "--node-manager-port",
    "--object-manager-port",
    "--runtime-env-agent-port",
    "--dashboard-agent-grpc-port",
    "--dashboard-agent-listen-port",
    "--metrics-export-port",
    "--min-worker-port",
    "--max-worker-port",
    "--node-name",
})


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


def _local_ray_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("Ray executable must be one safe absolute local path")
    path = PureWindowsPath(value)
    folded = value.replace("/", "\\").casefold()
    if (
        not path.is_absolute()
        or path.anchor.startswith("\\\\")
        or folded.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\device\\"))
        or any(part == ".." for part in path.parts)
        or any(":" in part for part in path.parts[1:])
        or any(part.endswith((" ", ".")) for part in path.parts[1:])
        or path.name.casefold() != "ray.exe"
    ):
        raise ValueError("Ray executable must be one absolute local ray.exe path")
    return str(path)


def _option_pairs(
    arguments: tuple[str, ...],
    *,
    value_options: frozenset[str],
    flag_options: frozenset[str] = frozenset(),
) -> bool:
    seen: set[str] = set()
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in seen:
            return False
        seen.add(option)
        if option in flag_options:
            index += 1
            continue
        if option not in value_options or index + 1 >= len(arguments):
            return False
        value = arguments[index + 1]
        if not value or value.startswith("--"):
            return False
        index += 2
    return True


class LocalRayProcessRunner:
    """Run only the configured local Ray CLI with bounded argv and output."""

    def __init__(self, executable: str) -> None:
        self._executable = _local_ray_path(executable)

    def _validate_request(self, request: ProcessRequest) -> None:
        if not isinstance(request, ProcessRequest):
            raise TypeError("request must be a ProcessRequest")
        if request.cwd is not None:
            raise ValueError("Ray commands do not accept a working directory")
        argv = request.argv
        if ntpath.normcase(str(PureWindowsPath(argv[0]))) != ntpath.normcase(
            self._executable
        ):
            raise ValueError("Ray command executable does not match configuration")
        if len(argv) == 2 and argv[1] == "--version":
            return
        if len(argv) < 2:
            raise ValueError("Ray command is incomplete")
        verb = argv[1]
        tail = argv[2:]
        if verb == "start" and _option_pairs(
            tail,
            value_options=_START_VALUE_OPTIONS,
            flag_options=frozenset({"--head"}),
        ):
            return
        if verb == "stop" and _option_pairs(
            tail,
            value_options=frozenset({"--grace-period"}),
            flag_options=frozenset({"--force"}),
        ):
            return
        if verb == "status" and _option_pairs(
            tail,
            value_options=frozenset({"--address"}),
        ):
            return
        raise ValueError("Ray command is outside the local CLI allowlist")

    def _assert_executable(self) -> None:
        import os
        import stat

        try:
            details = os.stat(self._executable, follow_symlinks=False)
        except OSError:
            raise OSError("configured Ray executable is unavailable") from None
        if (
            not stat.S_ISREG(details.st_mode)
            or bool(getattr(details, "st_file_attributes", 0) & 0x400)
        ):
            raise OSError("configured Ray executable is not a regular local file")

    @staticmethod
    def _environment() -> dict[str, str]:
        import os

        blocked_prefixes = ("PIP_", "PYTHON", "RAY_")
        result = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(blocked_prefixes)
        }
        result["RAY_ENABLE_WINDOWS_OR_OSX_CLUSTER"] = "1"
        result["RAY_USAGE_STATS_ENABLED"] = "0"
        result["RAY_USAGE_STATS_PROMPT_ENABLED"] = "0"
        return result

    def run(
        self,
        request: ProcessRequest,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ProcessResult:
        import subprocess

        self._validate_request(request)
        self._assert_executable()
        if cancellation is not None and cancellation.cancelled:
            return ProcessResult(None, cancelled=True)
        started = time.monotonic()
        process = subprocess.Popen(
            request.argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            cwd=None,
            env=self._environment(),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = {"stdout": bytearray(), "stderr": bytearray()}
        output_lock = Lock()
        remaining = [request.max_output_bytes]

        def drain(name: str, stream: object) -> None:
            try:
                while True:
                    try:
                        chunk = stream.read(4_096)  # type: ignore[attr-defined]
                    except (OSError, ValueError):
                        break
                    if not chunk:
                        break
                    with output_lock:
                        keep = min(len(chunk), remaining[0])
                        if keep:
                            output[name].extend(chunk[:keep])
                            remaining[0] -= keep
            finally:
                try:
                    stream.close()  # type: ignore[attr-defined]
                except (OSError, ValueError):
                    pass

        readers = (
            Thread(target=drain, args=("stdout", process.stdout), daemon=True),
            Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        )
        for reader in readers:
            reader.start()
        timed_out = False
        cancelled = False
        deadline = started + request.timeout_seconds
        while process.poll() is None:
            if cancellation is not None and cancellation.cancelled:
                cancelled = True
                try:
                    process.kill()
                except OSError:
                    pass
                break
            if time.monotonic() >= deadline:
                timed_out = True
                try:
                    process.kill()
                except OSError:
                    pass
                break
            time.sleep(0.01)
        process.wait()
        for reader in readers:
            reader.join(0.5)
        for stream, reader in zip(
            (process.stdout, process.stderr), readers, strict=True
        ):
            if reader.is_alive():
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
                reader.join(0.5)
        duration = max(0.0, time.monotonic() - started)
        return ProcessResult(
            None if timed_out or cancelled else process.returncode,
            stdout=bytes(output["stdout"]).decode("utf-8", errors="replace"),
            stderr=bytes(output["stderr"]).decode("utf-8", errors="replace"),
            duration_seconds=duration,
            timed_out=timed_out,
            cancelled=cancelled,
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
        request = ProcessRequest(
            (self._settings.executable, "--version"),
            timeout_seconds=self._settings.status_timeout_seconds,
            max_output_bytes=self._settings.max_output_bytes,
        )
        try:
            result = self._process_runner.run(
                request,
                cancellation=cancellation,
            )
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
        version = _RAY_VERSION.search(f"{result.stdout}\n{result.stderr}")
        if version is None or version.group(1) != SUPPORTED_RAY_VERSION:
            return ActionResult(ActionStatus.FAILED, "ray.version_unsupported")
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
    "LocalRayProcessRunner",
    "ManifestSink",
    "RayCliAdapter",
    "RayCliSettings",
    "SUPPORTED_RAY_VERSION",
]
