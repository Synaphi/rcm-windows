from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
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
from ..cluster import (
    ClusterMember, ClusterMemberState, ClusterSnapshot,
    ClusterWorkloadEvidence, MAX_OBSERVED_NODES,
)
from ..ports import CancellationToken, ProcessRequest, ProcessResult, ProcessRunner
from ..ray import (
    RayCommand, RayCommandBuilder, RayMode, RayStartSpec, RayStateListSpec,
    RayStateResource, RayStatusSpec, RayStopSpec,
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
        if verb == "list" and len(argv) >= 11:
            try:
                resource = RayStateResource(argv[2])
                filter_count = {
                    RayStateResource.NODES: 0,
                    RayStateResource.JOBS: 3,
                    RayStateResource.TASKS: 2,
                    RayStateResource.ACTORS: 1,
                    RayStateResource.PLACEMENT_GROUPS: 1,
                }[resource]
                suffix_at = 5 + filter_count * 2
                if argv[3:5] != ("--format", "json"):
                    raise ValueError
                if len(argv) != suffix_at + 6:
                    raise ValueError
                if argv[suffix_at::2] != (
                    "--address", "--timeout", "--limit",
                ):
                    raise ValueError
                spec = RayStateListSpec(
                    argv[0],
                    resource,
                    argv[suffix_at + 1],
                    int(argv[suffix_at + 3]),
                    int(argv[suffix_at + 5]),
                )
                expected = RayCommandBuilder().list_state(spec).arguments
            except (KeyError, TypeError, ValueError):
                pass
            else:
                if argv == expected:
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
        output_truncated = [False]

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
                        if keep < len(chunk):
                            output_truncated[0] = True
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
        invalid_encoding = False
        try:
            stdout = bytes(output["stdout"]).decode("utf-8", errors="strict")
            stderr = bytes(output["stderr"]).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            stdout = ""
            stderr = ""
            invalid_encoding = True
        return ProcessResult(
            None if timed_out or cancelled else process.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            timed_out=timed_out,
            cancelled=cancelled,
            output_truncated=output_truncated[0],
            output_invalid_encoding=invalid_encoding,
        )


_KNOWN_ACTIVE_STATES = {
    RayStateResource.JOBS: frozenset({"PENDING", "RUNNING"}),
    RayStateResource.TASKS: frozenset({
        "NIL", "PENDING_ARGS_AVAIL", "PENDING_NODE_ASSIGNMENT",
        "PENDING_OBJ_STORE_MEM_AVAIL", "PENDING_ARGS_FETCH",
        "SUBMITTED_TO_WORKER", "PENDING_ACTOR_TASK_ARGS_FETCH",
        "PENDING_ACTOR_TASK_ORDERING_OR_CONCURRENCY", "RUNNING",
        "RUNNING_IN_RAY_GET", "RUNNING_IN_RAY_WAIT",
        "GETTING_AND_PINNING_ARGS",
    }),
    RayStateResource.ACTORS: frozenset({
        "DEPENDENCIES_UNREADY", "PENDING_CREATION", "ALIVE", "RESTARTING",
    }),
    RayStateResource.PLACEMENT_GROUPS: frozenset({
        "PENDING", "PREPARED", "CREATED", "RESCHEDULING",
    }),
}
_STATE_FIELD = {
    RayStateResource.JOBS: "status",
    RayStateResource.TASKS: "state",
    RayStateResource.ACTORS: "state",
    RayStateResource.PLACEMENT_GROUPS: "state",
}
_EMPTY_STATE_OUTPUTS = frozenset({
    "No resource in the cluster\n",
    "No resource in the cluster\r\n",
})


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError(f"duplicate JSON key: {key}")
        decoded[key] = value
    return decoded


class RayStateCliObserver:
    """Read and immediately reduce five bounded Ray State CLI results."""

    def __init__(
        self,
        executable: str,
        address: str,
        process_runner: ProcessRunner,
        *,
        clock: object = time.monotonic,
        timeout_seconds: int = 10,
        max_output_bytes: int = 65_536,
        limit: int = 10_000,
        builder: RayCommandBuilder | None = None,
    ) -> None:
        if not callable(getattr(process_runner, "run", None)):
            raise TypeError("process_runner must provide run()")
        if not callable(clock):
            raise TypeError("clock must be callable")
        sample = RayStateListSpec(
            executable, RayStateResource.NODES, address,
            timeout_seconds, limit,
        )
        if (
            isinstance(max_output_bytes, bool)
            or not isinstance(max_output_bytes, int)
            or not 1 <= max_output_bytes <= 1_048_576
        ):
            raise ValueError("state output bound must be between 1 and 1048576")
        self._executable = sample.executable
        self._address = sample.address
        self._runner = process_runner
        self._clock = clock
        self._timeout = sample.timeout_seconds
        self._max_output = max_output_bytes
        self._limit = sample.limit
        self._builder = builder or RayCommandBuilder()

    def _query(
        self,
        resource: RayStateResource,
        cancellation: CancellationToken | None,
    ) -> tuple[list[dict[str, object]] | None, tuple[str, ...]]:
        code = resource.value.replace("-", "_")
        if cancellation is not None and cancellation.cancelled:
            return None, (f"{code}:cancelled",)
        command = self._builder.list_state(RayStateListSpec(
            self._executable, resource, self._address,
            self._timeout, self._limit,
        ))
        request = ProcessRequest(
            command.arguments,
            timeout_seconds=float(self._timeout),
            max_output_bytes=self._max_output,
        )
        try:
            result = self._runner.run(request, cancellation=cancellation)
        except Exception:
            return None, (f"{code}:runner_error",)
        if not isinstance(result, ProcessResult):
            return None, (f"{code}:invalid_result",)
        if result.output_invalid_encoding:
            return None, (f"{code}:invalid_encoding",)
        if result.cancelled:
            return None, (f"{code}:cancelled",)
        if result.timed_out:
            return None, (f"{code}:timeout",)
        if result.exit_code != 0:
            return None, (f"{code}:exit_nonzero",)
        reasons: list[str] = []
        if result.output_truncated:
            reasons.append(f"{code}:output_truncated")
        if result.stderr.strip():
            reasons.append(f"{code}:warning")
        if result.stdout in _EMPTY_STATE_OUTPUTS:
            if reasons:
                return None, tuple(dict.fromkeys(reasons))
            return [], ()
        try:
            decoded = json.loads(
                result.stdout,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (TypeError, ValueError):
            return None, tuple(reasons + [f"{code}:malformed_json"])
        if not isinstance(decoded, list) or any(
            not isinstance(item, dict) for item in decoded
        ):
            return None, tuple(reasons + [f"{code}:invalid_schema"])
        entries = decoded
        if len(entries) >= self._limit:
            reasons.append(f"{code}:limit_reached")
        return entries, tuple(dict.fromkeys(reasons))

    @staticmethod
    def _same_address(left: str, right: str) -> bool:
        try:
            return ipaddress.ip_address(left) == ipaddress.ip_address(right)
        except ValueError:
            return left.casefold() == right.casefold()

    def _members(
        self,
        nodes: tuple[Node, ...],
        expected_head_id: str,
        entries: list[dict[str, object]] | None,
        reasons: tuple[str, ...],
        observed_at: float,
    ) -> tuple[tuple[ClusterMember, ...], tuple[str, ...]]:
        topology_reasons = list(reasons)
        matches: dict[str, list[dict[str, object]]] = {
            node.node_id: [] for node in nodes
        }
        live_ids: set[str] = set()
        duplicate_live_ids: set[str] = set()
        if entries is not None:
            for entry in entries:
                state = entry.get("state")
                ray_node_id = entry.get("node_id")
                node_name = entry.get("node_name")
                node_ip = entry.get("node_ip")
                is_head = entry.get("is_head_node")
                if (
                    state not in ("ALIVE", "DEAD")
                    or not isinstance(ray_node_id, str)
                    or not ray_node_id
                    or not isinstance(node_name, str)
                    or not isinstance(node_ip, str)
                    or type(is_head) is not bool
                ):
                    topology_reasons.append("nodes:invalid_schema")
                    continue
                if state == "DEAD":
                    continue
                if ray_node_id in live_ids:
                    duplicate_live_ids.add(ray_node_id)
                live_ids.add(ray_node_id)
                candidates = [
                    node for node in nodes
                    if node.node_id == node_name
                    or self._same_address(node.address, node_ip)
                ]
                if len(candidates) != 1:
                    topology_reasons.append(
                        "nodes:unexpected_alive" if not candidates
                        else "nodes:ambiguous_identity"
                    )
                    continue
                matches[candidates[0].node_id].append(entry)
        members: list[ClusterMember] = []
        for node in nodes:
            alive = matches[node.node_id]
            valid = len(alive) == 1
            if len(alive) > 1:
                topology_reasons.append("nodes:duplicate_alive")
            if not alive:
                topology_reasons.append(
                    "nodes:missing_head"
                    if node.node_id == expected_head_id
                    else "nodes:missing_member"
                )
            if valid:
                if alive[0]["node_id"] in duplicate_live_ids:
                    valid = False
                    topology_reasons.append("nodes:duplicate_ray_id")
            if valid:
                expected_flag = node.node_id == expected_head_id
                if alive[0]["is_head_node"] is not expected_flag:
                    valid = False
                    topology_reasons.append("nodes:head_mismatch")
            members.append(ClusterMember(
                node,
                ClusterMemberState.ALIVE if valid else ClusterMemberState.UNKNOWN,
                observed_at,
            ))
        return tuple(members), tuple(dict.fromkeys(topology_reasons))

    def _active_count(
        self,
        resource: RayStateResource,
        entries: list[dict[str, object]] | None,
        reasons: tuple[str, ...],
    ) -> tuple[int | None, tuple[str, ...]]:
        if entries is None:
            return None, reasons
        updated = list(reasons)
        field = _STATE_FIELD[resource]
        for entry in entries:
            state = entry.get(field)
            if not isinstance(state, str) or state not in _KNOWN_ACTIVE_STATES[resource]:
                updated.append(
                    f"{resource.value.replace('-', '_')}:unknown_state"
                )
        if len(updated) != len(reasons):
            return None, tuple(dict.fromkeys(updated))
        return len(entries), reasons

    def observe(
        self,
        nodes: tuple[Node, ...],
        *,
        expected_head_id: str,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ClusterSnapshot:
        _valid_epoch(epoch)
        if (
            not isinstance(nodes, tuple)
            or not 1 <= len(nodes) <= MAX_OBSERVED_NODES
            or any(not isinstance(node, Node) or not node.enabled for node in nodes)
        ):
            raise ValueError("observer nodes must be 1 to 32 enabled Node values")
        if expected_head_id not in {node.node_id for node in nodes}:
            raise ValueError("expected head must be an observed node")
        observed_at = float(self._clock())
        results: dict[RayStateResource, tuple[list[dict[str, object]] | None,
                                                   tuple[str, ...]]] = {}
        resources = (
            RayStateResource.NODES,
            RayStateResource.JOBS,
            RayStateResource.TASKS,
            RayStateResource.ACTORS,
            RayStateResource.PLACEMENT_GROUPS,
        )
        for index, resource in enumerate(resources):
            results[resource] = self._query(resource, cancellation)
            if cancellation is not None and cancellation.cancelled:
                for omitted in resources[index + 1:]:
                    code = omitted.value.replace("-", "_")
                    results[omitted] = (None, (f"{code}:cancelled",))
                break
        node_entries, node_reasons = results[RayStateResource.NODES]
        members, topology_reasons = self._members(
            nodes, expected_head_id, node_entries, node_reasons, observed_at,
        )
        counts: list[int | None] = []
        workload_reasons = list(topology_reasons)
        for resource in resources[1:]:
            entries, reasons = results[resource]
            count, updated = self._active_count(resource, entries, reasons)
            counts.append(count)
            workload_reasons.extend(updated)
        unique_reasons = tuple(dict.fromkeys(workload_reasons))
        workload = ClusterWorkloadEvidence(
            observed_at,
            *counts,
            complete=not unique_reasons and all(count is not None for count in counts),
            reasons=unique_reasons,
        )
        return ClusterSnapshot(
            epoch, expected_head_id, members, observed_at, workload,
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
        if result.output_invalid_encoding:
            return ActionResult(ActionStatus.FAILED, "ray.invalid_encoding")
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
        if result.output_invalid_encoding:
            return ActionResult(ActionStatus.FAILED, "ray.invalid_encoding")
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
    "RayStateCliObserver",
    "SUPPORTED_RAY_VERSION",
]
