"""Sanitized probe for the hosted PR-06 isolated Ray lab.

This file is not part of normal unit discovery.  The dedicated route-free T3
workflow runs it inside the isolated head container after the two workers
join, and again after one worker is replaced.
"""

from __future__ import annotations

import argparse
import importlib
import math
import subprocess
import sys
from threading import Lock, Thread
import time
from urllib.request import urlopen


SUPPORTED_RAY_VERSION = "2.55.1"


def _bounded_cli_run(request: object) -> object:
    from rcm.ports import ProcessResult

    started = time.monotonic()
    process = subprocess.Popen(
        request.argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    output = {"stdout": bytearray(), "stderr": bytearray()}
    output_lock = Lock()
    remaining = [request.max_output_bytes]
    truncated = [False]

    def drain(name: str, stream: object) -> None:
        try:
            while True:
                chunk = stream.read(4_096)
                if not chunk:
                    break
                with output_lock:
                    keep = min(len(chunk), remaining[0])
                    output[name].extend(chunk[:keep])
                    remaining[0] -= keep
                    if keep < len(chunk):
                        truncated[0] = True
        finally:
            stream.close()

    readers = tuple(
        Thread(target=drain, args=(name, stream), daemon=True)
        for name, stream in (
            ("stdout", process.stdout),
            ("stderr", process.stderr),
        )
    )
    for reader in readers:
        reader.start()
    timed_out = False
    deadline = started + request.timeout_seconds
    while process.poll() is None:
        if time.monotonic() >= deadline:
            timed_out = True
            process.kill()
            break
        time.sleep(0.01)
    process.wait()
    for reader in readers:
        reader.join(0.5)
    invalid_encoding = False
    try:
        stdout = bytes(output["stdout"]).decode("utf-8", errors="strict")
        stderr = bytes(output["stderr"]).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        stdout = ""
        stderr = ""
        invalid_encoding = True
    return ProcessResult(
        None if timed_out else process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=max(0.0, time.monotonic() - started),
        timed_out=timed_out,
        output_truncated=truncated[0],
        output_invalid_encoding=invalid_encoding,
    )


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-nodes", type=_positive_integer, required=True)
    parser.add_argument(
        "--expected-worker-cpus",
        type=_positive_integer,
        required=True,
    )
    args = parser.parse_args()

    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:2] != (3, 12)
        or sys.maxsize != 2**63 - 1
    ):
        raise RuntimeError("isolated lab requires CPython 3.12 x64")

    importlib.import_module("rcm.ray")
    importlib.import_module("rcm.cluster")
    importlib.import_module("rcm.adapters.ray_cli")
    if "ray" in sys.modules:
        raise RuntimeError("service import loaded Ray before the T3 boundary")
    if "tkinter" in sys.modules:
        raise RuntimeError("service import loaded Tk")

    from rcm.adapters.ray_cli import RayStateCliObserver
    from rcm.cluster import ClusterBusyPolicy, ClusterStateService
    from rcm.core import BusyState, Node, NodeRole
    from rcm.ports import ProcessRequest, ProcessResult
    from rcm.ray import RayCommandBuilder, RayMode, RayStartSpec

    command = RayCommandBuilder().start(RayStartSpec(
        "ray", RayMode.WORKER, address="192.0.2.10:6379",
        node_ip_address="192.0.2.20", num_cpus=1,
    ))
    if command.arguments[:4] != (
        "ray", "start", "--address", "192.0.2.10:6379",
    ):
        raise RuntimeError("production Ray command boundary diverged")

    class _CliRunner:
        @staticmethod
        def run(
            request: ProcessRequest,
            *,
            cancellation: object | None = None,
        ) -> ProcessResult:
            if cancellation is not None and cancellation.cancelled:
                return ProcessResult(None, cancelled=True)
            return _bounded_cli_run(request)

    policy_nodes = tuple(
        Node(
            "head" if index == 0 else f"worker-{index}",
            f"192.0.2.{10 + index * 10}",
            NodeRole.HEAD if index == 0 else NodeRole.WORKER,
        )
        for index in range(args.expected_nodes)
    )
    service = ClusterStateService(
        RayStateCliObserver(
            "ray", "192.0.2.10:6379", _CliRunner(),
        ),
        ClusterBusyPolicy(max_age_seconds=60),
    )
    idle = service.diagnose(
        policy_nodes,
        expected_head_id="head",
        epoch=1,
    )
    if idle.assessment.state is not BusyState.IDLE:
        raise RuntimeError("idle State CLI observation was not proven idle")

    import ray

    if ray.__version__ != SUPPORTED_RAY_VERSION:
        raise RuntimeError("isolated lab Ray version is not the supported pin")

    with urlopen("http://127.0.0.1:8265/api/version", timeout=5) as response:
        dashboard_body = response.read(4_097)
        if response.status != 200 or not dashboard_body or len(dashboard_body) > 4_096:
            raise RuntimeError("isolated dashboard did not answer bounded health probe")

    ray.init(address="auto", logging_level="ERROR")
    try:
        alive = [node for node in ray.nodes() if node.get("Alive") is True]
        if len(alive) != args.expected_nodes:
            raise RuntimeError("isolated node count did not converge")
        cpu_total = sum(
            float((node.get("Resources") or {}).get("CPU", 0.0))
            for node in alive
        )
        if not math.isclose(
            cpu_total,
            float(args.expected_worker_cpus),
            rel_tol=0.0,
            abs_tol=0.001,
        ):
            raise RuntimeError("isolated CPU total did not converge")

        @ray.remote(num_cpus=1)
        class _PinnedWorker:
            def node_id(self) -> str:
                return ray.get_runtime_context().get_node_id()

        actors = [
            _PinnedWorker.remote()
            for _ in range(args.expected_worker_cpus)
        ]
        try:
            node_ids = ray.get(
                [actor.node_id.remote() for actor in actors], timeout=10,
            )
            if len(set(node_ids)) != args.expected_worker_cpus:
                raise RuntimeError("worker placement did not span isolated workers")
            busy = service.diagnose(
                policy_nodes,
                expected_head_id="head",
                epoch=1,
            )
            if busy.assessment.state is not BusyState.BUSY:
                raise RuntimeError("active isolated work was not classified busy")
        finally:
            for actor in actors:
                ray.kill(actor, no_restart=True)

        @ray.remote
        def _job_round_trip(value: int) -> int:
            return value + 1

        if ray.get(_job_round_trip.remote(41), timeout=10) != 42:
            raise RuntimeError("isolated job round trip failed")
    finally:
        ray.shutdown()

    print(
        "isolated_lab=pass "
        "python=cpython-3.12 arch=x64 "
        f"ray_version={SUPPORTED_RAY_VERSION} "
        "dashboard=pass "
        "state_cli_idle=pass "
        "state_cli_busy=pass "
        f"nodes={args.expected_nodes} "
        f"worker_cpus={args.expected_worker_cpus}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
