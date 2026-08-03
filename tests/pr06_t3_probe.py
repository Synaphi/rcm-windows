"""Sanitized probe for the hosted PR-06 isolated Ray lab.

This file is not part of normal unit discovery.  The dedicated route-free T3
workflow runs it inside the isolated head container after the two workers
join, and again after one worker is replaced.
"""

from __future__ import annotations

import argparse
import importlib
import math
import sys
import time
from urllib.request import urlopen


SUPPORTED_RAY_VERSION = "2.55.1"


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

    importlib.import_module("rcm.ray")
    importlib.import_module("rcm.cluster")
    importlib.import_module("rcm.adapters.ray_cli")
    if "ray" in sys.modules:
        raise RuntimeError("service import loaded Ray before the T3 boundary")
    if "tkinter" in sys.modules:
        raise RuntimeError("service import loaded Tk")

    from rcm.cluster import (
        ClusterBusyPolicy,
        ClusterMember,
        ClusterMemberState,
        ClusterSnapshot,
    )
    from rcm.core import BusyState, Node, NodeRole
    from rcm.ray import RayCommandBuilder, RayMode, RayStartSpec

    command = RayCommandBuilder().start(RayStartSpec(
        "ray", RayMode.WORKER, address="192.0.2.10:6379",
        node_ip_address="192.0.2.20", num_cpus=1,
    ))
    if command.arguments[:4] != (
        "ray", "start", "--address", "192.0.2.10:6379",
    ):
        raise RuntimeError("production Ray command boundary diverged")

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
            observed = time.monotonic()
            policy_nodes = tuple(
                Node(
                    str(node.get("NodeID")),
                    f"192.0.2.{index + 1}",
                    NodeRole.HEAD if index == 0 else NodeRole.WORKER,
                )
                for index, node in enumerate(alive)
            )
            busy_members = tuple(
                ClusterMember(
                    node,
                    ClusterMemberState.ALIVE,
                    observed,
                    active_jobs=0,
                    active_tasks=1 if index == 0 else 0,
                    workload_evidence_fresh=True,
                )
                for index, node in enumerate(policy_nodes)
            )
            busy = ClusterBusyPolicy(max_age_seconds=5).assess(
                ClusterSnapshot(
                    1,
                    policy_nodes[0].node_id,
                    busy_members,
                    observed,
                ),
                now=observed,
            )
            if busy.state is not BusyState.BUSY:
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
        f"ray_version={SUPPORTED_RAY_VERSION} "
        "dashboard=pass "
        f"nodes={args.expected_nodes} "
        f"worker_cpus={args.expected_worker_cpus}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
