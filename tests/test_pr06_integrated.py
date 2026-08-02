from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest

from rcm.cluster import (
    ClusterBusyPolicy,
    ClusterMember,
    ClusterMemberState,
    ClusterSnapshot,
    MaintenanceGuard,
)
from rcm.core import ActionResult, MetricSnapshot, MetricState, Node, NodeRole
from rcm.monitoring import MonitoringPolicy, MonitoringService
from rcm.reconfiguration import (
    ClusterReconfigurator,
    ClusterTopology,
    MemoryReconfigurationJournal,
    ReconfigurationPlan,
    ReconfigurationStatus,
)

from fake_test_kit.clock import FakeClock


class _ScaleSensor:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls: list[str] = []

    def sample(self, node_id: str) -> MetricSnapshot:
        self.calls.append(node_id)
        return MetricSnapshot(
            node_id,
            self.clock.monotonic_ns(),
            cpu_percent=25,
            memory_percent=50,
        )


class _RayFake:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []

    def _ok(self, action: str, node: Node, epoch: int) -> ActionResult:
        self.events.append((action, node.node_id, epoch))
        return ActionResult.success()

    def preflight(
        self, node: Node, *, epoch: int, cancellation: object | None = None
    ) -> ActionResult:
        return self._ok("preflight", node, epoch)

    def stop(
        self, node: Node, *, epoch: int, cancellation: object | None = None
    ) -> ActionResult:
        return self._ok("stop", node, epoch)

    def push_manifest(
        self,
        node: Node,
        manifest_digest: str,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        self.assert_digest(manifest_digest)
        return self._ok("push", node, epoch)

    def start_head(
        self, node: Node, *, epoch: int, cancellation: object | None = None
    ) -> ActionResult:
        return self._ok("start", node, epoch)

    def join_worker(
        self,
        node: Node,
        head: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        self.assertEqualRole(head, NodeRole.HEAD)
        return self._ok("join", node, epoch)

    def verify(
        self,
        nodes: tuple[Node, ...],
        head: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        if head not in nodes:
            raise AssertionError("verified nodes must include the head")
        return self._ok("verify", head, epoch)

    @staticmethod
    def assert_digest(value: str) -> None:
        if len(value) != 64:
            raise AssertionError("manifest digest must be SHA-256")

    @staticmethod
    def assertEqualRole(node: Node, role: NodeRole) -> None:
        if node.role is not role:
            raise AssertionError("head role mismatch")


class IntegratedCoreRuntimeTests(unittest.TestCase):
    def test_t0_idle_gate_and_full_fake_reconfiguration(self) -> None:
        old_head = Node("head-a", "192.0.2.10", NodeRole.HEAD)
        new_worker = Node("head-b", "192.0.2.20", NodeRole.WORKER)
        worker = Node("worker", "192.0.2.30", NodeRole.WORKER)
        members = tuple(
            ClusterMember(
                node,
                ClusterMemberState.ALIVE,
                10,
                active_jobs=0,
                active_tasks=0,
                workload_evidence_fresh=True,
            )
            for node in (old_head, new_worker, worker)
        )
        snapshot = ClusterSnapshot(7, old_head.node_id, members, 10)
        assessment = ClusterBusyPolicy(max_age_seconds=5).assess(
            snapshot,
            now=11,
        )
        lease = MaintenanceGuard().acquire(
            request_id="integrated-operation",
            assessment=assessment,
            expected_epoch=7,
        )
        desired = ClusterTopology(
            8,
            Node("head-b", "192.0.2.20", NodeRole.HEAD),
            (
                Node("head-a", "192.0.2.10", NodeRole.WORKER),
                worker,
            ),
        )
        adapter = _RayFake()

        result = ClusterReconfigurator(
            adapter,
            MemoryReconfigurationJournal(),
        ).run(
            ReconfigurationPlan(
                "integrated-operation",
                ClusterTopology(7, old_head, (new_worker, worker)),
                desired,
            ),
            maintenance_lease=lease,
        )

        self.assertEqual(ReconfigurationStatus.SUCCEEDED, result.status)
        self.assertEqual(8, result.effective_epoch)
        self.assertEqual("head-b", result.effective_head_id)
        stop_ids = [
            node_id
            for action, node_id, _epoch in adapter.events
            if action == "stop"
        ]
        self.assertEqual(["head-a", "head-b", "worker"], stop_ids)

    def test_t4_monitoring_scales_deterministically_to_1_8_32_nodes(self) -> None:
        for size in (1, 8, 32):
            with self.subTest(size=size):
                clock = FakeClock(seed=size)
                sensor = _ScaleSensor(clock)
                service = MonitoringService(
                    clock=clock,
                    sensor=sensor,
                    policy=MonitoringPolicy(
                        interval_seconds=1,
                        stale_after_seconds=5,
                        maximum_backoff_seconds=8,
                        backoff_multiplier=2,
                    ),
                )
                node_ids = [
                    f"synthetic-node-{index:02d}"
                    for index in range(size)
                ]

                observations = [
                    service.poll(node_id) for node_id in node_ids
                ]

                self.assertEqual(node_ids, sensor.calls)
                self.assertTrue(
                    all(
                        item.snapshot.state is MetricState.OK
                        for item in observations
                    )
                )

    def test_t1_rayless_child_has_zero_import_side_effects(self) -> None:
        project_root = Path(__file__).parents[1]
        source_root = project_root / "src"
        test_root = project_root / "tests"
        child = textwrap.dedent(
            f"""
            import json
            import os
            import sys
            import threading

            sys.path.insert(0, {str(test_root)!r})
            sys.path.insert(0, {str(source_root)!r})
            from fake_test_kit.guard import (
                FORBIDDEN_USER_ENVIRONMENT_KEYS,
                NoLiveAccessGuard,
            )

            touches = {{
                "filesystem": 0,
                "network": 0,
                "process": 0,
                "profile": 0,
                "thread": 0,
            }}
            write_flags = (
                os.O_APPEND | os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR
            )
            filesystem_events = {{
                "os.chmod", "os.chown", "os.link", "os.mkdir", "os.remove",
                "os.rename", "os.rmdir", "os.symlink", "os.truncate",
                "os.utime",
            }}
            def block_filesystem_mutation(event, arguments):
                flags = arguments[2] if event == "open" else 0
                if (
                    event in filesystem_events
                    or (
                        event == "open"
                        and isinstance(flags, int)
                        and flags & write_flags
                    )
                ):
                    touches["filesystem"] += 1
                    raise AssertionError("filesystem mutation during import")
            def blocked_thread(*args, **kwargs):
                touches["thread"] += 1
                raise AssertionError("thread touch during import")

            sys.addaudithook(block_filesystem_mutation)
            threading.Thread.start = blocked_thread
            assert not FORBIDDEN_USER_ENVIRONMENT_KEYS.intersection(os.environ)
            guard = NoLiveAccessGuard()
            with guard:
                import rcm
                import rcm.adapters
                import rcm.cleanup
                import rcm.cluster
                import rcm.core
                import rcm.monitoring
                import rcm.ports
                import rcm.ray
                import rcm.rdp
                import rcm.reconfiguration
                import rcm.release
                import rcm.runtime
                from rcm.adapters.windows import WindowsRdpLauncher
                from rcm.core import CapabilityState
                capability = WindowsRdpLauncher(
                    filesystem=object(), directory="synthetic-rdp",
                ).capability()
                assert capability.state in tuple(CapabilityState)
                assert "ray" not in sys.modules
                assert "tkinter" not in sys.modules
                assert guard.violations == []
            assert guard.resource_count() == 0
            assert touches == {{
                "filesystem": 0,
                "network": 0,
                "process": 0,
                "profile": 0,
                "thread": 0,
            }}
            print(json.dumps(touches, sort_keys=True))
            """
        )

        child_env = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        }
        for name in ("SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                child_env[name] = os.environ[name]
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", child],
            cwd=project_root,
            env=child_env,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(
            {
                "filesystem": 0,
                "network": 0,
                "process": 0,
                "profile": 0,
                "thread": 0,
            },
            json.loads(completed.stdout),
        )


if __name__ == "__main__":
    unittest.main()
