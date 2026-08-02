from __future__ import annotations

import unittest
from threading import Barrier, Thread

from rcm.adapters.ray_cli import RayCliAdapter, RayCliSettings
from rcm.cluster import (
    BusyAssessment,
    ClusterBusyPolicy,
    ClusterMember,
    ClusterMemberState,
    ClusterSnapshot,
    MaintenanceGuard,
)
from rcm.core import (
    ActionStatus,
    BusyState,
    ConflictError,
    Node,
    NodeRole,
)
from rcm.ports import ProcessRequest, ProcessResult
from rcm.ray import (
    RayCommandBuilder,
    RayMode,
    RayStartSpec,
    RayStatusSpec,
    RayStopSpec,
)
from rcm.runtime import CancellationToken


class FakeProcessRunner:
    def __init__(self, result: ProcessResult | None = None) -> None:
        self.result = result or ProcessResult(0)
        self.requests: list[ProcessRequest] = []
        self.cancellations: list[object | None] = []

    def run(
        self,
        request: ProcessRequest,
        *,
        cancellation: object | None = None,
    ) -> ProcessResult:
        self.requests.append(request)
        self.cancellations.append(cancellation)
        return self.result


class RayCommandBuilderTests(unittest.TestCase):
    def test_head_command_matches_frozen_separate_token_order(self) -> None:
        command = RayCommandBuilder().start(
            RayStartSpec(
                "ray.exe",
                RayMode.HEAD,
                node_ip_address="192.0.2.10",
                port=6379,
                dashboard_host="0.0.0.0",
                num_cpus=8,
            )
        )
        self.assertEqual(
            (
                "ray.exe",
                "start",
                "--head",
                "--node-ip-address",
                "192.0.2.10",
                "--port",
                "6379",
                "--dashboard-host",
                "0.0.0.0",
                "--num-cpus",
                "8",
            ),
            command.arguments,
        )

    def test_worker_command_matches_frozen_fixed_port_matrix(self) -> None:
        command = RayCommandBuilder().start(
            RayStartSpec(
                "ray.exe",
                RayMode.WORKER,
                address="192.0.2.10:6379",
                node_ip_address="192.0.2.20",
                num_cpus=4,
                temp_dir="C:/synthetic temp/ray",
                node_manager_port=6380,
                object_manager_port=6381,
                runtime_env_agent_port=6382,
                dashboard_agent_grpc_port=6383,
                dashboard_agent_listen_port=6384,
                metrics_export_port=6385,
                min_worker_port=10002,
                max_worker_port=10100,
                node_name="synthetic-worker",
                block=True,
            )
        )
        self.assertEqual(
            (
                "ray.exe",
                "start",
                "--address",
                "192.0.2.10:6379",
                "--node-ip-address",
                "192.0.2.20",
                "--num-cpus",
                "4",
                "--temp-dir",
                "C:/synthetic temp/ray",
                "--node-manager-port",
                "6380",
                "--object-manager-port",
                "6381",
                "--runtime-env-agent-port",
                "6382",
                "--dashboard-agent-grpc-port",
                "6383",
                "--dashboard-agent-listen-port",
                "6384",
                "--metrics-export-port",
                "6385",
                "--min-worker-port",
                "10002",
                "--max-worker-port",
                "10100",
                "--node-name",
                "synthetic-worker",
                "--block",
            ),
            command.arguments,
        )

    def test_driver_only_is_explicit_cpu_zero(self) -> None:
        command = RayCommandBuilder().start(
            RayStartSpec(
                "ray.exe",
                RayMode.DRIVER_ONLY,
                address="192.0.2.10:6379",
                node_ip_address="192.0.2.30",
            )
        )
        self.assertEqual(
            (
                "ray.exe",
                "start",
                "--address",
                "192.0.2.10:6379",
                "--node-ip-address",
                "192.0.2.30",
                "--num-cpus",
                "0",
            ),
            command.arguments,
        )
        with self.assertRaisesRegex(ValueError, "requires num_cpus zero"):
            RayStartSpec(
                "ray.exe",
                RayMode.DRIVER_ONLY,
                address="192.0.2.10:6379",
                num_cpus=1,
            )
        with self.assertRaisesRegex(ValueError, "require an address"):
            RayStartSpec("ray.exe", RayMode.DRIVER_ONLY)

    def test_status_stop_and_hostile_values_remain_argv_only(self) -> None:
        builder = RayCommandBuilder()
        self.assertEqual(
            ("ray.exe", "status", "--address", "192.0.2.10:6379"),
            builder.status(
                RayStatusSpec("ray.exe", "192.0.2.10:6379")
            ).arguments,
        )
        self.assertEqual(
            (
                "ray.exe",
                "stop",
                "--force",
                "--grace-period",
                "2.5",
            ),
            builder.stop(
                RayStopSpec(
                    "ray.exe",
                    force=True,
                    grace_period_seconds=2.5,
                )
            ).arguments,
        )
        with self.assertRaises(ValueError):
            RayStartSpec(
                "ray.exe",
                RayMode.WORKER,
                address="synthetic\n--head",
            )
        with self.assertRaises(ValueError):
            RayStartSpec(
                "ray.exe",
                RayMode.WORKER,
                address="192.0.2.10:6379",
                min_worker_port=10100,
                max_worker_port=10002,
            )


class RayCliAdapterTests(unittest.TestCase):
    def _settings(
        self,
        *,
        local_node_id: str = "worker",
        driver_only: bool = False,
    ) -> RayCliSettings:
        return RayCliSettings(
            "C:/synthetic path/ray.exe",
            local_node_id,
            6379,
            num_cpus=0 if driver_only else 4,
            driver_only=driver_only,
            temp_dir="C:/synthetic temp/ray",
            node_manager_port=6380,
            object_manager_port=6381,
            runtime_env_agent_port=6382,
            dashboard_agent_grpc_port=6383,
            dashboard_agent_listen_port=6384,
            metrics_export_port=6385,
            min_worker_port=10002,
            max_worker_port=10100,
        )

    def test_worker_join_uses_process_port_and_bounded_request(self) -> None:
        runner = FakeProcessRunner(
            ProcessResult(
                0,
                stdout="private-looking output is never returned",
                duration_seconds=0.25,
            )
        )
        adapter = RayCliAdapter(self._settings(), runner)
        worker = Node(
            "worker",
            "192.0.2.20",
            NodeRole.WORKER,
        )
        head = Node("head", "192.0.2.10", NodeRole.HEAD)
        token = CancellationToken()
        result = adapter.join_worker(
            worker,
            head,
            epoch=8,
            cancellation=token,
        )
        self.assertTrue(result.ok)
        self.assertEqual("ray.worker_joined", result.code)
        self.assertEqual("", result.message)
        self.assertEqual(1, len(runner.requests))
        request = runner.requests[0]
        self.assertEqual(
            "C:/synthetic path/ray.exe",
            request.argv[0],
        )
        self.assertNotIn("--block", request.argv)
        self.assertEqual(65_536, request.max_output_bytes)
        self.assertIs(token, runner.cancellations[0])

    def test_driver_only_joins_as_zero_cpu_worker_and_refuses_head(self) -> None:
        runner = FakeProcessRunner()
        adapter = RayCliAdapter(
            self._settings(driver_only=True),
            runner,
        )
        worker = Node("worker", "192.0.2.20", NodeRole.WORKER)
        head = Node("head", "192.0.2.10", NodeRole.HEAD)

        joined = adapter.join_worker(worker, head, epoch=8)
        refused = adapter.start_head(
            Node("worker", "192.0.2.20", NodeRole.HEAD),
            epoch=8,
        )

        self.assertTrue(joined.ok)
        self.assertEqual(
            (
                "C:/synthetic path/ray.exe",
                "start",
                "--address",
                "192.0.2.10:6379",
                "--node-ip-address",
                "192.0.2.20",
                "--num-cpus",
                "0",
                "--temp-dir",
                "C:/synthetic temp/ray",
                "--node-manager-port",
                "6380",
                "--object-manager-port",
                "6381",
                "--runtime-env-agent-port",
                "6382",
                "--dashboard-agent-grpc-port",
                "6383",
                "--dashboard-agent-listen-port",
                "6384",
                "--metrics-export-port",
                "6385",
                "--min-worker-port",
                "10002",
                "--max-worker-port",
                "10100",
                "--node-name",
                "worker",
            ),
            runner.requests[0].argv,
        )
        self.assertFalse(refused.ok)
        self.assertEqual("rejected", refused.code)
        with self.assertRaisesRegex(ValueError, "dashboard settings"):
            RayCliSettings(
                "ray.exe",
                "worker",
                6379,
                num_cpus=0,
                driver_only=True,
                dashboard_host="127.0.0.1",
            )

    def test_timeout_cancellation_and_remote_rejection_are_typed(self) -> None:
        worker = Node("worker", "192.0.2.20", NodeRole.WORKER)
        timeout_runner = FakeProcessRunner(
            ProcessResult(None, timed_out=True)
        )
        timeout_adapter = RayCliAdapter(
            self._settings(),
            timeout_runner,
        )
        result = timeout_adapter.stop(worker, epoch=1)
        self.assertEqual(ActionStatus.FAILED, result.status)
        self.assertEqual("ray.timeout", result.code)

        cancelled_runner = FakeProcessRunner(
            ProcessResult(None, cancelled=True)
        )
        cancelled_adapter = RayCliAdapter(
            self._settings(),
            cancelled_runner,
        )
        result = cancelled_adapter.stop(worker, epoch=1)
        self.assertEqual(ActionStatus.CANCELLED, result.status)
        self.assertEqual("ray.cancelled", result.code)

        remote = Node("remote", "192.0.2.30", NodeRole.WORKER)
        result = cancelled_adapter.stop(remote, epoch=1)
        self.assertEqual("rejected", result.code)
        self.assertEqual(1, len(cancelled_runner.requests))

    def test_verify_is_exact_for_local_head_and_fails_closed_for_cluster(
        self,
    ) -> None:
        runner = FakeProcessRunner()
        adapter = RayCliAdapter(
            self._settings(local_node_id="head"), runner,
        )
        head = Node("head", "192.0.2.10", NodeRole.HEAD)
        worker = Node("worker", "192.0.2.20", NodeRole.WORKER)

        self.assertTrue(adapter.verify((head,), head, epoch=8).ok)
        cluster = adapter.verify((head, worker), head, epoch=8)
        self.assertEqual("unsupported", cluster.code)
        self.assertEqual(1, len(runner.requests))
        self.assertEqual("status", runner.requests[0].argv[1])

    def test_adapter_rejects_epoch_regression(self) -> None:
        runner = FakeProcessRunner()
        adapter = RayCliAdapter(self._settings(), runner)
        worker = Node("worker", "192.0.2.20", NodeRole.WORKER)
        self.assertTrue(adapter.preflight(worker, epoch=3).ok)
        self.assertEqual("stale", adapter.stop(worker, epoch=2).code)
        self.assertEqual([], runner.requests)

    def test_ipv6_head_endpoint_is_bracketed_for_join_and_status(self) -> None:
        worker_runner = FakeProcessRunner()
        worker_adapter = RayCliAdapter(self._settings(), worker_runner)
        worker = Node("worker", "2001:db8::20", NodeRole.WORKER)
        head = Node("head", "2001:db8::10", NodeRole.HEAD)
        self.assertTrue(worker_adapter.join_worker(worker, head, epoch=8).ok)
        self.assertIn("[2001:db8::10]:6379", worker_runner.requests[0].argv)

        head_runner = FakeProcessRunner()
        head_adapter = RayCliAdapter(
            self._settings(local_node_id="head"), head_runner,
        )
        self.assertTrue(head_adapter.verify((head,), head, epoch=8).ok)
        self.assertIn("[2001:db8::10]:6379", head_runner.requests[0].argv)


class ClusterPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.head = Node("head", "192.0.2.10", NodeRole.HEAD)
        self.worker = Node(
            "worker",
            "192.0.2.20",
            NodeRole.WORKER,
        )
        self.policy = ClusterBusyPolicy(max_age_seconds=10)

    def snapshot(
        self,
        *,
        jobs: int | None,
        tasks: int | None,
        evidence_fresh: bool,
        captured_at: float = 100,
    ) -> ClusterSnapshot:
        return ClusterSnapshot(
            7,
            "head",
            (
                ClusterMember(
                    self.head,
                    ClusterMemberState.ALIVE,
                    captured_at,
                    jobs,
                    tasks,
                    evidence_fresh,
                ),
                ClusterMember(
                    self.worker,
                    ClusterMemberState.STOPPED,
                    captured_at,
                ),
            ),
            captured_at,
        )

    def test_only_fresh_explicit_zero_workload_is_idle(self) -> None:
        assessment = self.policy.assess(
            self.snapshot(jobs=0, tasks=0, evidence_fresh=True),
            now=105,
        )
        self.assertEqual(BusyState.IDLE, assessment.state)
        self.assertTrue(assessment.safe_for_maintenance)

        unknown = self.policy.assess(
            self.snapshot(
                jobs=None,
                tasks=None,
                evidence_fresh=False,
            ),
            now=105,
        )
        self.assertEqual(BusyState.UNKNOWN, unknown.state)
        self.assertFalse(unknown.safe_for_maintenance)

    def test_active_workload_stale_and_maintenance_are_distinct(self) -> None:
        busy = self.policy.assess(
            self.snapshot(jobs=1, tasks=0, evidence_fresh=True),
            now=105,
        )
        self.assertEqual(BusyState.BUSY, busy.state)
        stale = self.policy.assess(
            self.snapshot(
                jobs=0,
                tasks=0,
                evidence_fresh=True,
            ),
            now=111,
        )
        self.assertEqual(BusyState.UNKNOWN, stale.state)
        maintenance = self.policy.assess(
            self.snapshot(
                jobs=0,
                tasks=0,
                evidence_fresh=True,
            ),
            now=105,
            maintenance=True,
        )
        self.assertEqual(BusyState.MAINTENANCE, maintenance.state)

    def test_maintenance_lease_is_epoch_bound_and_idempotent(self) -> None:
        guard = MaintenanceGuard()
        idle = BusyAssessment(BusyState.IDLE, 7, ())
        lease = guard.acquire(
            request_id="operation-1",
            assessment=idle,
            expected_epoch=7,
        )
        self.assertIs(
            lease,
            guard.acquire(
                request_id="operation-1",
                assessment=idle,
                expected_epoch=7,
            ),
        )
        with self.assertRaises(ConflictError):
            guard.acquire(
                request_id="operation-2",
                assessment=idle,
                expected_epoch=7,
            )
        guard.release(lease)
        guard.release(lease)
        self.assertFalse(guard.active)

    def test_concurrent_maintenance_acquire_has_one_owner(self) -> None:
        guard = MaintenanceGuard()
        idle = BusyAssessment(BusyState.IDLE, 7, ())
        barrier = Barrier(3)
        leases = []
        conflicts: list[ConflictError] = []

        def acquire(request_id: str) -> None:
            barrier.wait()
            try:
                leases.append(guard.acquire(
                    request_id=request_id,
                    assessment=idle,
                    expected_epoch=7,
                ))
            except ConflictError as exc:
                conflicts.append(exc)
            barrier.wait()

        threads = [
            Thread(target=acquire, args=(f"operation-{index}",))
            for index in (1, 2)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        barrier.wait()
        for thread in threads:
            thread.join(1)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual((1, 1), (len(leases), len(conflicts)))
        guard.release(leases[0])


if __name__ == "__main__":
    unittest.main()
