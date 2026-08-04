from __future__ import annotations

from io import BytesIO
import json
import unittest
from unittest import mock

from rcm.adapters.ray_cli import LocalRayProcessRunner, RayStateCliObserver
from rcm.cluster import (
    ClusterBusyPolicy,
    ClusterStateService,
    ClusterWorkloadEvidence,
)
from rcm.core import BusyState, Node, NodeRole
from rcm.ports import ProcessRequest, ProcessResult
from rcm.ray import RayCommandBuilder, RayStateListSpec, RayStateResource
from rcm.runtime import CancellationToken
from tests.pr06_t3_probe import _bounded_cli_run


RAY_EXE = "C:/Synthetic/Ray/ray.exe"
RAY_ADDRESS = "192.0.2.10:6379"


def _json_result(value: object, **kwargs: object) -> ProcessResult:
    return ProcessResult(0, stdout=json.dumps(value), **kwargs)


class StateRunner:
    def __init__(
        self,
        nodes: list[dict[str, object]],
        overrides: dict[str, ProcessResult] | None = None,
    ) -> None:
        self.nodes = nodes
        self.overrides = overrides or {}
        self.requests: list[ProcessRequest] = []

    def run(
        self,
        request: ProcessRequest,
        *,
        cancellation: object | None = None,
    ) -> ProcessResult:
        del cancellation
        self.requests.append(request)
        resource = request.argv[2]
        if resource in self.overrides:
            return self.overrides[resource]
        return _json_result(self.nodes if resource == "nodes" else [])


class RayStateObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.head = Node("head", "192.0.2.10", NodeRole.HEAD)
        self.worker = Node("worker", "192.0.2.20", NodeRole.WORKER)
        self.nodes = (self.head, self.worker)
        self.alive = [
            {
                "node_id": "synthetic-ray-head-id",
                "node_ip": "192.0.2.10",
                "node_name": "head",
                "state": "ALIVE",
                "is_head_node": True,
            },
            {
                "node_id": "synthetic-ray-worker-id",
                "node_ip": "192.0.2.20",
                "node_name": "worker",
                "state": "ALIVE",
                "is_head_node": False,
            },
        ]

    def observer(
        self, runner: StateRunner, *, clock: object = lambda: 100.0,
    ) -> RayStateCliObserver:
        return RayStateCliObserver(
            RAY_EXE, RAY_ADDRESS, runner, clock=clock,
        )

    def diagnose(
        self,
        runner: StateRunner,
        *,
        now: float = 100.0,
        nodes: tuple[Node, ...] | None = None,
    ):
        service = ClusterStateService(
            self.observer(runner), ClusterBusyPolicy(max_age_seconds=10),
        )
        return service.diagnose(
            self.nodes if nodes is None else nodes,
            expected_head_id="head",
            epoch=17,
            now=now,
        )

    def test_builder_uses_only_five_exact_bounded_state_queries(self) -> None:
        builder = RayCommandBuilder()
        expected_filters = {
            RayStateResource.NODES: (),
            RayStateResource.JOBS: (
                "status!=STOPPED", "status!=SUCCEEDED", "status!=FAILED",
            ),
            RayStateResource.TASKS: ("state!=FINISHED", "state!=FAILED"),
            RayStateResource.ACTORS: ("state!=DEAD",),
            RayStateResource.PLACEMENT_GROUPS: ("state!=REMOVED",),
        }
        local_runner = LocalRayProcessRunner(RAY_EXE)
        for resource, filters in expected_filters.items():
            command = builder.list_state(RayStateListSpec(
                RAY_EXE, resource, RAY_ADDRESS,
            ))
            self.assertEqual((RAY_EXE, "list", resource.value), command.arguments[:3])
            self.assertIn(("--format", "json"), tuple(zip(
                command.arguments, command.arguments[1:]
            )))
            self.assertEqual(
                filters,
                tuple(
                    command.arguments[index + 1]
                    for index, value in enumerate(command.arguments)
                    if value == "--filter"
                ),
            )
            self.assertIn("10", command.arguments)
            self.assertIn("10000", command.arguments)
            local_runner._validate_request(ProcessRequest(command.arguments))
        with self.assertRaises(ValueError):
            RayStateListSpec(
                RAY_EXE, RayStateResource.NODES, RAY_ADDRESS,
                timeout_seconds=11,
            )
        hostile = list(builder.list_state(RayStateListSpec(
            RAY_EXE, RayStateResource.NODES, RAY_ADDRESS,
        )).arguments)
        hostile[2] = "objects"
        with self.assertRaises(ValueError):
            local_runner._validate_request(ProcessRequest(tuple(hostile)))

    def test_local_runner_reports_discarded_output(self) -> None:
        class CompletedProcess:
            def __init__(self) -> None:
                self.stdout = BytesIO(b"0123456789")
                self.stderr = BytesIO(b"abcdefghij")
                self.returncode = 0

            def poll(self) -> int:
                return self.returncode

            def wait(self) -> int:
                return self.returncode

        runner = LocalRayProcessRunner(RAY_EXE)
        with mock.patch.object(runner, "_assert_executable"), mock.patch(
            "subprocess.Popen", return_value=CompletedProcess()
        ):
            result = runner.run(ProcessRequest(
                (RAY_EXE, "--version"), max_output_bytes=7,
            ))
        self.assertTrue(result.output_truncated)
        self.assertLessEqual(
            len(result.stdout.encode()) + len(result.stderr.encode()), 7,
        )

        invalid = CompletedProcess()
        invalid.stdout = BytesIO(b"\xff" * 7)
        invalid.stderr = BytesIO()
        with mock.patch.object(runner, "_assert_executable"), mock.patch(
            "subprocess.Popen", return_value=invalid
        ):
            result = runner.run(ProcessRequest(
                (RAY_EXE, "--version"), max_output_bytes=7,
            ))
        self.assertTrue(result.output_invalid_encoding)
        self.assertEqual(("", ""), (result.stdout, result.stderr))
        self.assertLessEqual(
            len(result.stdout.encode()) + len(result.stderr.encode()), 7,
        )

    def test_t3_runner_streams_large_output_into_shared_bound(self) -> None:
        class TrackingStream(BytesIO):
            largest_read = 0

            def read(self, size: int = -1) -> bytes:
                self.largest_read = max(self.largest_read, size)
                if not 0 < size <= 4_096:
                    raise AssertionError("T3 runner attempted an unbounded read")
                return super().read(size)

        class Process:
            def __init__(self) -> None:
                self.stdout = TrackingStream(b"x" * 2_000_000)
                self.stderr = TrackingStream(b"y" * 2_000_000)
                self.returncode = 0

            def poll(self) -> int:
                return self.returncode

            def wait(self) -> int:
                return self.returncode

            def kill(self) -> None:
                raise AssertionError("completed process must not be killed")

        process = Process()
        with mock.patch(
            "tests.pr06_t3_probe.subprocess.Popen", return_value=process,
        ):
            result = _bounded_cli_run(ProcessRequest(
                ("ray", "list", "nodes"), max_output_bytes=65_536,
            ))
        self.assertTrue(result.output_truncated)
        self.assertEqual(
            65_536,
            len(result.stdout.encode()) + len(result.stderr.encode()),
        )
        self.assertLessEqual(process.stdout.largest_read, 4_096)
        self.assertLessEqual(process.stderr.largest_read, 4_096)

    def test_five_complete_zero_queries_are_point_in_time_idle(self) -> None:
        runner = StateRunner(self.alive)
        diagnosis = self.diagnose(runner)
        self.assertEqual(BusyState.IDLE, diagnosis.assessment.state)
        self.assertIsNotNone(diagnosis.snapshot)
        self.assertTrue(diagnosis.snapshot.workload.complete)
        self.assertEqual((0, 0, 0, 0), diagnosis.snapshot.workload.counts)
        self.assertEqual(
            ("nodes", "jobs", "tasks", "actors", "placement-groups"),
            tuple(request.argv[2] for request in runner.requests),
        )
        self.assertTrue(all(request.timeout_seconds <= 10 for request in runner.requests))

    def test_exact_ray_empty_sentinel_is_zero_but_variants_fail_closed(self) -> None:
        for line_ending in ("\n", "\r\n"):
            with self.subTest(exact_line_ending=repr(line_ending)):
                sentinel = ProcessResult(
                    0, stdout="No resource in the cluster" + line_ending,
                )
                overrides = {
                    resource: sentinel for resource in (
                        "jobs", "tasks", "actors", "placement-groups",
                    )
                }
                self.assertEqual(
                    BusyState.IDLE,
                    self.diagnose(
                        StateRunner(self.alive, overrides)
                    ).assessment.state,
                )

        sentinel = ProcessResult(0, stdout="No resource in the cluster\r\n")
        overrides = {
            resource: sentinel for resource in (
                "jobs", "tasks", "actors", "placement-groups",
            )
        }
        for result in (
            ProcessResult(0, stdout="No resource in the cluster"),
            ProcessResult(0, stdout=" No resource in the cluster\r\n"),
            ProcessResult(0, stdout="\tNo resource in the cluster\r\n"),
            ProcessResult(0, stdout="No resource in the cluster \r\n"),
            ProcessResult(0, stdout="No resource in the cluster\r\n\r\n"),
            ProcessResult(0, stdout="No resource in the cluster."),
            ProcessResult(
                0, stdout="No resource in the cluster\r\n",
                stderr="synthetic warning",
            ),
            ProcessResult(
                0, stdout="No resource in the cluster\r\n",
                output_truncated=True,
            ),
        ):
            with self.subTest(result=result):
                mutated = dict(overrides)
                mutated["jobs"] = result
                diagnosis = self.diagnose(StateRunner(self.alive, mutated))
                self.assertEqual(BusyState.UNKNOWN, diagnosis.assessment.state)
                self.assertIsNone(diagnosis.snapshot.workload.active_jobs)

    def test_non_standard_json_and_duplicate_keys_fail_closed(self) -> None:
        for constant in ("NaN", "Infinity", "-Infinity"):
            nodes = json.dumps(self.alive)
            mutated = nodes[:-2] + f', "metadata": {constant}' + nodes[-2:]
            with self.subTest(constant=constant):
                diagnosis = self.diagnose(StateRunner(
                    self.alive,
                    {"nodes": ProcessResult(0, stdout=mutated)},
                ))
                self.assertEqual(BusyState.UNKNOWN, diagnosis.assessment.state)

        duplicate_key = json.dumps(self.alive).replace(
            '"state": "ALIVE"',
            '"state": "ALIVE", "state": "ALIVE"',
            1,
        )
        diagnosis = self.diagnose(StateRunner(
            self.alive,
            {"nodes": ProcessResult(0, stdout=duplicate_key)},
        ))
        self.assertEqual(BusyState.UNKNOWN, diagnosis.assessment.state)

    def test_known_active_is_busy_even_when_another_query_is_partial(self) -> None:
        runner = StateRunner(self.alive, {
            "jobs": _json_result([{
                "status": "RUNNING",
                "entrypoint": "synthetic-sensitive-entrypoint",
                "metadata": {"synthetic": "discard-me"},
            }]),
            "tasks": ProcessResult(None, timed_out=True),
        })
        diagnosis = self.diagnose(runner)
        self.assertEqual(BusyState.BUSY, diagnosis.assessment.state)
        self.assertEqual(("cluster:active_workload",), diagnosis.assessment.reasons)
        rendered = repr(diagnosis) + repr(diagnosis.snapshot.workload.reasons)
        self.assertNotIn("synthetic-sensitive-entrypoint", rendered)
        self.assertNotIn("discard-me", rendered)

    def test_zero_with_warning_truncation_or_unknown_enum_is_unknown(self) -> None:
        cases = {
            "warning": {
                "actors": _json_result([], stderr="synthetic warning")
            },
            "truncated": {
                "tasks": _json_result([], output_truncated=True)
            },
            "malformed": {
                "jobs": ProcessResult(0, stdout="not-json")
            },
            "nonzero": {
                "placement-groups": ProcessResult(2)
            },
            "unknown enum": {
                "actors": _json_result([{"state": "SYNTHETIC_NEW_STATE"}])
            },
            "invalid UTF-8": {
                "nodes": ProcessResult(0, output_invalid_encoding=True)
            },
        }
        for name, overrides in cases.items():
            with self.subTest(case=name):
                diagnosis = self.diagnose(StateRunner(self.alive, overrides))
                self.assertEqual(BusyState.UNKNOWN, diagnosis.assessment.state)
                self.assertFalse(diagnosis.assessment.safe_for_maintenance)

    def test_topology_anomalies_fail_closed_but_dead_history_is_ignored(self) -> None:
        anomalies = {
            "missing head": self.alive[1:],
            "unexpected alive": self.alive + [{
                "node_id": "synthetic-extra-id",
                "node_ip": "192.0.2.30",
                "node_name": "extra",
                "state": "ALIVE",
                "is_head_node": False,
            }],
            "duplicate alive": self.alive + [dict(self.alive[0])],
            "duplicate Ray node id": [
                self.alive[0],
                dict(
                    self.alive[1],
                    node_id=self.alive[0]["node_id"],
                ),
            ],
            "ambiguous identity": self.alive + [{
                "node_id": "synthetic-ambiguous-id",
                "node_ip": "192.0.2.20",
                "node_name": "head",
                "state": "ALIVE",
                "is_head_node": True,
            }],
            "head mismatch": [dict(self.alive[0], is_head_node=False), self.alive[1]],
        }
        for name, observed in anomalies.items():
            with self.subTest(case=name):
                result = self.diagnose(StateRunner(observed))
                self.assertEqual(BusyState.UNKNOWN, result.assessment.state)

        historical = self.alive + [dict(
            self.alive[0], node_id="synthetic-dead-id", state="DEAD"
        )]
        self.assertEqual(
            BusyState.IDLE,
            self.diagnose(StateRunner(historical)).assessment.state,
        )

    def test_service_samples_shared_clock_after_observation_completes(self) -> None:
        runner = StateRunner(self.alive)
        samples: list[int] = []
        values = iter((100.001, 100.002))

        def clock() -> float:
            samples.append(len(runner.requests))
            return next(values)

        service = ClusterStateService(
            self.observer(runner, clock=clock),
            ClusterBusyPolicy(max_age_seconds=10),
            clock=clock,
        )
        diagnosis = service.diagnose(
            self.nodes,
            expected_head_id="head",
            epoch=17,
        )
        self.assertEqual(BusyState.IDLE, diagnosis.assessment.state)
        self.assertEqual(100.001, diagnosis.snapshot.captured_at)
        self.assertEqual([0, 5], samples)

    def test_slow_queries_age_from_oldest_contributing_boundary(self) -> None:
        elapsed = [0.0]

        class SlowRunner(StateRunner):
            def run(
                self,
                request: ProcessRequest,
                *,
                cancellation: object | None = None,
            ) -> ProcessResult:
                result = super().run(request, cancellation=cancellation)
                elapsed[0] += 9.0
                return result

        runner = SlowRunner(self.alive)

        def clock() -> float:
            return elapsed[0]

        service = ClusterStateService(
            self.observer(runner, clock=clock),
            ClusterBusyPolicy(max_age_seconds=10),
            clock=clock,
        )
        diagnosis = service.diagnose(
            self.nodes,
            expected_head_id="head",
            epoch=17,
        )
        self.assertEqual(BusyState.UNKNOWN, diagnosis.assessment.state)
        self.assertEqual(0.0, diagnosis.snapshot.captured_at)
        self.assertEqual(("stale_snapshot",), diagnosis.assessment.reasons)

    def test_configuration_bound_cancellation_and_freshness_fail_closed(self) -> None:
        runner = StateRunner(self.alive)
        service = ClusterStateService(
            self.observer(runner), ClusterBusyPolicy(max_age_seconds=10),
        )
        empty = service.diagnose(
            (), expected_head_id="head", epoch=17, now=100,
        )
        self.assertEqual(BusyState.UNKNOWN, empty.assessment.state)
        self.assertEqual([], runner.requests)

        too_many = tuple(
            Node(
                f"node-{index}", f"192.0.2.{index + 1}",
                NodeRole.HEAD if index == 0 else NodeRole.WORKER,
            )
            for index in range(33)
        )
        oversized = service.diagnose(
            too_many, expected_head_id="node-0", epoch=17, now=100,
        )
        self.assertEqual(BusyState.UNKNOWN, oversized.assessment.state)
        self.assertEqual([], runner.requests)

        stale = self.diagnose(StateRunner(self.alive), now=111)
        self.assertEqual(BusyState.UNKNOWN, stale.assessment.state)

        token = CancellationToken()
        token.cancel()
        cancelled = service.diagnose(
            self.nodes, expected_head_id="head", epoch=17, now=100,
            cancellation=token,
        )
        self.assertEqual(BusyState.UNKNOWN, cancelled.assessment.state)

    def test_workload_evidence_rejects_false_complete_claims(self) -> None:
        with self.assertRaises(ValueError):
            ClusterWorkloadEvidence(
                100, 0, 0, 0, None, complete=True,
            )
        with self.assertRaises(ValueError):
            ClusterWorkloadEvidence(
                100, 0, 0, 0, 0, complete=True,
                reasons=("tasks:warning",),
            )


if __name__ == "__main__":
    unittest.main()
