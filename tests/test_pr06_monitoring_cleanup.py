from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Callable
import unittest

from fake_test_kit import FakeClock
from rcm.cleanup import (
    CleanupFacade,
    CleanupOutcome,
    CleanupPolicy,
    CleanupRule,
    ProcessIdentity,
    ProcessObservation,
)
from rcm.adapters.process_cleanup import (
    LocalCleanupContext,
    PsutilProcessCleanupBackend,
    command_fingerprint,
    owner_token,
)
from rcm.adapters.sensors import PsutilSensor
from rcm.core import (
    ConflictError,
    MetricSnapshot,
    MetricState,
    PermissionDeniedError,
    RejectedError,
    UnavailableError,
    UnsupportedError,
)
from rcm.monitoring import MonitoringPolicy, MonitoringService


_OWNER = owner_token("SYNTHETIC_OPERATOR")
_OTHER_OWNER = owner_token("SYNTHETIC_OTHER_OPERATOR")
_COMMAND = ("synthetic-worker.exe", "--synthetic-task", "alpha")
_FINGERPRINT = command_fingerprint(_COMMAND)


class RecordingCleanupBackend:
    def __init__(self, observations: tuple[ProcessObservation, ...]) -> None:
        self.observations = observations
        self.inspect_results: list[ProcessIdentity | None] = []
        self.wait_results: list[bool] = []
        self.events: list[tuple[str, int, float | None]] = []

    def scan(self, limit: int) -> tuple[ProcessObservation, ...]:
        self.events.append(("scan", limit, None))
        return self.observations

    def inspect(self, pid: int) -> ProcessIdentity | None:
        self.events.append(("inspect", pid, None))
        if self.inspect_results:
            return self.inspect_results.pop(0)
        return None

    def request_graceful(self, expected: ProcessIdentity) -> bool:
        self.events.append(("graceful", expected.pid, None))
        return True

    def wait(self, pid: int, timeout_seconds: float) -> bool:
        self.events.append(("wait", pid, timeout_seconds))
        return self.wait_results.pop(0)

    def force(self, expected: ProcessIdentity) -> bool:
        self.events.append(("force", expected.pid, None))
        return True


def _identity(
    clock: FakeClock,
    *,
    pid: int = 41_001,
    owner: str = _OWNER,
    session_id: int = 7,
    image_name: str = "synthetic-worker.exe",
) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        create_time=clock.now().timestamp() - 3_600,
        image_name=image_name,
        owner_token=owner,
        session_id=session_id,
    )


def _observation(
    clock: FakeClock,
    *,
    pid: int = 41_001,
    owner: str = _OWNER,
    session_id: int = 7,
    fingerprint: str = _FINGERPRINT,
    connection_count: int = 0,
    image_name: str = "synthetic-worker.exe",
) -> ProcessObservation:
    return ProcessObservation(
        identity=_identity(
            clock,
            pid=pid,
            owner=owner,
            session_id=session_id,
            image_name=image_name,
        ),
        command_fingerprint=fingerprint,
        connection_count=connection_count,
    )


def _policy() -> CleanupPolicy:
    return CleanupPolicy(
        owner_token=_OWNER,
        session_id=7,
        rules=(
            CleanupRule(
                rule_id="synthetic-worker",
                image_names=("synthetic-worker.exe",),
                command_fingerprints=(_FINGERPRINT,),
                minimum_age_seconds=60,
            ),
        ),
        result_max_age_seconds=30,
        graceful_timeout_seconds=5,
        force_timeout_seconds=10,
    )


class CleanupFacadeTests(unittest.TestCase):
    def test_cleanup_rejects_timezone_ambiguous_wall_clock(self) -> None:
        clock = FakeClock(seed=1)
        clock.now = lambda: datetime(2020, 1, 1)  # type: ignore[method-assign]
        facade = CleanupFacade(
            clock=clock,
            backend=RecordingCleanupBackend(()),
            policy=_policy(),
        )

        with self.assertRaisesRegex(RejectedError, "timezone-aware"):
            facade.scan()

    def test_scan_requires_exact_command_owner_session_and_no_connection(
        self,
    ) -> None:
        clock = FakeClock(seed=1)
        observations = (
            _observation(clock, pid=41_001),
            _observation(
                clock,
                pid=41_002,
                fingerprint=hashlib.sha256(b"different").hexdigest(),
            ),
            _observation(clock, pid=41_003, owner=_OTHER_OWNER),
            _observation(clock, pid=41_004, session_id=8),
            _observation(clock, pid=41_005, connection_count=1),
            _observation(clock, pid=41_006, image_name="synthetic-other.exe"),
        )
        backend = RecordingCleanupBackend(observations)
        facade = CleanupFacade(
            clock=clock,
            backend=backend,
            policy=_policy(),
        )

        scan = facade.scan()

        self.assertEqual((41_001,), tuple(
            candidate.identity.pid for candidate in scan.candidates
        ))
        self.assertEqual(6, scan.inspected_count)

    def test_owner_and_image_case_policy_is_explicit(self) -> None:
        self.assertNotEqual(
            owner_token("Synthetic", case_sensitive=True),
            owner_token("synthetic", case_sensitive=True),
        )
        self.assertEqual(
            owner_token("Synthetic", case_sensitive=False),
            owner_token("synthetic", case_sensitive=False),
        )
        observation = _observation(
            FakeClock(seed=1),
            image_name="SYNTHETIC-WORKER.EXE",
        )
        rule = _policy().rules[0]
        self.assertFalse(rule.matches(observation, age_seconds=3600))
        self.assertTrue(
            replace(rule, image_case_sensitive=False).matches(
                observation,
                age_seconds=3600,
            )
        )

    def test_stale_evidence_is_rejected_before_process_revalidation(
        self,
    ) -> None:
        clock = FakeClock(seed=2)
        backend = RecordingCleanupBackend((_observation(clock),))
        facade = CleanupFacade(
            clock=clock,
            backend=backend,
            policy=_policy(),
        )
        candidate = facade.scan().candidates[0]
        clock.advance(31)

        report = facade.execute((candidate,))

        self.assertEqual(CleanupOutcome.SKIPPED_STALE, report.items[0].outcome)
        self.assertEqual(
            [("scan", _policy().max_processes + 1, None)],
            backend.events,
        )

    def test_identity_change_refuses_graceful_and_force_operations(self) -> None:
        clock = FakeClock(seed=3)
        observation = _observation(clock)
        replacements = (
            replace(
                observation.identity,
                create_time=observation.identity.create_time + 1,
            ),
            replace(observation.identity, image_name="synthetic-other.exe"),
            replace(observation.identity, owner_token=_OTHER_OWNER),
            replace(observation.identity, session_id=8),
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                backend = RecordingCleanupBackend((observation,))
                backend.inspect_results.append(replacement)
                facade = CleanupFacade(
                    clock=clock,
                    backend=backend,
                    policy=_policy(),
                )
                candidate = facade.scan().candidates[0]

                report = facade.execute((candidate,))

                self.assertEqual(
                    CleanupOutcome.SKIPPED_CHANGED,
                    report.items[0].outcome,
                )
                self.assertEqual(
                    [
                        ("scan", _policy().max_processes + 1, None),
                        ("inspect", observation.identity.pid, None),
                    ],
                    backend.events,
                )

    def test_graceful_completion_never_reaches_force(self) -> None:
        clock = FakeClock(seed=4)
        observation = _observation(clock)
        backend = RecordingCleanupBackend((observation,))
        backend.inspect_results.append(observation.identity)
        backend.wait_results.append(True)
        facade = CleanupFacade(
            clock=clock,
            backend=backend,
            policy=_policy(),
        )

        report = facade.execute(facade.scan().candidates)

        self.assertEqual(CleanupOutcome.GRACEFUL, report.items[0].outcome)
        self.assertEqual(
            [
                ("scan", _policy().max_processes + 1, None),
                ("inspect", observation.identity.pid, None),
                ("graceful", observation.identity.pid, None),
                ("wait", observation.identity.pid, 5),
            ],
            backend.events,
        )

    def test_force_requires_second_exact_identity_revalidation(self) -> None:
        clock = FakeClock(seed=5)
        observation = _observation(clock)
        backend = RecordingCleanupBackend((observation,))
        backend.inspect_results.extend(
            (observation.identity, observation.identity)
        )
        backend.wait_results.extend((False, True))
        facade = CleanupFacade(
            clock=clock,
            backend=backend,
            policy=_policy(),
        )

        report = facade.execute(facade.scan().candidates)

        self.assertEqual(CleanupOutcome.FORCED, report.items[0].outcome)
        self.assertEqual(
            [
                ("scan", _policy().max_processes + 1, None),
                ("inspect", observation.identity.pid, None),
                ("graceful", observation.identity.pid, None),
                ("wait", observation.identity.pid, 5),
                ("inspect", observation.identity.pid, None),
                ("force", observation.identity.pid, None),
                ("wait", observation.identity.pid, 10),
            ],
            backend.events,
        )

    def test_evidence_is_bound_to_one_facade_and_one_execution(self) -> None:
        clock = FakeClock(seed=6)
        observation = _observation(clock)
        backend = RecordingCleanupBackend((observation,))
        backend.inspect_results.append(None)
        facade = CleanupFacade(
            clock=clock,
            backend=backend,
            policy=_policy(),
        )
        candidate = facade.scan().candidates[0]
        facade.execute((candidate,))

        with self.assertRaises(RejectedError):
            facade.execute((candidate,))

    def test_effectful_cleanup_imports_are_method_local(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "rcm"
            / "adapters"
            / "process_cleanup.py"
        ).read_text(encoding="utf-8")
        prefix = source.split(
            "class PsutilProcessCleanupBackend:",
            maxsplit=1,
        )[0]
        self.assertNotIn("import psutil", prefix)
        self.assertNotIn("import ctypes", prefix)

    def test_psutil_adapter_uses_only_pid_specific_mutations(self) -> None:
        class SyntheticProcess:
            def __init__(self) -> None:
                self.info = {
                    "pid": 41_001,
                    "create_time": 1_500_000_000.0,
                    "name": "synthetic-worker.exe",
                    "username": "SYNTHETIC_OPERATOR",
                    "cmdline": list(_COMMAND),
                }
                self.events: list[str] = []

            def username(self) -> str:
                return str(self.info["username"])

            def create_time(self) -> float:
                return float(self.info["create_time"])

            def name(self) -> str:
                return str(self.info["name"])

            def connections(self, *, kind: str) -> tuple[object, ...]:
                self.events.append(f"connections:{kind}")
                return ()

            def terminate(self) -> None:
                self.events.append("terminate")

            def kill(self) -> None:
                self.events.append("kill")

            def wait(self, *, timeout: float) -> int:
                self.events.append(f"wait:{timeout}")
                return 0

        process = SyntheticProcess()

        class SyntheticPsutil:
            class NoSuchProcess(Exception):
                pass

            class ZombieProcess(Exception):
                pass

            class AccessDenied(Exception):
                pass

            class TimeoutExpired(Exception):
                pass

            @staticmethod
            def process_iter(*, attrs: tuple[str, ...]) -> tuple[object, ...]:
                self.assertIn("cmdline", attrs)
                return (process,)

            @staticmethod
            def Process(pid: int) -> SyntheticProcess:
                self.assertEqual(41_001, pid)
                return process

        backend = PsutilProcessCleanupBackend(
            local_context=LocalCleanupContext(_OWNER, 7),
            psutil_module=SyntheticPsutil,
            session_reader=lambda _pid: 7,
        )

        observed = backend.scan(2)

        self.assertEqual((41_001,), tuple(
            item.identity.pid for item in observed
        ))
        self.assertEqual(_FINGERPRINT, observed[0].command_fingerprint)
        self.assertEqual(observed[0].identity, backend.inspect(41_001))
        self.assertTrue(backend.request_graceful(observed[0].identity))
        self.assertTrue(backend.force(observed[0].identity))
        self.assertTrue(backend.wait(41_001, 1))
        self.assertEqual(
            ["connections:inet", "terminate", "kill", "wait:1"],
            process.events,
        )
        with self.assertRaises(ConflictError):
            backend.force(
                replace(
                    observed[0].identity,
                    create_time=observed[0].identity.create_time - 1,
                )
            )
        self.assertEqual(1, process.events.count("kill"))


class ScriptedSensor:
    def __init__(
        self,
        outcomes: list[
            MetricSnapshot
            | BaseException
            | Callable[[], MetricSnapshot]
        ],
    ) -> None:
        self.outcomes = outcomes
        self.calls: list[str] = []

    def sample(self, node_id: str) -> MetricSnapshot:
        self.calls.append(node_id)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if callable(outcome):
            return outcome()
        return outcome


def _metric(
    clock: FakeClock,
    *,
    node_id: str = "synthetic-node-01",
    cpu: float = 25.0,
) -> MetricSnapshot:
    return MetricSnapshot(
        node_id=node_id,
        observed_at_ns=clock.monotonic_ns(),
        cpu_percent=cpu,
        memory_percent=50.0,
    )


def _monitoring_policy(
    *,
    maximum: float = 8.0,
    multiplier: float = 2.0,
) -> MonitoringPolicy:
    return MonitoringPolicy(
        interval_seconds=1,
        stale_after_seconds=5,
        maximum_backoff_seconds=maximum,
        backoff_multiplier=multiplier,
    )


class MonitoringServiceTests(unittest.TestCase):
    def test_fresh_sample_is_reused_until_poll_is_due(self) -> None:
        clock = FakeClock(seed=10)
        sensor = ScriptedSensor([_metric(clock)])
        service = MonitoringService(
            clock=clock,
            sensor=sensor,
            policy=_monitoring_policy(),
        )

        first = service.poll("synthetic-node-01")
        clock.advance(0.5)
        second = service.poll("synthetic-node-01")

        self.assertEqual(MetricState.OK, first.snapshot.state)
        self.assertEqual(first.snapshot, second.snapshot)
        self.assertEqual(["synthetic-node-01"], sensor.calls)
        self.assertAlmostEqual(0.5, second.next_poll_seconds)

    def test_first_soft_miss_retains_fresh_last_good_until_stale(self) -> None:
        clock = FakeClock(seed=11)
        sensor = ScriptedSensor(
            [
                _metric(clock),
                UnavailableError("synthetic unavailable"),
            ]
        )
        service = MonitoringService(
            clock=clock,
            sensor=sensor,
            policy=_monitoring_policy(),
        )
        good = service.poll("synthetic-node-01")
        clock.advance(1)

        soft_miss = service.poll("synthetic-node-01")

        self.assertEqual(good.snapshot, soft_miss.snapshot)
        self.assertEqual(
            MetricState.UNAVAILABLE,
            soft_miss.last_attempt_state,
        )
        self.assertEqual(1, soft_miss.consecutive_failures)
        self.assertEqual(2, soft_miss.next_poll_seconds)

        clock.advance(5)
        stale = service.current("synthetic-node-01")
        self.assertEqual(MetricState.STALE, stale.snapshot.state)
        self.assertEqual(MetricState.UNAVAILABLE, stale.last_attempt_state)

    def test_transient_backoff_is_bounded_and_success_resets_it(self) -> None:
        clock = FakeClock(seed=12)
        sensor = ScriptedSensor(
            [
                UnavailableError(),
                UnavailableError(),
                lambda: _metric(clock, cpu=30),
            ]
        )
        service = MonitoringService(
            clock=clock,
            sensor=sensor,
            policy=_monitoring_policy(),
        )

        first = service.poll("synthetic-node-01")
        clock.advance(2)
        second = service.poll("synthetic-node-01")
        clock.advance(4)
        third = service.poll("synthetic-node-01")

        self.assertEqual(2, first.next_poll_seconds)
        self.assertEqual(4, second.next_poll_seconds)
        self.assertEqual(MetricState.OK, third.snapshot.state)
        self.assertEqual(0, third.consecutive_failures)
        self.assertEqual(1, third.next_poll_seconds)

    def test_huge_multiplier_saturates_without_numeric_overflow(self) -> None:
        clock = FakeClock(seed=13)
        sensor = ScriptedSensor([UnavailableError()])
        service = MonitoringService(
            clock=clock,
            sensor=sensor,
            policy=_monitoring_policy(
                maximum=60,
                multiplier=1e308,
            ),
        )

        observation = service.poll("synthetic-node-01")

        self.assertEqual(60, observation.next_poll_seconds)

    def test_unsupported_and_permission_states_surface_immediately(self) -> None:
        for error, expected in (
            (UnsupportedError(), MetricState.UNSUPPORTED),
            (PermissionDeniedError(), MetricState.PERMISSION_DENIED),
        ):
            with self.subTest(expected=expected):
                clock = FakeClock(seed=14)
                sensor = ScriptedSensor([_metric(clock), error])
                service = MonitoringService(
                    clock=clock,
                    sensor=sensor,
                    policy=_monitoring_policy(),
                )
                service.poll("synthetic-node-01")
                clock.advance(1)

                observation = service.poll("synthetic-node-01")

                self.assertEqual(expected, observation.snapshot.state)
                self.assertEqual(8, observation.next_poll_seconds)

    def test_sensor_node_mismatch_is_a_sanitized_contract_failure(self) -> None:
        clock = FakeClock(seed=15)
        sensor = ScriptedSensor(
            [_metric(clock, node_id="synthetic-other-node")]
        )
        service = MonitoringService(
            clock=clock,
            sensor=sensor,
            policy=_monitoring_policy(),
        )

        observation = service.poll("synthetic-node-01")

        self.assertEqual(MetricState.UNAVAILABLE, observation.snapshot.state)
        self.assertEqual(
            "sensor_contract_invalid",
            observation.snapshot.detail_code,
        )

    def test_lazy_psutil_sensor_maps_cpu_memory_and_temperature(self) -> None:
        class SyntheticPsutil:
            class AccessDenied(Exception):
                pass

            @staticmethod
            def cpu_percent(*, interval: None) -> float:
                return 20.0

            @staticmethod
            def virtual_memory() -> object:
                return type("Memory", (), {"percent": 40.0})()

            @staticmethod
            def sensors_temperatures() -> dict[str, list[object]]:
                return {
                    "synthetic": [
                        type("Temperature", (), {"current": 55.0})(),
                        type("Temperature", (), {"current": 65.0})(),
                    ]
                }

        clock = FakeClock(seed=16)
        sensor = PsutilSensor(
            clock=clock,
            psutil_module=SyntheticPsutil,
        )

        snapshot = sensor.sample("synthetic-node-01")

        self.assertEqual(20, snapshot.cpu_percent)
        self.assertEqual(40, snapshot.memory_percent)
        self.assertEqual(65, snapshot.temperature_celsius)

    def test_effectful_sensor_import_is_method_local(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src"
            / "rcm"
            / "adapters"
            / "sensors.py"
        ).read_text(encoding="utf-8")
        prefix = source.split("class PsutilSensor:", maxsplit=1)[0]
        self.assertNotIn("import psutil", prefix)


if __name__ == "__main__":
    unittest.main()
