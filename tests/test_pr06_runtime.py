from __future__ import annotations

import unittest
from threading import Event, Thread
import traceback

from rcm.runtime import (
    CancellationToken,
    RuntimeCoordinator,
    RuntimeShutdownError,
    RuntimeStartError,
    RuntimeState,
    RuntimeUnit,
)


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FakeComponent:
    def __init__(
        self,
        name: str,
        events: list[str],
        *,
        clock: FakeMonotonic | None = None,
    ) -> None:
        self.name = name
        self.events = events
        self.clock = clock
        self.fail_start = False
        self.fail_stop = False
        self.joined = True
        self.cancel_during_start = False
        self.stop_advance = 0.0
        self.start_count = 0
        self.stop_timeouts: list[float] = []
        self.join_timeouts: list[float] = []
        self.token: CancellationToken | None = None
        self.start_entered: Event | None = None
        self.start_gate: Event | None = None
        self.wait_for_cancel = False
        self.start_exception: BaseException | None = None

    def start(self, cancellation: CancellationToken) -> None:
        self.events.append(f"start:{self.name}")
        self.start_count += 1
        self.token = cancellation
        if self.start_entered is not None:
            self.start_entered.set()
        if self.start_gate is not None:
            if self.wait_for_cancel:
                while (
                    not cancellation.cancelled
                    and not self.start_gate.wait(0.01)
                ):
                    pass
            elif not self.start_gate.wait(2):
                raise RuntimeError("synthetic gate timeout")
        if self.cancel_during_start:
            cancellation.cancel()
        if self.start_exception is not None:
            raise self.start_exception
        if self.fail_start:
            raise RuntimeError("synthetic start failure")

    def stop(self, timeout_seconds: float) -> None:
        self.events.append(f"stop:{self.name}")
        self.stop_timeouts.append(timeout_seconds)
        if self.clock is not None:
            self.clock.advance(self.stop_advance)
        if self.fail_stop:
            raise RuntimeError("synthetic stop failure")

    def join(self, timeout_seconds: float) -> bool:
        self.events.append(f"join:{self.name}")
        self.join_timeouts.append(timeout_seconds)
        return self.joined


class RuntimeCoordinatorTests(unittest.TestCase):
    def build(
        self,
        *,
        clock: FakeMonotonic | None = None,
    ) -> tuple[
        RuntimeCoordinator,
        tuple[FakeComponent, ...],
        list[str],
    ]:
        events: list[str] = []
        components = tuple(
            FakeComponent(name, events, clock=clock)
            for name in (
                "watchdog",
                "guard",
                "monitor",
                "sensor",
                "server",
            )
        )
        coordinator = RuntimeCoordinator(
            tuple(
                RuntimeUnit(component.name, component)
                for component in components
            ),
            shutdown_timeout_seconds=5,
            monotonic=clock or FakeMonotonic(),
        )
        return coordinator, components, events

    def test_one_owner_starts_once_and_stops_in_reverse_order(self) -> None:
        coordinator, components, events = self.build()
        started = coordinator.start()
        self.assertEqual(RuntimeState.RUNNING, started.state)
        self.assertEqual(
            (
                "watchdog",
                "guard",
                "monitor",
                "sensor",
                "server",
            ),
            started.active,
        )
        repeated = coordinator.start()
        self.assertEqual(started, repeated)
        self.assertTrue(
            all(component.start_count == 1 for component in components)
        )

        stopped = coordinator.stop()
        self.assertEqual(RuntimeState.STOPPED, stopped.state)
        self.assertEqual((), stopped.active)
        self.assertEqual(
            [
                "stop:server",
                "stop:sensor",
                "stop:monitor",
                "stop:guard",
                "stop:watchdog",
            ],
            [
                event for event in events if event.startswith("stop:")
            ],
        )
        event_count = len(events)
        self.assertEqual(RuntimeState.STOPPED, coordinator.stop().state)
        self.assertEqual(event_count, len(events))

    def test_partial_start_failure_cancels_and_unwinds_started_units(
        self,
    ) -> None:
        coordinator, components, events = self.build()
        components[2].fail_start = True
        with self.assertRaises(RuntimeStartError):
            coordinator.start()
        snapshot = coordinator.snapshot()
        self.assertEqual(RuntimeState.FAILED, snapshot.state)
        self.assertTrue(snapshot.cancellation_requested)
        self.assertEqual((), snapshot.active)
        self.assertEqual(
            [
                "start:watchdog",
                "start:guard",
                "start:monitor",
                "stop:monitor",
                "stop:guard",
                "stop:watchdog",
                "join:monitor",
                "join:guard",
                "join:watchdog",
            ],
            events,
        )

    def test_cooperative_cancellation_during_start_unwinds(self) -> None:
        coordinator, components, events = self.build()
        components[0].cancel_during_start = True
        with self.assertRaises(RuntimeStartError):
            coordinator.start()
        self.assertEqual(
            [
                "start:watchdog",
                "stop:watchdog",
                "join:watchdog",
            ],
            events,
        )
        self.assertEqual(RuntimeState.FAILED, coordinator.snapshot().state)

    def test_cancellation_by_last_component_is_not_lost(self) -> None:
        coordinator, components, events = self.build()
        components[-1].cancel_during_start = True

        with self.assertRaises(RuntimeStartError):
            coordinator.start()

        self.assertEqual((), coordinator.snapshot().active)
        self.assertIn("stop:server", events)

    def test_shutdown_budget_is_shared_and_unresolved_unit_remains(
        self,
    ) -> None:
        clock = FakeMonotonic()
        coordinator, components, _events = self.build(clock=clock)
        coordinator.start()
        server = components[-1]
        server.stop_advance = 6
        server.joined = False
        with self.assertRaises(RuntimeShutdownError):
            coordinator.stop(timeout_seconds=5)
        snapshot = coordinator.snapshot()
        self.assertEqual(RuntimeState.FAILED, snapshot.state)
        self.assertEqual(("server",), snapshot.active)
        self.assertEqual(5, server.stop_timeouts[0])
        self.assertEqual(0, server.join_timeouts[0])

        server.joined = True
        recovered = coordinator.stop(timeout_seconds=1)
        self.assertEqual(RuntimeState.STOPPED, recovered.state)
        self.assertEqual((), recovered.active)

    def test_stop_failure_still_joins_every_owned_unit(self) -> None:
        coordinator, components, events = self.build()
        components[2].fail_stop = True
        coordinator.start()
        with self.assertRaises(RuntimeShutdownError):
            coordinator.stop()
        self.assertEqual(
            5,
            len(
                [
                    event
                    for event in events
                    if event.startswith("join:")
                ]
            ),
        )
        self.assertEqual((), coordinator.snapshot().active)

    def test_external_cancel_token_is_shared_by_all_components(self) -> None:
        coordinator, components, _events = self.build()
        coordinator.start()
        tokens = {id(component.token) for component in components}
        self.assertEqual(1, len(tokens))
        coordinator.cancel()
        self.assertTrue(
            all(
                component.token is not None
                and component.token.cancelled
                for component in components
            )
        )
        coordinator.stop()

    def test_concurrent_start_transitions_are_serialized(self) -> None:
        coordinator, components, _events = self.build()
        entered, release = Event(), Event()
        components[0].start_entered = entered
        components[0].start_gate = release
        failures: list[BaseException] = []

        def call(action) -> None:
            try:
                action()
            except BaseException as exc:
                failures.append(exc)

        starter = Thread(target=lambda: call(coordinator.start))
        second_starter = Thread(target=lambda: call(coordinator.start))
        starter.start()
        self.assertTrue(entered.wait(1))
        second_starter.start()
        self.assertTrue(second_starter.is_alive())
        release.set()
        starter.join(2)
        second_starter.join(2)
        self.assertFalse(starter.is_alive() or second_starter.is_alive())
        self.assertEqual([], failures)
        self.assertEqual(RuntimeState.RUNNING, coordinator.snapshot().state)
        coordinator.stop()

    def test_base_exception_unwinds_then_preserves_interrupt(self) -> None:
        coordinator, components, _events = self.build()
        components[1].start_exception = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            coordinator.start()
        self.assertEqual(RuntimeState.FAILED, coordinator.snapshot().state)
        self.assertEqual((), coordinator.snapshot().active)

    def test_start_failure_traceback_suppresses_private_cause(self) -> None:
        coordinator, components, _events = self.build()
        components[0].start_exception = RuntimeError("PRIVATE_CANARY_VALUE")
        try:
            coordinator.start()
        except RuntimeStartError as exc:
            rendered = "".join(traceback.format_exception(exc))
        else:
            self.fail("runtime start did not fail")
        self.assertNotIn("PRIVATE_CANARY_VALUE", rendered)

    def test_stop_cancels_a_start_before_waiting_for_transition(self) -> None:
        coordinator, components, _events = self.build()
        entered, cleanup_gate = Event(), Event()
        components[0].start_entered = entered
        components[0].start_gate = cleanup_gate
        components[0].wait_for_cancel = True
        failures: list[BaseException] = []
        starter = Thread(
            target=lambda: self._capture(coordinator.start, failures)
        )
        stopper = Thread(
            target=lambda: self._capture(coordinator.stop, failures)
        )
        starter.start()
        self.assertTrue(entered.wait(1))
        stopper.start()
        starter.join(1)
        stopper.join(1)
        completed = not starter.is_alive() and not stopper.is_alive()
        cleanup_gate.set()
        starter.join(1)
        stopper.join(1)
        self.assertTrue(completed)
        self.assertFalse(starter.is_alive() or stopper.is_alive())
        self.assertEqual(1, len(failures))
        self.assertIsInstance(failures[0], RuntimeStartError)
        self.assertEqual(RuntimeState.STOPPED, coordinator.snapshot().state)

    @staticmethod
    def _capture(action, failures: list[BaseException]) -> None:
        try:
            action()
        except BaseException as exc:
            failures.append(exc)


if __name__ == "__main__":
    unittest.main()
