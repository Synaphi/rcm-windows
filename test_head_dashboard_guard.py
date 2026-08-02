from __future__ import annotations

import unittest

from ray_monitor import (
    ActionResult,
    HeadDashboardGuard,
    WorkerWatchdog,
)


def guard_config():
    return {
        "head_ip": "192.0.2.20",
        "head_port": 6379,
        "dashboard_port": 8265,
        "this": {
            "role": "head",
            "mode": "ray",
            "ip": "192.0.2.20",
            "num_cpus": 4,
        },
        "head_dashboard_guard_interval_sec": 20,
        "head_dashboard_guard_cycles": 3,
    }


class FakeHeadController:
    def __init__(self, start_ok=True):
        self.repairing = False
        self.auto_paused = False
        self.reset_calls = 0
        self.start_calls = 0
        self.start_ok = start_ok

    def _shutdown_requested(self):
        return False

    def reset(self):
        self.reset_calls += 1
        return ActionResult(True, "reset")

    def start_head(self):
        self.start_calls += 1
        return ActionResult(self.start_ok, "started" if self.start_ok else "failed")


class HeadDashboardGuardTests(unittest.TestCase):
    def make_guard(self, controller, gcs=True, dashboard=False, cycles=3):
        ports = {6379: gcs, 8265: dashboard}
        return HeadDashboardGuard(
            controller, guard_config(), lambda _message: None,
            interval=20, cycles=cycles,
            tcp_probe=lambda _ip, port, timeout=1.0: ports[port])

    def test_recovers_after_required_consecutive_cycles(self):
        controller = FakeHeadController()
        guard = self.make_guard(controller, cycles=3)

        guard.check_once()
        guard.check_once()
        self.assertEqual(controller.start_calls, 0)
        guard.check_once()

        self.assertEqual(controller.reset_calls, 1)
        self.assertEqual(controller.start_calls, 1)

    def test_repairing_or_auto_paused_skips_recovery(self):
        for attribute in ("repairing", "auto_paused"):
            with self.subTest(attribute=attribute):
                controller = FakeHeadController()
                setattr(controller, attribute, True)
                guard = self.make_guard(controller, cycles=1)
                guard.check_once()
                self.assertEqual(controller.start_calls, 0)

    def test_gcs_offline_is_not_a_guard_target(self):
        controller = FakeHeadController()
        guard = self.make_guard(controller, gcs=False, cycles=1)
        guard.check_once()
        self.assertEqual(controller.start_calls, 0)

    def test_failed_recovery_increases_backoff(self):
        controller = FakeHeadController(start_ok=False)
        guard = self.make_guard(controller, cycles=1)
        self.assertEqual(guard._current_interval(), 20)
        guard.check_once()
        self.assertEqual(guard._current_interval(), 40)
        guard.check_once()
        self.assertEqual(guard._current_interval(), 80)


class FakeWorkerController:
    auto_paused = False
    repairing = False

    def __init__(self):
        self.start_calls = 0

    def worker_running(self):
        return False

    def start_worker(self):
        self.start_calls += 1
        return ActionResult(True, "connecting")


class WorkerWatchdogFallbackTests(unittest.TestCase):
    def test_dead_worker_rejoins_even_when_dashboard_check_is_unavailable(self):
        controller = FakeWorkerController()
        cfg = {
            "head_ip": "192.0.2.20",
            "head_port": 6379,
            "dashboard_port": 8265,
            "this": {
                "role": "worker",
                "ip": "192.0.2.21",
                "num_cpus": 4,
            },
        }
        watchdog = WorkerWatchdog(
            controller, cfg, lambda _message: None, interval=60)

        watchdog.check_once()

        self.assertEqual(controller.start_calls, 1)


if __name__ == "__main__":
    unittest.main()
