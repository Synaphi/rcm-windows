from __future__ import annotations

import unittest
from threading import Barrier, Event, Thread

from rcm.cluster import BusyAssessment, MaintenanceGuard
from rcm.core import (
    ActionResult,
    ActionStatus,
    BusyState,
    Capability,
    CapabilityState,
    ConflictError,
    Node,
    NodeRole,
    StaleError,
)
from rcm.reconfiguration import (
    ClusterReconfigurator,
    ClusterTopology,
    MemoryReconfigurationJournal,
    ReconfigurationPhase,
    ReconfigurationPlan,
    ReconfigurationStatus,
)
from rcm.runtime import CancellationToken


class ControllerCrash(BaseException):
    pass


def maintenance_lease(request_id: str, epoch: int):
    return MaintenanceGuard().acquire(
        request_id=request_id,
        assessment=BusyAssessment(BusyState.IDLE, epoch, ()),
        expected_epoch=epoch,
    )


class FakeRayAdapter:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []
        self.failures: dict[tuple[str, str], str] = {}
        self.epoch_failures: dict[tuple[str, str, int], str] = {}
        self.crash_once: tuple[str, str] | None = None
        self.crash_once_epoch: tuple[str, str, int] | None = None
        self.cancel_after_start = False
        self.cancel_after_push_node: str | None = None
        self.block_on: tuple[str, str] | None = None
        self.block_entered = Event()
        self.block_release = Event()

    def _result(
        self,
        action: str,
        node_id: str,
        epoch: int,
    ) -> ActionResult:
        self.events.append((action, node_id, epoch))
        if self.block_on == (action, node_id):
            self.block_entered.set()
            if not self.block_release.wait(2):
                raise RuntimeError("synthetic block timeout")
        if self.crash_once == (action, node_id):
            self.crash_once = None
            raise ControllerCrash
        if self.crash_once_epoch == (action, node_id, epoch):
            self.crash_once_epoch = None
            raise ControllerCrash
        code = self.epoch_failures.get(
            (action, node_id, epoch),
            self.failures.get((action, node_id)),
        )
        if code is not None:
            return ActionResult(ActionStatus.FAILED, code)
        return ActionResult.success()

    def preflight(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        return self._result("preflight", node.node_id, epoch)

    def stop(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        return self._result("stop", node.node_id, epoch)

    def push_manifest(
        self,
        node: Node,
        manifest_digest: str,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        self.assert_digest(manifest_digest)
        result = self._result("push", node.node_id, epoch)
        if self.cancel_after_push_node == node.node_id and cancellation is not None:
            cancellation.cancel()
        return result

    def start_head(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        result = self._result("start", node.node_id, epoch)
        if self.cancel_after_start and cancellation is not None:
            cancellation.cancel()
        return result

    def join_worker(
        self,
        node: Node,
        head: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        if head.role is not NodeRole.HEAD:
            return ActionResult(ActionStatus.FAILED, "head.invalid")
        return self._result("join", node.node_id, epoch)

    def verify(
        self,
        nodes: tuple[Node, ...],
        head: Node,
        *,
        epoch: int,
        cancellation: object | None = None,
    ) -> ActionResult:
        if head not in nodes:
            return ActionResult(ActionStatus.FAILED, "head.missing")
        action = "verify_head" if len(nodes) == 1 else "verify"
        return self._result(action, head.node_id, epoch)

    def assert_digest(self, value: str) -> None:
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise AssertionError("manifest digest is not canonical SHA-256")


class ReconfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        old_head = Node("old-head", "192.0.2.10", NodeRole.HEAD)
        new_worker = Node(
            "new-head",
            "192.0.2.20",
            NodeRole.WORKER,
        )
        worker = Node("worker-2", "192.0.2.30", NodeRole.WORKER)
        self.expected = ClusterTopology(
            7,
            old_head,
            (new_worker, worker),
        )
        new_head = Node("new-head", "192.0.2.20", NodeRole.HEAD)
        old_worker = Node(
            "old-head",
            "192.0.2.10",
            NodeRole.WORKER,
        )
        self.desired = ClusterTopology(
            8,
            new_head,
            (old_worker, worker),
        )
        self.plan = ReconfigurationPlan(
            "operation-1",
            self.expected,
            self.desired,
        )
        self.lease = maintenance_lease("operation-1", 7)
        self.adapter = FakeRayAdapter()
        self.journal = MemoryReconfigurationJournal()
        self.service = ClusterReconfigurator(
            self.adapter,
            self.journal,
        )

    def test_full_flow_stops_old_head_first_and_is_idempotent(self) -> None:
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.SUCCEEDED, result.status)
        self.assertEqual(8, result.effective_epoch)
        self.assertEqual("new-head", result.effective_head_id)
        self.assertFalse(result.rollback_performed)
        stop_events = [
            event for event in self.adapter.events if event[0] == "stop"
        ]
        self.assertEqual(
            [
                ("stop", "old-head", 8),
                ("stop", "new-head", 8),
                ("stop", "worker-2", 8),
            ],
            stop_events,
        )
        self.assertEqual(
            ["old-head", "worker-2"],
            [
                node_id
                for action, node_id, _epoch in self.adapter.events
                if action == "join"
            ],
        )

        event_count = len(self.adapter.events)
        repeated = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertIs(result, repeated)
        self.assertEqual(event_count, len(self.adapter.events))

    def test_operation_id_reuse_with_another_plan_is_rejected(self) -> None:
        self.service.run(self.plan, maintenance_lease=self.lease)
        changed_head = Node(
            "new-head",
            "192.0.2.21",
            NodeRole.HEAD,
        )
        changed = ReconfigurationPlan(
            "operation-1",
            self.expected,
            ClusterTopology(
                8,
                changed_head,
                self.desired.workers,
            ),
        )
        self.assertNotEqual(
            self.plan.fingerprint, changed.fingerprint,
        )
        renamed_worker = Node(
            "renamed-worker", self.desired.workers[0].address, NodeRole.WORKER,
        )
        renamed = ClusterTopology(
            8, self.desired.head, (renamed_worker, self.desired.workers[1]),
        )
        self.assertNotEqual(
            self.desired.manifest_digest, renamed.manifest_digest,
        )
        capability_worker = Node(
            self.desired.workers[0].node_id,
            self.desired.workers[0].address,
            NodeRole.WORKER,
            capabilities=(
                Capability("remote_desktop", CapabilityState.AVAILABLE),
            ),
        )
        capability_changed = ClusterTopology(
            8,
            self.desired.head,
            (capability_worker, self.desired.workers[1]),
        )
        capability_plan = ReconfigurationPlan(
            "operation-1", self.expected, capability_changed,
        )
        self.assertNotEqual(
            self.desired.manifest_digest,
            capability_changed.manifest_digest,
        )
        self.assertNotEqual(self.plan.fingerprint, capability_plan.fingerprint)
        with self.assertRaises(ConflictError):
            self.service.run(
                capability_plan,
                maintenance_lease=self.lease,
            )

    def test_stale_lease_is_rejected_before_adapter_touch(self) -> None:
        with self.assertRaises(StaleError):
            self.service.run(
                self.plan,
                maintenance_lease=maintenance_lease("operation-1", 6),
            )
        self.assertEqual([], self.adapter.events)

    def test_critical_preflight_failure_has_no_disruptive_rollback(self) -> None:
        self.adapter.failures[("preflight", "new-head")] = (
            "preflight.unavailable"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.FAILED, result.status)
        self.assertFalse(result.rollback_performed)
        self.assertFalse(
            any(
                action in {"stop", "push", "start", "join"}
                for action, _node_id, _epoch in self.adapter.events
            )
        )

    def test_removed_worker_must_preflight_before_any_stop(self) -> None:
        removed = Node("removed-worker", "192.0.2.40", NodeRole.WORKER)
        plan = ReconfigurationPlan(
            "operation-removed-worker",
            ClusterTopology(
                self.expected.epoch,
                self.expected.head,
                (*self.expected.workers, removed),
            ),
            self.desired,
        )
        lease = maintenance_lease(
            "operation-removed-worker", self.expected.epoch,
        )
        self.adapter.failures[("preflight", "removed-worker")] = (
            "preflight.unavailable"
        )

        result = ClusterReconfigurator(
            self.adapter,
            MemoryReconfigurationJournal(),
        ).run(plan, maintenance_lease=lease)

        self.assertEqual(ReconfigurationStatus.FAILED, result.status)
        self.assertFalse(
            any(
                action in {"stop", "push", "start", "join"}
                for action, _node_id, _epoch in self.adapter.events
            )
        )

    def test_new_head_start_failure_rolls_back_at_next_epoch(self) -> None:
        self.adapter.failures[("start", "new-head")] = (
            "start.unavailable"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.FAILED, result.status)
        self.assertTrue(result.rollback_performed)
        self.assertTrue(result.effective_state_known)
        self.assertEqual(9, result.effective_epoch)
        self.assertEqual("old-head", result.effective_head_id)
        rollback_reports = [
            report
            for report in result.reports
            if report.phase is ReconfigurationPhase.ROLLBACK
        ]
        self.assertTrue(rollback_reports)
        self.assertIn(
            ("start", "old-head", 9),
            self.adapter.events,
        )
        rollback_stop = self.adapter.events.index(
            ("stop", "new-head", 9)
        )
        rollback_start = self.adapter.events.index(
            ("start", "old-head", 9)
        )
        self.assertLess(rollback_stop, rollback_start)
        self.assertFalse(
            ("start", "old-head", 8) in self.adapter.events
        )

    def test_rollback_never_starts_old_head_if_candidate_stop_fails(
        self,
    ) -> None:
        self.adapter.failures[("stop", "new-head")] = "stop.uncertain"
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.FAILED, result.status)
        self.assertTrue(result.rollback_performed)
        self.assertFalse(result.effective_state_known)
        self.assertNotIn(
            ("start", "old-head", 8),
            self.adapter.events,
        )

    def test_rollback_requires_new_epoch_manifest_on_old_head(self) -> None:
        self.adapter.failures[("push", "old-head")] = "push.rejected"
        self.adapter.failures[("start", "new-head")] = (
            "start.unavailable"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertTrue(result.rollback_performed)
        self.assertFalse(result.effective_state_known)
        self.assertIn(("push", "old-head", 9), self.adapter.events)
        self.assertNotIn(("start", "old-head", 9), self.adapter.events)

    def test_worker_join_failure_reports_partial_without_rollback(
        self,
    ) -> None:
        self.adapter.failures[("join", "worker-2")] = (
            "join.unavailable"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.PARTIAL, result.status)
        self.assertEqual(("worker-2",), result.missing_worker_ids)
        self.assertFalse(result.rollback_performed)
        self.assertEqual(8, result.effective_epoch)
        self.assertFalse(
            any(epoch == 9 for _action, _node_id, epoch in self.adapter.events)
        )

    def test_head_verify_failure_rolls_back_before_worker_join(self) -> None:
        self.adapter.failures[("verify_head", "new-head")] = (
            "verify.head_unhealthy"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.FAILED, result.status)
        self.assertTrue(result.rollback_performed)
        self.assertEqual(9, result.effective_epoch)
        first_join = next(
            (
                event
                for event in self.adapter.events
                if event[0] == "join"
            ),
            None,
        )
        self.assertIsNotNone(first_join)
        self.assertEqual(9, first_join[2])

    def test_cancel_after_start_rolls_back_until_head_is_verified(
        self,
    ) -> None:
        self.adapter.cancel_after_start = True
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.CANCELLED, result.status)
        self.assertTrue(result.rollback_performed)
        self.assertEqual(9, result.effective_epoch)

    def test_cancel_after_successful_push_restores_at_fresh_epoch(self) -> None:
        self.adapter.cancel_after_push_node = "new-head"
        result = self.service.run(
            self.plan, maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.CANCELLED, result.status)
        self.assertTrue(result.rollback_performed)
        self.assertEqual(9, result.effective_epoch)
        self.assertIn(("push", "old-head", 9), self.adapter.events)

    def test_verify_failure_does_not_create_split_brain_rollback(
        self,
    ) -> None:
        self.adapter.failures[("verify", "new-head")] = (
            "verify.incomplete"
        )
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.PARTIAL, result.status)
        self.assertFalse(result.rollback_performed)
        self.assertEqual(8, result.effective_epoch)

    def test_post_effect_crash_resumes_with_conservative_rollback(self) -> None:
        self.adapter.crash_once = ("push", "new-head")
        with self.assertRaises(ControllerCrash):
            self.service.run(
                self.plan,
                maintenance_lease=self.lease,
            )
        stop_count = len(
            [
                event
                for event in self.adapter.events
                if event[0] == "stop" and event[2] == 8
            ]
        )
        resumed = ClusterReconfigurator(
            self.adapter,
            self.journal,
        ).run(
            self.plan,
            maintenance_lease=self.lease,
        )
        self.assertEqual(ReconfigurationStatus.FAILED, resumed.status)
        self.assertTrue(resumed.rollback_performed)
        self.assertEqual(9, resumed.effective_epoch)
        self.assertEqual(
            stop_count,
            len(
                [
                    event
                    for event in self.adapter.events
                    if event[0] == "stop" and event[2] == 8
                ]
            ),
        )

    def test_unfinished_crash_blocks_other_operation_until_recovered(self) -> None:
        self.adapter.crash_once = ("push", "new-head")
        with self.assertRaises(ControllerCrash):
            self.service.run(self.plan, maintenance_lease=self.lease)

        blocked_adapter = FakeRayAdapter()
        blocked_plan = ReconfigurationPlan(
            "operation-blocked", self.desired, self.desired.with_epoch(9),
        )
        with self.assertRaises(ConflictError):
            ClusterReconfigurator(
                blocked_adapter, self.journal,
            ).run(
                blocked_plan,
                maintenance_lease=maintenance_lease("operation-blocked", 8),
            )
        self.assertEqual([], blocked_adapter.events)

        recovered = self.service.run(
            self.plan, maintenance_lease=self.lease,
        )
        self.assertEqual(9, recovered.effective_epoch)
        expected = self.expected.with_epoch(9)
        next_plan = ReconfigurationPlan(
            "operation-next", expected, expected.with_epoch(10),
        )
        next_result = ClusterReconfigurator(
            blocked_adapter, self.journal,
        ).run(
            next_plan,
            maintenance_lease=maintenance_lease("operation-next", 9),
        )
        self.assertEqual(ReconfigurationStatus.SUCCEEDED, next_result.status)

    def test_released_lease_is_rejected_before_adapter_touch(self) -> None:
        guard = MaintenanceGuard()
        lease = guard.acquire(
            request_id="operation-1",
            assessment=BusyAssessment(BusyState.IDLE, 7, ()),
            expected_epoch=7,
        )
        guard.release(lease)
        with self.assertRaises(ConflictError):
            self.service.run(self.plan, maintenance_lease=lease)
        self.assertEqual([], self.adapter.events)

    def test_new_operation_cannot_reuse_stale_authoritative_epoch(self) -> None:
        self.service.run(self.plan, maintenance_lease=self.lease)
        stale = ReconfigurationPlan(
            "operation-stale", self.expected, self.desired,
        )
        with self.assertRaises(StaleError):
            self.service.run(
                stale,
                maintenance_lease=maintenance_lease(
                    "operation-stale", self.expected.epoch,
                ),
            )

    def test_journal_claim_serializes_different_operations(self) -> None:
        journal = MemoryReconfigurationJournal()
        barrier = Barrier(3)
        outcomes: list[tuple[str, bool]] = []

        def claim(operation_id: str) -> None:
            barrier.wait()
            acquired = journal.claim(operation_id, 7)
            outcomes.append((operation_id, acquired))
            barrier.wait()
            if acquired:
                journal.release(operation_id)

        threads = [
            Thread(target=claim, args=(f"operation-{index}",))
            for index in (1, 2)
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        barrier.wait()
        for thread in threads:
            thread.join(1)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([False, True], sorted(
            acquired for _operation, acquired in outcomes
        ))

    def test_one_lease_cannot_run_through_two_journals(self) -> None:
        self.adapter.block_on = ("preflight", "old-head")
        results = []
        worker = Thread(target=lambda: results.append(
            self.service.run(self.plan, maintenance_lease=self.lease)
        ))
        worker.start()
        self.assertTrue(self.adapter.block_entered.wait(1))
        other = ClusterReconfigurator(
            FakeRayAdapter(), MemoryReconfigurationJournal(),
        )
        with self.assertRaises(ConflictError):
            other.run(self.plan, maintenance_lease=self.lease)
        self.adapter.block_release.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(ReconfigurationStatus.SUCCEEDED, results[0].status)

    def test_rollback_worker_failure_is_missing_and_unknown(self) -> None:
        self.adapter.failures[("start", "new-head")] = "start.unavailable"
        self.adapter.failures[("join", "worker-2")] = "join.unavailable"
        result = self.service.run(self.plan, maintenance_lease=self.lease)
        self.assertIn("worker-2", result.missing_worker_ids)
        self.assertFalse(result.effective_state_known)

    def test_rollback_requires_exact_restored_membership_verification(self) -> None:
        self.adapter.failures[("start", "new-head")] = "start.unavailable"
        self.adapter.failures[("verify", "old-head")] = "verify.incomplete"
        result = self.service.run(self.plan, maintenance_lease=self.lease)
        self.assertEqual(
            set(self.expected.worker_ids), set(result.missing_worker_ids),
        )
        self.assertFalse(result.effective_state_known)

    def test_rollback_manifest_failure_never_joins_that_worker(self) -> None:
        self.adapter.failures[("start", "new-head")] = "start.unavailable"
        self.adapter.epoch_failures[("push", "worker-2", 9)] = "push.rejected"
        result = self.service.run(self.plan, maintenance_lease=self.lease)
        self.assertNotIn(("join", "worker-2", 9), self.adapter.events)
        self.assertIn("worker-2", result.missing_worker_ids)
        self.assertFalse(result.effective_state_known)

    def test_rollback_push_crash_resume_never_joins_unknown_worker(self) -> None:
        self.adapter.failures[("start", "new-head")] = "start.unavailable"
        self.adapter.crash_once_epoch = ("push", "worker-2", 9)
        with self.assertRaises(ControllerCrash):
            self.service.run(self.plan, maintenance_lease=self.lease)
        result = self.service.run(self.plan, maintenance_lease=self.lease)
        self.assertNotIn(("join", "worker-2", 9), self.adapter.events)
        self.assertIn("worker-2", result.missing_worker_ids)
        self.assertFalse(result.effective_state_known)

    def test_pre_cancelled_operation_has_no_mutation_or_rollback(
        self,
    ) -> None:
        token = CancellationToken()
        token.cancel()
        result = self.service.run(
            self.plan,
            maintenance_lease=self.lease,
            cancellation=token,
        )
        self.assertEqual(ReconfigurationStatus.CANCELLED, result.status)
        self.assertFalse(result.rollback_performed)
        self.assertEqual([], self.adapter.events)


if __name__ == "__main__":
    unittest.main()
