from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import hashlib
import json
import re
from threading import RLock
from typing import Protocol

from .cluster import MaintenanceLease
from .core import ActionResult, ActionStatus, ConflictError, Node, NodeRole, StaleError
from .ports import RayAdapter
from .runtime import CancellationToken


_SAFE_CODE = re.compile(r"[a-z0-9_.:-]+\Z")


def _manifest_node(node: Node) -> dict[str, object]:
    return {
        "node_id": node.node_id, "address": node.address,
        "role": node.role.value, "enabled": node.enabled,
        "capabilities": [
            (item.name, item.state.value, item.detail_code)
            for item in node.capabilities
        ],
    }


def _token(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value or _SAFE_CODE.fullmatch(value) is None:
        raise ValueError(f"{field} must be a safe lowercase token")
    return value


def _epoch(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


class ReconfigurationPhase(StrEnum):
    PREFLIGHT = "preflight"
    STOP = "stop"
    PUSH = "push"
    START = "start"
    JOIN = "join"
    VERIFY = "verify"
    ROLLBACK = "rollback"


class ReconfigurationStatus(StrEnum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True, repr=False)
class ClusterTopology:
    epoch: int
    head: Node
    workers: tuple[Node, ...]

    def __post_init__(self) -> None:
        _epoch(self.epoch, field="epoch")
        if not isinstance(self.head, Node):
            raise ValueError("head must be a Node")
        if self.head.role is not NodeRole.HEAD:
            raise ValueError("head node must use the head role")
        if not isinstance(self.workers, tuple):
            raise ValueError("workers must be a tuple")
        if any(not isinstance(worker, Node) for worker in self.workers):
            raise ValueError("workers must contain Node values")
        if any(worker.role is not NodeRole.WORKER for worker in self.workers):
            raise ValueError("worker nodes must use the worker role")
        worker_ids = tuple(worker.node_id for worker in self.workers)
        if self.head.node_id in worker_ids:
            raise ValueError("head cannot also be a worker")
        if len(set(worker_ids)) != len(worker_ids):
            raise ValueError("worker identifiers must be unique")

    @property
    def node_ids(self) -> tuple[str, ...]:
        return (self.head.node_id, *self.worker_ids)

    def with_epoch(self, epoch: int) -> ClusterTopology:
        return replace(self, epoch=epoch)

    @property
    def head_id(self) -> str:
        return self.head.node_id

    @property
    def worker_ids(self) -> tuple[str, ...]:
        return tuple(worker.node_id for worker in self.workers)

    @property
    def nodes(self) -> tuple[Node, ...]:
        return (self.head, *self.workers)

    def node(self, node_id: str) -> Node:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise LookupError("unknown topology node")

    @property
    def manifest_digest(self) -> str:
        payload = {
            "epoch": self.epoch,
            "head": _manifest_node(self.head),
            "workers": [_manifest_node(worker) for worker in self.workers],
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class ReconfigurationPlan:
    operation_id: str
    expected: ClusterTopology
    desired: ClusterTopology

    def __post_init__(self) -> None:
        _token(self.operation_id, field="operation_id")
        if not isinstance(self.expected, ClusterTopology):
            raise ValueError("expected must be a ClusterTopology")
        if not isinstance(self.desired, ClusterTopology):
            raise ValueError("desired must be a ClusterTopology")
        if self.desired.epoch != self.expected.epoch + 1:
            raise ValueError("desired epoch must be expected epoch plus one")

    @property
    def fingerprint(self) -> str:
        payload = {
            "expected": {"epoch": self.expected.epoch,
                         "manifest": self.expected.manifest_digest},
            "desired": {"epoch": self.desired.epoch,
                        "manifest": self.desired.manifest_digest},
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class StepOutcome:
    ok: bool
    code: str = "ok"

    def __post_init__(self) -> None:
        if not isinstance(self.ok, bool):
            raise ValueError("ok must be a bool")
        _token(self.code, field="code")
        if self.ok and self.code != "ok":
            raise ValueError("successful outcomes must use the ok code")
        if not self.ok and self.code == "ok":
            raise ValueError("failed outcomes require a failure code")

    @classmethod
    def success(cls) -> StepOutcome:
        return cls(True)

    @classmethod
    def failure(cls, code: str) -> StepOutcome:
        return cls(False, code)


@dataclass(frozen=True, slots=True, repr=False)
class PhaseReport:
    phase: ReconfigurationPhase
    node_id: str
    outcome: StepOutcome


@dataclass(frozen=True, slots=True, repr=False)
class ReconfigurationResult:
    operation_id: str
    status: ReconfigurationStatus
    effective_epoch: int
    effective_head_id: str
    reports: tuple[PhaseReport, ...]
    missing_worker_ids: tuple[str, ...] = ()
    rollback_performed: bool = False
    effective_state_known: bool = True


@dataclass(frozen=True, slots=True, repr=False)
class ReconfigurationCheckpoint:
    plan_fingerprint: str
    completed_steps: frozenset[str] = frozenset()
    reports: tuple[PhaseReport, ...] = ()
    unavailable_nodes: frozenset[str] = frozenset()
    new_head_healthy: bool = False
    inflight_step: str | None = None
    rollback_status: ReconfigurationStatus | None = None
    result: ReconfigurationResult | None = None


class ReconfigurationJournal(Protocol):
    def claim(self, operation_id: str, expected_epoch: int) -> bool: ...

    def release(self, operation_id: str) -> None: ...

    def advance_epoch(self, epoch: int) -> None: ...

    def load(self, operation_id: str) -> ReconfigurationCheckpoint | None: ...

    def save(self, operation_id: str, checkpoint: ReconfigurationCheckpoint) -> None: ...


class MemoryReconfigurationJournal:
    def __init__(self) -> None:
        self._records: dict[str, ReconfigurationCheckpoint] = {}
        self._active_operation: str | None = None
        self._unfinished_operation: str | None = None
        self._epoch: int | None = None
        self._lock = RLock()

    def claim(self, operation_id: str, expected_epoch: int) -> bool:
        _token(operation_id, field="operation_id")
        _epoch(expected_epoch, field="expected_epoch")
        with self._lock:
            if self._active_operation is not None:
                return False
            if (
                self._unfinished_operation is not None
                and self._unfinished_operation != operation_id
            ):
                return False
            existing = self._records.get(operation_id)
            if self._epoch is None:
                self._epoch = expected_epoch
            elif self._epoch != expected_epoch and operation_id not in self._records:
                raise StaleError("journal epoch does not match plan")
            if existing is None or existing.result is None:
                self._unfinished_operation = operation_id
            self._active_operation = operation_id
            return True

    def release(self, operation_id: str) -> None:
        _token(operation_id, field="operation_id")
        with self._lock:
            if self._active_operation != operation_id:
                raise ConflictError("reconfiguration claim does not match owner")
            self._active_operation = None

    def advance_epoch(self, epoch: int) -> None:
        value = _epoch(epoch, field="epoch")
        with self._lock:
            if self._active_operation is None:
                raise ConflictError("reconfiguration epoch advance is unclaimed")
            if self._epoch is not None and value < self._epoch:
                raise StaleError("reconfiguration epoch cannot move backward")
            self._epoch = value

    def load(self, operation_id: str) -> ReconfigurationCheckpoint | None:
        _token(operation_id, field="operation_id")
        with self._lock:
            return self._records.get(operation_id)

    def save(self, operation_id: str, checkpoint: ReconfigurationCheckpoint) -> None:
        _token(operation_id, field="operation_id")
        if not isinstance(checkpoint, ReconfigurationCheckpoint):
            raise TypeError("checkpoint must be a ReconfigurationCheckpoint")
        with self._lock:
            existing = self._records.get(operation_id)
            if existing and existing.plan_fingerprint != checkpoint.plan_fingerprint:
                raise ConflictError("operation identifier was reused for another plan")
            self._records[operation_id] = checkpoint
            if checkpoint.result is not None and self._unfinished_operation == operation_id:
                self._unfinished_operation = None


class _Cancelled(Exception):
    def __init__(self, checkpoint: ReconfigurationCheckpoint | None = None) -> None:
        self.checkpoint = checkpoint


class ClusterReconfigurator:
    def __init__(self, control: RayAdapter, journal: ReconfigurationJournal) -> None:
        self._control = control
        self._journal = journal

    def run(
        self,
        plan: ReconfigurationPlan,
        *,
        maintenance_lease: MaintenanceLease,
        cancellation: CancellationToken | None = None,
    ) -> ReconfigurationResult:
        if not isinstance(plan, ReconfigurationPlan):
            raise TypeError("plan must be a ReconfigurationPlan")
        if not isinstance(maintenance_lease, MaintenanceLease):
            raise TypeError("maintenance_lease must be a MaintenanceLease")
        if not maintenance_lease.active:
            raise ConflictError("maintenance lease is not active")
        if maintenance_lease.request_id != plan.operation_id:
            raise ConflictError("maintenance lease belongs to another operation")
        if maintenance_lease.epoch != plan.expected.epoch:
            raise StaleError("maintenance lease has a stale epoch")
        if not maintenance_lease._claim():
            raise ConflictError("maintenance lease is already in use")
        try:
            if not self._journal.claim(plan.operation_id, plan.expected.epoch):
                raise ConflictError("another reconfiguration is in progress")
            try:
                return self._execute(plan, cancellation)
            finally:
                self._journal.release(plan.operation_id)
        finally:
            maintenance_lease._release_claim()

    def _execute(self, plan: ReconfigurationPlan,
                 cancellation: CancellationToken | None) -> ReconfigurationResult:
        token = cancellation or CancellationToken()

        checkpoint = self._journal.load(plan.operation_id)
        if checkpoint is None:
            checkpoint = ReconfigurationCheckpoint(plan.fingerprint)
            self._journal.save(plan.operation_id, checkpoint)
        elif checkpoint.plan_fingerprint != plan.fingerprint:
            raise ConflictError("operation identifier was reused for another plan")
        if checkpoint.result is not None:
            return checkpoint.result
        if checkpoint.rollback_status is not None:
            checkpoint, result = self._rollback(
                plan, checkpoint, status=checkpoint.rollback_status)
            checkpoint = replace(checkpoint, result=result)
            self._journal.save(plan.operation_id, checkpoint)
            return result

        try:
            checkpoint = self._preflight(plan, checkpoint, token)
            checkpoint = self._stop(plan, checkpoint, token)
            checkpoint = self._push(plan, checkpoint, token)
            checkpoint = self._start(plan, checkpoint, token)
            checkpoint = self._verify_head(plan, checkpoint, token)
            checkpoint, missing = self._join(plan, checkpoint, token)
            checkpoint, verified_missing, verification_ok = self._verify(
                plan, checkpoint, token)
            missing = tuple(sorted(set(missing) | set(verified_missing)))
            status = (
                ReconfigurationStatus.SUCCEEDED
                if verification_ok and not missing
                else ReconfigurationStatus.PARTIAL
            )
            result = ReconfigurationResult(
                plan.operation_id, status, plan.desired.epoch,
                plan.desired.head_id, checkpoint.reports, missing)
        except _Cancelled as exc:
            checkpoint = exc.checkpoint or checkpoint
            checkpoint, result = self._recover(
                plan, checkpoint, ReconfigurationStatus.CANCELLED,
                ReconfigurationStatus.CANCELLED,
            )
        except _PhaseFailed as exc:
            checkpoint = exc.checkpoint
            checkpoint, result = self._recover(
                plan, checkpoint, ReconfigurationStatus.FAILED,
                ReconfigurationStatus.PARTIAL,
            )

        checkpoint = replace(checkpoint, result=result)
        self._journal.save(plan.operation_id, checkpoint)
        return result

    def _recover(self, plan: ReconfigurationPlan,
                 checkpoint: ReconfigurationCheckpoint,
                 status: ReconfigurationStatus,
                 stable_status: ReconfigurationStatus,
                 ) -> tuple[ReconfigurationCheckpoint, ReconfigurationResult]:
        if checkpoint.new_head_healthy:
            result = self._terminal_result(
                plan, checkpoint, stable_status, plan.desired)
            return checkpoint, result
        if not self._needs_rollback(checkpoint):
            result = self._terminal_result(
                plan, checkpoint, status, plan.expected)
            return checkpoint, result
        return self._rollback(plan, checkpoint, status=status)

    def _terminal_result(self, plan: ReconfigurationPlan,
                         checkpoint: ReconfigurationCheckpoint,
                         status: ReconfigurationStatus,
                         topology: ClusterTopology) -> ReconfigurationResult:
        return ReconfigurationResult(
            plan.operation_id, status, topology.epoch, topology.head_id,
            checkpoint.reports, tuple(sorted(checkpoint.unavailable_nodes)),
        )

    def _needs_rollback(self, checkpoint: ReconfigurationCheckpoint) -> bool:
        mutation_phases = {
            ReconfigurationPhase.STOP, ReconfigurationPhase.PUSH,
            ReconfigurationPhase.START,
        }
        return any(report.phase in mutation_phases for report in checkpoint.reports)

    def _check_cancelled(self, token: CancellationToken,
                         checkpoint: ReconfigurationCheckpoint) -> None:
        if token.cancelled:
            raise _Cancelled(checkpoint)

    def _call(
        self, plan: ReconfigurationPlan,
        checkpoint: ReconfigurationCheckpoint,
        phase: ReconfigurationPhase,
        node_id: str, action: object, token: CancellationToken,
        *,
        step_key_suffix: str | None = None,
    ) -> tuple[ReconfigurationCheckpoint, StepOutcome]:
        self._check_cancelled(token, checkpoint)
        suffix = node_id if step_key_suffix is None else step_key_suffix
        step_key = f"{phase.value}:{suffix}"
        if step_key in checkpoint.completed_steps:
            return checkpoint, StepOutcome.success()
        if checkpoint.inflight_step is not None:
            outcome = StepOutcome.failure("step.outcome_unknown")
            checkpoint = replace(
                checkpoint, inflight_step=None,
                reports=(*checkpoint.reports, PhaseReport(phase, node_id, outcome)))
            self._journal.save(plan.operation_id, checkpoint)
            return checkpoint, outcome
        if not callable(action):
            raise TypeError("cluster control action must be callable")
        if phase in {ReconfigurationPhase.STOP, ReconfigurationPhase.PUSH,
                     ReconfigurationPhase.START}:
            self._journal.advance_epoch(plan.desired.epoch)
        checkpoint = replace(checkpoint, inflight_step=step_key)
        self._journal.save(plan.operation_id, checkpoint)
        cancelled = False
        try:
            raw_outcome = action()
        except Exception:
            if token.cancelled:
                outcome = StepOutcome.failure("cancelled")
                cancelled = True
            else:
                outcome = StepOutcome.failure("adapter.exception")
        else:
            outcome = self._step_outcome(raw_outcome)
            cancelled = (isinstance(raw_outcome, ActionResult)
                         and raw_outcome.status is ActionStatus.CANCELLED)
        if token.cancelled:
            outcome, cancelled = StepOutcome.failure("cancelled"), True
        if not isinstance(outcome, StepOutcome):
            outcome = StepOutcome.failure("adapter.invalid_result")
        report = PhaseReport(phase, node_id, outcome)
        completed = checkpoint.completed_steps
        if outcome.ok:
            completed = completed | {step_key}
        checkpoint = replace(
            checkpoint, completed_steps=completed,
            reports=(*checkpoint.reports, report), inflight_step=None)
        self._journal.save(plan.operation_id, checkpoint)
        if cancelled:
            raise _Cancelled(checkpoint)
        return checkpoint, outcome

    def _step_outcome(self, result: object) -> StepOutcome:
        if not isinstance(result, ActionResult):
            return StepOutcome.failure("adapter.invalid_result")
        try:
            return StepOutcome.success() if result.ok else StepOutcome.failure(result.code)
        except ValueError:
            return StepOutcome.failure("adapter.invalid_code")

    def _safe_action(self, action: object) -> StepOutcome:
        if not callable(action):
            return StepOutcome.failure("adapter.invalid_action")
        try:
            return self._step_outcome(action())
        except Exception:
            return StepOutcome.failure("adapter.exception")

    def _node(self, plan: ReconfigurationPlan, node_id: str) -> Node:
        for topology in (plan.desired, plan.expected):
            try:
                return topology.node(node_id)
            except LookupError:
                continue
        raise LookupError("unknown reconfiguration node")

    def _preflight(self, plan: ReconfigurationPlan,
                   checkpoint: ReconfigurationCheckpoint,
                   token: CancellationToken) -> ReconfigurationCheckpoint:
        nodes = tuple(dict.fromkeys((
            *plan.expected.node_ids, *plan.desired.node_ids,
        )))
        critical = {*plan.expected.node_ids, plan.desired.head_id}
        unavailable = set(checkpoint.unavailable_nodes)
        for node_id in nodes:
            checkpoint, outcome = self._call(
                plan, checkpoint, ReconfigurationPhase.PREFLIGHT, node_id,
                lambda node_id=node_id: self._control.preflight(
                    self._node(plan, node_id), epoch=plan.desired.epoch,
                    cancellation=token),
                token,
            )
            if not outcome.ok:
                unavailable.add(node_id)
                checkpoint = replace(
                    checkpoint, unavailable_nodes=frozenset(unavailable))
                self._journal.save(plan.operation_id, checkpoint)
                if node_id in critical:
                    raise _PhaseFailed(checkpoint)
            elif node_id in unavailable:
                unavailable.remove(node_id)
                checkpoint = replace(
                    checkpoint, unavailable_nodes=frozenset(unavailable))
                self._journal.save(plan.operation_id, checkpoint)
        return checkpoint

    def _stop(self, plan: ReconfigurationPlan,
              checkpoint: ReconfigurationCheckpoint,
              token: CancellationToken) -> ReconfigurationCheckpoint:
        for node_id in plan.expected.node_ids:
            if node_id in checkpoint.unavailable_nodes:
                continue
            checkpoint, outcome = self._call(
                plan, checkpoint, ReconfigurationPhase.STOP, node_id,
                lambda node_id=node_id: self._control.stop(
                    plan.expected.node(node_id), epoch=plan.desired.epoch,
                    cancellation=token),
                token,
            )
            if not outcome.ok:
                raise _PhaseFailed(checkpoint)
        return checkpoint

    def _push(self, plan: ReconfigurationPlan,
              checkpoint: ReconfigurationCheckpoint,
              token: CancellationToken) -> ReconfigurationCheckpoint:
        for node_id in plan.desired.node_ids:
            if node_id in checkpoint.unavailable_nodes:
                continue
            checkpoint, outcome = self._call(
                plan, checkpoint, ReconfigurationPhase.PUSH, node_id,
                lambda node_id=node_id: self._control.push_manifest(
                    plan.desired.node(node_id),
                    plan.desired.manifest_digest, epoch=plan.desired.epoch,
                    cancellation=token),
                token,
            )
            if not outcome.ok:
                if node_id == plan.desired.head_id:
                    raise _PhaseFailed(checkpoint)
                checkpoint = replace(
                    checkpoint,
                    unavailable_nodes=checkpoint.unavailable_nodes | {node_id})
        return checkpoint

    def _start(self, plan: ReconfigurationPlan,
               checkpoint: ReconfigurationCheckpoint,
               token: CancellationToken) -> ReconfigurationCheckpoint:
        node_id = plan.desired.head_id
        checkpoint, outcome = self._call(
            plan, checkpoint, ReconfigurationPhase.START, node_id,
            lambda: self._control.start_head(
                plan.desired.head, epoch=plan.desired.epoch,
                cancellation=token),
            token,
        )
        if not outcome.ok:
            raise _PhaseFailed(checkpoint)
        return checkpoint

    def _verify_head(self, plan: ReconfigurationPlan,
                     checkpoint: ReconfigurationCheckpoint,
                     token: CancellationToken) -> ReconfigurationCheckpoint:
        checkpoint, outcome = self._call(
            plan, checkpoint, ReconfigurationPhase.VERIFY,
            plan.desired.head_id,
            lambda: self._control.verify(
                (plan.desired.head,), plan.desired.head,
                epoch=plan.desired.epoch, cancellation=token),
            token, step_key_suffix="head",
        )
        if not outcome.ok:
            raise _PhaseFailed(checkpoint)
        checkpoint = replace(checkpoint, new_head_healthy=True)
        self._journal.save(plan.operation_id, checkpoint)
        return checkpoint

    def _join(self, plan: ReconfigurationPlan,
              checkpoint: ReconfigurationCheckpoint,
              token: CancellationToken,
              ) -> tuple[ReconfigurationCheckpoint, tuple[str, ...]]:
        missing: list[str] = []
        for node_id in plan.desired.worker_ids:
            if node_id in checkpoint.unavailable_nodes:
                missing.append(node_id)
                continue
            checkpoint, outcome = self._call(
                plan, checkpoint, ReconfigurationPhase.JOIN, node_id,
                lambda node_id=node_id: self._control.join_worker(
                    plan.desired.node(node_id), plan.desired.head,
                    epoch=plan.desired.epoch, cancellation=token),
                token,
            )
            if not outcome.ok:
                missing.append(node_id)
        return checkpoint, tuple(missing)

    def _verify(self, plan: ReconfigurationPlan,
                checkpoint: ReconfigurationCheckpoint,
                token: CancellationToken,
                ) -> tuple[ReconfigurationCheckpoint, tuple[str, ...], bool]:
        checkpoint, outcome = self._call(
            plan, checkpoint, ReconfigurationPhase.VERIFY, "cluster",
            lambda: self._control.verify(
                plan.desired.nodes, plan.desired.head,
                epoch=plan.desired.epoch, cancellation=token),
            token, step_key_suffix="cluster",
        )
        unavailable = set(checkpoint.unavailable_nodes)
        missing = tuple(node_id for node_id in plan.desired.worker_ids
                        if node_id in unavailable)
        if not outcome.ok:
            missing = plan.desired.worker_ids
        return checkpoint, missing, outcome.ok

    def _rollback(self, plan: ReconfigurationPlan,
                  checkpoint: ReconfigurationCheckpoint, *,
                  status: ReconfigurationStatus,
                  ) -> tuple[ReconfigurationCheckpoint, ReconfigurationResult]:
        target = plan.expected.with_epoch(plan.desired.epoch + 1)
        reports = list(checkpoint.reports)
        failed = set(checkpoint.unavailable_nodes) | {
            report.node_id for report in reports if
            report.phase is ReconfigurationPhase.ROLLBACK and not report.outcome.ok}
        checkpoint = replace(checkpoint, rollback_status=status)
        self._journal.save(plan.operation_id, checkpoint)

        def act(key: str, node_id: str, action: object) -> StepOutcome:
            nonlocal checkpoint
            ok_key, failed_key = f"{key}:ok", f"{key}:failed"
            if ok_key in checkpoint.completed_steps:
                return StepOutcome.success()
            if failed_key in checkpoint.completed_steps:
                return StepOutcome.failure("rollback.previous_failure")
            if checkpoint.inflight_step == key:
                outcome = StepOutcome.failure("step.outcome_unknown")
            else:
                self._journal.advance_epoch(target.epoch)
                checkpoint = replace(checkpoint, inflight_step=key)
                self._journal.save(plan.operation_id, checkpoint)
                outcome = self._safe_action(action)
            reports.append(PhaseReport(
                ReconfigurationPhase.ROLLBACK, node_id, outcome))
            if not outcome.ok:
                failed.add(node_id)
            marker = ok_key if outcome.ok else failed_key
            checkpoint = replace(
                checkpoint, reports=tuple(reports), inflight_step=None,
                completed_steps=checkpoint.completed_steps | {marker})
            self._journal.save(plan.operation_id, checkpoint)
            return outcome

        def result(known: bool) -> ReconfigurationResult:
            missing = tuple(sorted(failed & set(target.worker_ids)))
            return ReconfigurationResult(
                plan.operation_id, status, target.epoch, target.head_id,
                checkpoint.reports, missing, True, known and not failed)

        candidate_stop = act(
            f"rollback:stop:{plan.desired.head_id}", plan.desired.head_id,
            lambda: self._control.stop(plan.desired.head, epoch=target.epoch))
        if not candidate_stop.ok:
            return checkpoint, result(False)
        head_manifest_ok = False
        for node in target.nodes:
            if (node.node_id in checkpoint.unavailable_nodes
                    and node.node_id != target.head_id):
                continue
            outcome = act(
                f"rollback:push:{node.node_id}", node.node_id,
                lambda node=node: self._control.push_manifest(
                    node, target.manifest_digest, epoch=target.epoch),
            )
            if node.node_id == target.head_id:
                head_manifest_ok = outcome.ok
        head_outcome = (
            act(
                f"rollback:start:{target.head_id}", target.head_id,
                lambda: self._control.start_head(
                    target.head, epoch=target.epoch),
            )
            if head_manifest_ok
            else StepOutcome.failure("rollback.head_manifest_failed")
        )
        head_verified = StepOutcome.failure("rollback.head_not_started")
        cluster_verified = head_verified
        if head_outcome.ok:
            head_verified = act(
                f"rollback:verify:{target.head_id}", target.head_id,
                lambda: self._control.verify(
                    (target.head,), target.head, epoch=target.epoch),
            )
        if head_verified.ok:
            for node in target.workers:
                if node.node_id in failed:
                    continue
                act(
                    f"rollback:join:{node.node_id}", node.node_id,
                    lambda node=node: self._control.join_worker(
                        node, target.head, epoch=target.epoch),
                )
            cluster_verified = act(
                "rollback:verify:cluster", "cluster",
                lambda: self._control.verify(
                    target.nodes, target.head, epoch=target.epoch),
            )
            if not cluster_verified.ok:
                failed.update(target.worker_ids)
        return checkpoint, result(cluster_verified.ok)


class _PhaseFailed(Exception):
    def __init__(self, checkpoint: ReconfigurationCheckpoint) -> None:
        self.checkpoint = checkpoint
