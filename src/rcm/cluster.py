from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
from threading import RLock
import time
from typing import Protocol

from .core import BusyError, BusyState, ConflictError, Node, NodeRole


class ClusterMemberState(StrEnum):
    ALIVE = "alive"
    STOPPED = "stopped"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


MAX_OBSERVED_NODES = 32


def _non_negative_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _time(value: object, *, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
    ):
        raise ValueError(f"{field} must be finite")
    return float(value)


@dataclass(frozen=True, slots=True, repr=False)
class ClusterMember:
    node: Node
    state: ClusterMemberState
    observed_at: float
    active_jobs: int | None = None
    active_tasks: int | None = None
    workload_evidence_fresh: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.node, Node):
            raise ValueError("node must be a Node")
        if not isinstance(self.state, ClusterMemberState):
            raise ValueError("state must be a ClusterMemberState")
        _time(self.observed_at, field="observed_at")
        if self.active_jobs is not None:
            _non_negative_int(self.active_jobs, field="active_jobs")
        if self.active_tasks is not None:
            _non_negative_int(self.active_tasks, field="active_tasks")
        if not isinstance(self.workload_evidence_fresh, bool):
            raise ValueError("workload_evidence_fresh must be a bool")
        if self.state is not ClusterMemberState.ALIVE and (
            self.active_jobs is not None or self.active_tasks is not None
        ):
            raise ValueError(
                "only alive members may carry workload evidence"
            )


@dataclass(frozen=True, slots=True, repr=False)
class ClusterWorkloadEvidence:
    observed_at: float
    active_jobs: int | None = None
    active_tasks: int | None = None
    active_actors: int | None = None
    active_placement_groups: int | None = None
    complete: bool = False
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _time(self.observed_at, field="observed_at")
        counts = (
            self.active_jobs,
            self.active_tasks,
            self.active_actors,
            self.active_placement_groups,
        )
        for field, value in zip(
            ("active_jobs", "active_tasks", "active_actors",
             "active_placement_groups"), counts, strict=True,
        ):
            if value is not None:
                _non_negative_int(value, field=field)
        if not isinstance(self.complete, bool):
            raise ValueError("complete must be a bool")
        if not isinstance(self.reasons, tuple) or any(
            not isinstance(reason, str)
            or not reason
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_:"
                   for character in reason)
            for reason in self.reasons
        ):
            raise ValueError("reasons must contain safe reason codes")
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("evidence reasons must be unique")
        if self.complete and (any(value is None for value in counts) or self.reasons):
            raise ValueError("complete evidence requires every count and no reason")

    @property
    def counts(self) -> tuple[int | None, ...]:
        return (
            self.active_jobs,
            self.active_tasks,
            self.active_actors,
            self.active_placement_groups,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ClusterSnapshot:
    epoch: int
    expected_head_id: str
    members: tuple[ClusterMember, ...]
    captured_at: float
    workload: ClusterWorkloadEvidence | None = None

    def __post_init__(self) -> None:
        _non_negative_int(self.epoch, field="epoch")
        if not isinstance(self.expected_head_id, str) or not self.expected_head_id:
            raise ValueError("expected_head_id must be non-empty")
        if not isinstance(self.members, tuple) or not self.members:
            raise ValueError("members must be a non-empty tuple")
        if any(not isinstance(member, ClusterMember) for member in self.members):
            raise ValueError("members must contain ClusterMember values")
        identifiers = tuple(member.node.node_id for member in self.members)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("cluster member node identifiers must be unique")
        if self.expected_head_id not in identifiers:
            raise ValueError("expected head must be present in members")
        head_roles = [member.node for member in self.members
                      if member.node.role is NodeRole.HEAD]
        if len(head_roles) != 1 or head_roles[0].node_id != self.expected_head_id:
            raise ValueError("snapshot must contain exactly its expected head")
        _time(self.captured_at, field="captured_at")
        if self.workload is not None and not isinstance(
            self.workload, ClusterWorkloadEvidence
        ):
            raise ValueError("workload must be ClusterWorkloadEvidence or None")

    def member(self, node_id: str) -> ClusterMember:
        for member in self.members:
            if member.node.node_id == node_id:
                return member
        raise LookupError("unknown cluster member")


@dataclass(frozen=True, slots=True, repr=False)
class BusyAssessment:
    state: BusyState
    epoch: int
    reasons: tuple[str, ...]

    @property
    def safe_for_maintenance(self) -> bool:
        return self.state is BusyState.IDLE


@dataclass(frozen=True, slots=True, repr=False)
class ClusterDiagnosis:
    assessment: BusyAssessment
    snapshot: ClusterSnapshot | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.assessment, BusyAssessment):
            raise TypeError("assessment must be a BusyAssessment")
        if self.snapshot is not None and not isinstance(
            self.snapshot, ClusterSnapshot
        ):
            raise TypeError("snapshot must be ClusterSnapshot or None")


class ClusterObserver(Protocol):
    def observe(
        self,
        nodes: tuple[Node, ...],
        *,
        expected_head_id: str,
        epoch: int,
        cancellation: object | None = None,
    ) -> ClusterSnapshot: ...


class ClusterBusyPolicy:
    """Uses explicit Ray workload evidence, never CPU utilization."""

    def __init__(self, *, max_age_seconds: float) -> None:
        max_age = _time(max_age_seconds, field="max_age_seconds")
        if max_age <= 0:
            raise ValueError("max_age_seconds must be positive")
        self._max_age = max_age

    def assess(
        self,
        snapshot: ClusterSnapshot,
        *,
        now: float,
        maintenance: bool = False,
    ) -> BusyAssessment:
        if not isinstance(snapshot, ClusterSnapshot):
            raise TypeError("snapshot must be a ClusterSnapshot")
        current = _time(now, field="now")
        if not isinstance(maintenance, bool):
            raise ValueError("maintenance must be a bool")
        if maintenance:
            return BusyAssessment(
                BusyState.MAINTENANCE, snapshot.epoch, ("maintenance_lock",),
            )
        if current < snapshot.captured_at:
            return BusyAssessment(
                BusyState.UNKNOWN, snapshot.epoch, ("clock_skew",),
            )
        if current - snapshot.captured_at > self._max_age:
            return BusyAssessment(
                BusyState.UNKNOWN, snapshot.epoch, ("stale_snapshot",),
            )

        workload = snapshot.workload
        if workload is not None:
            if current < workload.observed_at:
                return BusyAssessment(
                    BusyState.UNKNOWN, snapshot.epoch,
                    ("workload:clock_skew",),
                )
            if current - workload.observed_at > self._max_age:
                return BusyAssessment(
                    BusyState.UNKNOWN, snapshot.epoch,
                    ("workload:stale",),
                )
            if any(value is not None and value > 0 for value in workload.counts):
                return BusyAssessment(
                    BusyState.BUSY, snapshot.epoch,
                    ("cluster:active_workload",),
                )

        unknown: list[str] = []
        for member in snapshot.members:
            node_id = member.node.node_id
            if current < member.observed_at:
                unknown.append(f"{node_id}:clock_skew")
                continue
            if current - member.observed_at > self._max_age:
                unknown.append(f"{node_id}:stale")
                continue
            if member.state is ClusterMemberState.STOPPED:
                continue
            if member.state is not ClusterMemberState.ALIVE:
                unknown.append(f"{node_id}:unavailable")
                continue
            if workload is None:
                if (
                    not member.workload_evidence_fresh
                    or member.active_jobs is None
                    or member.active_tasks is None
                ):
                    unknown.append(f"{node_id}:workload_unknown")
                    continue
                if member.active_jobs > 0 or member.active_tasks > 0:
                    return BusyAssessment(
                        BusyState.BUSY, snapshot.epoch,
                        (f"{node_id}:active_workload",),
                    )

        if workload is not None and not workload.complete:
            unknown.extend(
                workload.reasons or ("workload:incomplete",)
            )

        if unknown:
            return BusyAssessment(
                BusyState.UNKNOWN, snapshot.epoch, tuple(unknown),
            )
        return BusyAssessment(BusyState.IDLE, snapshot.epoch, ())


class ClusterStateService:
    """Diagnose a bounded configured cluster without composing a poller."""

    def __init__(
        self,
        observer: ClusterObserver,
        policy: ClusterBusyPolicy,
        *,
        clock: object = time.monotonic,
    ) -> None:
        if not callable(getattr(observer, "observe", None)):
            raise TypeError("observer must provide observe()")
        if not isinstance(policy, ClusterBusyPolicy):
            raise TypeError("policy must be a ClusterBusyPolicy")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._observer = observer
        self._policy = policy
        self._clock = clock

    @staticmethod
    def _unknown(epoch: int, reason: str) -> ClusterDiagnosis:
        return ClusterDiagnosis(
            BusyAssessment(BusyState.UNKNOWN, epoch, (reason,))
        )

    def diagnose(
        self,
        nodes: tuple[Node, ...],
        *,
        expected_head_id: str,
        epoch: int,
        now: float | None = None,
        cancellation: object | None = None,
    ) -> ClusterDiagnosis:
        _non_negative_int(epoch, field="epoch")
        supplied_now = None if now is None else _time(now, field="now")
        if not isinstance(nodes, tuple) or any(
            not isinstance(node, Node) for node in nodes
        ):
            raise TypeError("nodes must be a tuple of Node values")
        enabled = tuple(node for node in nodes if node.enabled)
        if not enabled:
            return self._unknown(epoch, "configuration:no_enabled_nodes")
        if len(enabled) > MAX_OBSERVED_NODES:
            return self._unknown(epoch, "configuration:too_many_nodes")
        identifiers = tuple(node.node_id for node in enabled)
        heads = tuple(node for node in enabled if node.role is NodeRole.HEAD)
        if (
            not isinstance(expected_head_id, str)
            or expected_head_id not in identifiers
            or len(set(identifiers)) != len(identifiers)
            or len(heads) != 1
            or heads[0].node_id != expected_head_id
        ):
            return self._unknown(epoch, "configuration:ambiguous_topology")
        try:
            snapshot = self._observer.observe(
                enabled,
                expected_head_id=expected_head_id,
                epoch=epoch,
                cancellation=cancellation,
            )
        except Exception:
            return self._unknown(epoch, "observer:failed")
        if not isinstance(snapshot, ClusterSnapshot) or snapshot.epoch != epoch:
            return self._unknown(epoch, "observer:invalid_snapshot")
        current = (
            supplied_now
            if supplied_now is not None
            else _time(self._clock(), field="clock result")
        )
        return ClusterDiagnosis(
            self._policy.assess(snapshot, now=current), snapshot,
        )


class _LeaseToken:
    __slots__ = ("active", "in_use", "lock")

    def __init__(self) -> None:
        self.active = True
        self.in_use = False
        self.lock = RLock()


@dataclass(frozen=True, slots=True, repr=False, init=False)
class MaintenanceLease:
    request_id: str
    epoch: int
    _token: _LeaseToken

    @classmethod
    def _issue(cls, request_id: str, epoch: int) -> MaintenanceLease:
        lease = object.__new__(cls)
        object.__setattr__(lease, "request_id", request_id)
        object.__setattr__(lease, "epoch", epoch)
        object.__setattr__(lease, "_token", _LeaseToken())
        return lease

    @property
    def active(self) -> bool:
        return isinstance(getattr(self, "_token", None), _LeaseToken) and self._token.active

    def _claim(self) -> bool:
        with self._token.lock:
            if not self._token.active or self._token.in_use:
                return False
            self._token.in_use = True
            return True

    def _release_claim(self) -> None:
        with self._token.lock:
            self._token.in_use = False


class MaintenanceGuard:
    def __init__(self) -> None:
        self._lease: MaintenanceLease | None = None
        self._lock = RLock()

    @property
    def active(self) -> bool:
        with self._lock:
            return self._lease is not None

    @property
    def lease(self) -> MaintenanceLease | None:
        with self._lock:
            return self._lease

    def acquire(
        self, *, request_id: str,
        assessment: BusyAssessment,
        expected_epoch: int,
    ) -> MaintenanceLease:
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id must be non-empty")
        if any(ord(character) < 33 for character in request_id):
            raise ValueError("request_id must be a safe token")
        if not isinstance(assessment, BusyAssessment):
            raise TypeError("assessment must be a BusyAssessment")
        _non_negative_int(expected_epoch, field="expected_epoch")
        with self._lock:
            if assessment.epoch != expected_epoch:
                raise ConflictError("cluster epoch changed before maintenance")
            if self._lease is not None:
                if self._lease.request_id == request_id:
                    return self._lease
                raise ConflictError("maintenance is owned by another request")
            if not assessment.safe_for_maintenance:
                raise BusyError("cluster is not proven idle")
            self._lease = MaintenanceLease._issue(request_id, expected_epoch)
            return self._lease

    def release(self, lease: MaintenanceLease) -> None:
        if not isinstance(lease, MaintenanceLease):
            raise TypeError("lease must be a MaintenanceLease")
        if not lease.active:
            return
        with self._lock:
            if self._lease is None or self._lease is not lease:
                raise ConflictError("maintenance lease does not match owner")
            with lease._token.lock:
                if lease._token.in_use:
                    raise ConflictError("maintenance lease is in use")
                lease._token.active = False
            self._lease = None
