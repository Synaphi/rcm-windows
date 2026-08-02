"""Immutable, UI-independent contracts shared by RCM services."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
from typing import Iterable, Mapping


_MAX_TEXT = 1_024
_MAX_IDENTIFIER = 128
_MAX_INT64 = (1 << 63) - 1


def _text(
    value: object,
    name: str,
    *,
    allow_empty: bool = False,
    maximum: int = _MAX_TEXT,
) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if (not value and not allow_empty) or len(value) > maximum:
        qualifier = "between 1 and" if not allow_empty else "at most"
        raise ValueError(f"{name} must contain {qualifier} {maximum} characters")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _code(value: object, name: str, *, allow_empty: bool = False) -> str:
    result = _text(
        value, name, allow_empty=allow_empty, maximum=_MAX_IDENTIFIER)
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789_.:-"
    if any(character not in allowed for character in result):
        raise ValueError(f"{name} must be a safe lowercase code")
    return result


def _integer(value: object, name: str, *, maximum: int = _MAX_INT64) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} must be between 0 and {maximum}")
    return value


def _pairs(
    values: Iterable[tuple[str, str]],
    name: str,
) -> tuple[tuple[str, str], ...]:
    try:
        result = tuple(values)
    except TypeError:
        raise TypeError(f"{name} must be an iterable of string pairs") from None
    seen: set[str] = set()
    for pair in result:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not isinstance(pair[0], str)
            or not isinstance(pair[1], str)
        ):
            raise TypeError(f"{name} must contain string pairs")
        key = _text(pair[0], f"{name} key", maximum=_MAX_IDENTIFIER)
        _text(pair[1], f"{name} value", allow_empty=True)
        if key in seen:
            raise ValueError(f"{name} keys must be unique")
        seen.add(key)
    return result


class NodeRole(str, Enum):
    HEAD = "head"
    WORKER = "worker"
    OBSERVER = "observer"


class MetricState(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    STALE = "stale"


class CapabilityState(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"


class BusyState(str, Enum):
    """Conservative workload state.

    Only an explicitly observed ``IDLE`` state permits disruptive work.
    In particular, low CPU usage is not represented as idle evidence.
    """

    IDLE = "idle"
    BUSY = "busy"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"

    @property
    def allows_reconfiguration(self) -> bool:
        return self is BusyState.IDLE


class ActionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True, repr=False)
class Capability:
    name: str
    state: CapabilityState
    detail_code: str = ""

    def __post_init__(self) -> None:
        _code(self.name, "capability name")
        if not isinstance(self.state, CapabilityState):
            raise TypeError("capability state must be a CapabilityState")
        _code(self.detail_code, "capability detail code", allow_empty=True)

    @property
    def available(self) -> bool:
        return self.state is CapabilityState.AVAILABLE

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.value,
            "available": self.available,
        }


@dataclass(frozen=True, slots=True, repr=False)
class Node:
    node_id: str
    address: str = field(repr=False)
    role: NodeRole = NodeRole.WORKER
    enabled: bool = True
    capabilities: tuple[Capability, ...] = ()

    def __post_init__(self) -> None:
        _text(self.node_id, "node_id", maximum=_MAX_IDENTIFIER)
        _text(self.address, "node address", maximum=253)
        if not isinstance(self.role, NodeRole):
            raise TypeError("node role must be a NodeRole")
        if type(self.enabled) is not bool:
            raise TypeError("node enabled must be a bool")
        capabilities = tuple(self.capabilities)
        if any(not isinstance(item, Capability) for item in capabilities):
            raise TypeError("node capabilities must contain Capability values")
        names = [item.name for item in capabilities]
        if len(names) != len(set(names)):
            raise ValueError("node capability names must be unique")
        object.__setattr__(self, "capabilities", capabilities)

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "enabled": self.enabled,
            "capability_count": len(self.capabilities),
            "available_capability_count": sum(
                item.available for item in self.capabilities),
        }


def _metric(value: object, name: str, minimum: float, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric or None")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{name} is outside its supported range")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class MetricSnapshot:
    node_id: str
    observed_at_ns: int
    sequence: int = 0
    state: MetricState = MetricState.OK
    cpu_percent: float | None = None
    memory_percent: float | None = None
    temperature_celsius: float | None = None
    detail_code: str = ""

    def __post_init__(self) -> None:
        _text(self.node_id, "metric node_id", maximum=_MAX_IDENTIFIER)
        _integer(self.observed_at_ns, "observed_at_ns")
        _integer(self.sequence, "metric sequence")
        if not isinstance(self.state, MetricState):
            raise TypeError("metric state must be a MetricState")
        cpu = _metric(self.cpu_percent, "cpu_percent", 0.0, 100.0)
        memory = _metric(self.memory_percent, "memory_percent", 0.0, 100.0)
        temperature = _metric(
            self.temperature_celsius,
            "temperature_celsius",
            -273.15,
            1_000.0,
        )
        values = (cpu, memory, temperature)
        if self.state is MetricState.OK and all(value is None for value in values):
            raise ValueError("an OK metric snapshot requires at least one reading")
        if self.state is not MetricState.OK and any(value is not None for value in values):
            raise ValueError("a non-OK metric snapshot must not contain readings")
        _code(self.detail_code, "metric detail code", allow_empty=True)
        object.__setattr__(self, "cpu_percent", cpu)
        object.__setattr__(self, "memory_percent", memory)
        object.__setattr__(self, "temperature_celsius", temperature)

    def to_dict(self) -> dict[str, object]:
        readings = (
            self.cpu_percent,
            self.memory_percent,
            self.temperature_celsius,
        )
        return {
            "state": self.state.value,
            "reading_count": sum(value is not None for value in readings),
        }


@dataclass(frozen=True, slots=True, repr=False)
class ActionResult:
    status: ActionStatus
    code: str
    message: str = ""
    retryable: bool = False
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, ActionStatus):
            raise TypeError("action status must be an ActionStatus")
        _code(self.code, "action result code")
        _text(self.message, "action result message", allow_empty=True)
        if type(self.retryable) is not bool:
            raise TypeError("action result retryable must be a bool")
        object.__setattr__(self, "details", _pairs(self.details, "action result details"))
        if self.status is ActionStatus.SUCCEEDED and self.retryable:
            raise ValueError("a successful action result cannot be retryable")

    @property
    def ok(self) -> bool:
        return self.status is ActionStatus.SUCCEEDED

    @classmethod
    def success(
        cls,
        code: str = "ok",
        message: str = "",
        *,
        details: Iterable[tuple[str, str]] = (),
    ) -> ActionResult:
        return cls(ActionStatus.SUCCEEDED, code, message, False, tuple(details))

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "code": self.code,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True, repr=False)
class PlanStep:
    step_id: str
    action: str
    node_id: str = field(default="", repr=False)
    depends_on: tuple[str, ...] = ()
    disruptive: bool = False

    def __post_init__(self) -> None:
        _text(self.step_id, "step_id", maximum=_MAX_IDENTIFIER)
        _code(self.action, "step action")
        _text(self.node_id, "step node_id", allow_empty=True, maximum=_MAX_IDENTIFIER)
        dependencies = tuple(self.depends_on)
        for dependency in dependencies:
            _text(dependency, "step dependency", maximum=_MAX_IDENTIFIER)
        if len(dependencies) != len(set(dependencies)):
            raise ValueError("step dependencies must be unique")
        if self.step_id in dependencies:
            raise ValueError("a step cannot depend on itself")
        if type(self.disruptive) is not bool:
            raise TypeError("step disruptive must be a bool")
        object.__setattr__(self, "depends_on", dependencies)

    def to_dict(self) -> dict[str, object]:
        return {
            "dependency_count": len(self.depends_on),
            "disruptive": self.disruptive,
        }


@dataclass(frozen=True, slots=True, repr=False)
class Plan:
    plan_id: str
    epoch: int
    steps: tuple[PlanStep, ...]

    def __post_init__(self) -> None:
        _text(self.plan_id, "plan_id", maximum=_MAX_IDENTIFIER)
        _integer(self.epoch, "plan epoch")
        steps = tuple(self.steps)
        if not steps or any(not isinstance(step, PlanStep) for step in steps):
            raise ValueError("plan steps must contain at least one PlanStep")
        identifiers = tuple(step.step_id for step in steps)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("plan step identifiers must be unique")
        known = set(identifiers)
        for step in steps:
            unknown = set(step.depends_on) - known
            if unknown:
                raise ValueError("plan dependencies must reference plan steps")
        object.__setattr__(self, "steps", steps)
        self.ordered_steps()

    def ordered_steps(self) -> tuple[PlanStep, ...]:
        """Return a stable topological order, rejecting dependency cycles."""

        pending = list(self.steps)
        completed: set[str] = set()
        ordered: list[PlanStep] = []
        while pending:
            ready = [
                step
                for step in pending
                if set(step.depends_on).issubset(completed)
            ]
            if not ready:
                raise ValueError("plan dependencies contain a cycle")
            for step in ready:
                pending.remove(step)
                ordered.append(step)
                completed.add(step.step_id)
        return tuple(ordered)

    def ready_steps(self, completed: Iterable[str]) -> tuple[PlanStep, ...]:
        completed_set = set(completed)
        known = {step.step_id for step in self.steps}
        if not completed_set.issubset(known):
            raise ValueError("completed identifiers must reference plan steps")
        return tuple(
            step
            for step in self.steps
            if step.step_id not in completed_set
            and set(step.depends_on).issubset(completed_set)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "step_count": len(self.steps),
            "disruptive_count": sum(step.disruptive for step in self.steps),
        }


class RcmError(Exception):
    """Base class for sanitized, typed service failures."""

    code = "rcm_error"
    retryable = False

    def __init__(
        self,
        message: str = "",
        *,
        context: Iterable[tuple[str, str]] = (),
    ) -> None:
        _text(message, "error message", allow_empty=True)
        self.context = _pairs(context, "error context")
        super().__init__(message or self.code)

    def to_result(self) -> ActionResult:
        return ActionResult(
            ActionStatus.FAILED, self.code, retryable=self.retryable)


class UnavailableError(RcmError):
    code = "unavailable"
    retryable = True


class UnsupportedError(RcmError):
    code = "unsupported"


class PermissionDeniedError(RcmError):
    code = "permission_denied"


class StaleError(RcmError):
    code = "stale"
    retryable = True


class BusyError(RcmError):
    code = "busy"
    retryable = True


class ConflictError(RcmError):
    code = "conflict"
    retryable = True


class RejectedError(RcmError):
    code = "rejected"


def error_from_state(state: CapabilityState, message: str = "") -> RcmError:
    """Map an unavailable capability state to its public typed failure."""

    mapping: Mapping[CapabilityState, type[RcmError]] = {
        CapabilityState.UNAVAILABLE: UnavailableError,
        CapabilityState.UNSUPPORTED: UnsupportedError,
        CapabilityState.PERMISSION_DENIED: PermissionDeniedError,
    }
    if state is CapabilityState.AVAILABLE:
        raise ValueError("an available capability is not an error")
    return mapping[state](message)
