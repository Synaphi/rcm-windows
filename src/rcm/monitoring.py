"""Freshness-aware monitoring service with bounded adaptive backoff."""

from __future__ import annotations

from dataclasses import dataclass, replace
import math

from .core import (
    MetricSnapshot, MetricState, PermissionDeniedError, StaleError,
    UnavailableError, UnsupportedError,
)
from .ports import Clock, Sensor


def _positive(value: float, field: str, *, maximum: float | None = None) -> float:
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not math.isfinite(value) or value <= 0
        or (maximum is not None and value > maximum)
    ):
        raise ValueError(f"{field} must be a finite positive number")
    return float(value)


@dataclass(frozen=True, slots=True, repr=False)
class MonitoringPolicy:
    interval_seconds: float = 1.0
    stale_after_seconds: float = 5.0
    maximum_backoff_seconds: float = 60.0
    backoff_multiplier: float = 2.0

    def __post_init__(self) -> None:
        interval = _positive(self.interval_seconds, "interval_seconds", maximum=31_536_000)
        stale = _positive(
            self.stale_after_seconds, "stale_after_seconds", maximum=31_536_000
        )
        maximum = _positive(
            self.maximum_backoff_seconds, "maximum_backoff_seconds",
            maximum=31_536_000
        )
        multiplier = _positive(self.backoff_multiplier, "backoff_multiplier")
        if stale < interval * 2:
            raise ValueError("stale_after_seconds must be at least twice interval_seconds")
        if maximum < interval:
            raise ValueError("maximum_backoff_seconds must be at least interval_seconds")
        if multiplier < 1:
            raise ValueError("backoff_multiplier must be at least one")
        object.__setattr__(self, "interval_seconds", interval)
        object.__setattr__(self, "stale_after_seconds", stale)
        object.__setattr__(self, "maximum_backoff_seconds", maximum)
        object.__setattr__(self, "backoff_multiplier", multiplier)


@dataclass(frozen=True, slots=True, repr=False)
class MonitoringObservation:
    snapshot: MetricSnapshot
    last_attempt_state: MetricState
    last_good: MetricSnapshot | None
    age_seconds: float | None
    consecutive_failures: int
    next_poll_seconds: float


@dataclass(slots=True, repr=False)
class _NodeMonitoringState:
    snapshot: MetricSnapshot
    last_good: MetricSnapshot | None
    consecutive_failures: int
    next_due: float
    sequence: int


class MonitoringService:
    def __init__(
        self, *, clock: Clock, sensor: Sensor,
        policy: MonitoringPolicy = MonitoringPolicy(),
    ) -> None:
        self._clock = clock
        self._sensor = sensor
        self._policy = policy
        self._states: dict[str, _NodeMonitoringState] = {}

    def poll(self, node_id: str) -> MonitoringObservation:
        _node_id(node_id)
        now = self._clock.monotonic()
        current = self._states.get(node_id)
        if current is not None and now < current.next_due:
            return self._observation(current, now=now)
        sequence = 0 if current is None else current.sequence + 1
        last_good = None if current is None else current.last_good
        failures = 0 if current is None else current.consecutive_failures
        now_ns = self._clock.monotonic_ns()
        try:
            sampled = self._sensor.sample(node_id)
        except UnsupportedError:
            state = MetricState.UNSUPPORTED
            detail_code = "sensor_unsupported"
        except PermissionDeniedError:
            state = MetricState.PERMISSION_DENIED
            detail_code = "sensor_permission_denied"
        except (UnavailableError, StaleError):
            state = MetricState.UNAVAILABLE
            detail_code = "sensor_unavailable"
        except Exception:
            state = MetricState.UNAVAILABLE
            detail_code = "sensor_failure"
        else:
            if (not isinstance(sampled, MetricSnapshot)
                    or sampled.node_id != node_id
                    or sampled.observed_at_ns > now_ns):
                state = MetricState.UNAVAILABLE
                detail_code = "sensor_contract_invalid"
            elif sampled.state is not MetricState.OK:
                state = sampled.state
                detail_code = _detail_for_state(state)
            elif now_ns - sampled.observed_at_ns > self._stale_after_nanoseconds:
                state = MetricState.STALE
                detail_code = "sample_expired"
            else:
                fresh = replace(sampled, sequence=sequence)
                state_value = _NodeMonitoringState(
                    snapshot=fresh,
                    last_good=fresh,
                    consecutive_failures=0,
                    next_due=now + self._policy.interval_seconds,
                    sequence=sequence,
                )
                self._states[node_id] = state_value
                return self._observation(state_value, now=now)

        failures += 1
        snapshot = MetricSnapshot(
            node_id=node_id,
            observed_at_ns=now_ns,
            sequence=sequence,
            state=state,
            detail_code=detail_code,
        )
        delay = self._backoff(state, failures)
        state_value = _NodeMonitoringState(
            snapshot=snapshot,
            last_good=last_good,
            consecutive_failures=failures,
            next_due=now + delay,
            sequence=sequence,
        )
        self._states[node_id] = state_value
        return self._observation(state_value, now=now)

    def current(self, node_id: str) -> MonitoringObservation:
        _node_id(node_id)
        now = self._clock.monotonic()
        state = self._states.get(node_id)
        if state is None:
            snapshot = MetricSnapshot(
                node_id=node_id,
                observed_at_ns=self._clock.monotonic_ns(),
                state=MetricState.UNAVAILABLE,
                detail_code="not_sampled",
            )
            return MonitoringObservation(
                snapshot, MetricState.UNAVAILABLE, None, None, 0, 0.0
            )
        return self._observation(state, now=now)

    def reset(self, node_id: str | None = None) -> None:
        if node_id is None:
            self._states.clear()
            return
        _node_id(node_id)
        self._states.pop(node_id, None)

    @property
    def _stale_after_nanoseconds(self) -> int:
        return int(self._policy.stale_after_seconds * 1_000_000_000)

    def _backoff(self, state: MetricState, failures: int) -> float:
        if state in {MetricState.UNSUPPORTED, MetricState.PERMISSION_DENIED}:
            return self._policy.maximum_backoff_seconds
        delay = self._policy.interval_seconds
        for _index in range(failures):
            if delay >= (
                self._policy.maximum_backoff_seconds
                / self._policy.backoff_multiplier
            ):
                return self._policy.maximum_backoff_seconds
            delay *= self._policy.backoff_multiplier
        return min(delay, self._policy.maximum_backoff_seconds)

    def _observation(
        self, state: _NodeMonitoringState, *, now: float
    ) -> MonitoringObservation:
        age_seconds: float | None = None
        snapshot = state.snapshot
        if state.last_good is not None:
            age_ns = max(
                0, self._clock.monotonic_ns() - state.last_good.observed_at_ns
            )
            age_seconds = age_ns / 1_000_000_000
            if age_ns > self._stale_after_nanoseconds:
                snapshot = MetricSnapshot(
                    node_id=state.last_good.node_id,
                    observed_at_ns=state.last_good.observed_at_ns,
                    sequence=state.sequence,
                    state=MetricState.STALE,
                    detail_code="sample_expired",
                )
            elif state.snapshot.state in {MetricState.UNAVAILABLE, MetricState.STALE}:
                snapshot = state.last_good
        return MonitoringObservation(
            snapshot=snapshot,
            last_attempt_state=state.snapshot.state,
            last_good=state.last_good,
            age_seconds=age_seconds,
            consecutive_failures=state.consecutive_failures,
            next_poll_seconds=max(0.0, state.next_due - now),
        )


def _node_id(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 128
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError("node_id must be a safe non-empty string")


def _detail_for_state(state: MetricState) -> str:
    return {
        MetricState.UNAVAILABLE: "sensor_unavailable",
        MetricState.UNSUPPORTED: "sensor_unsupported",
        MetricState.PERMISSION_DENIED: "sensor_permission_denied",
        MetricState.STALE: "sample_expired",
        MetricState.OK: "sensor_contract_invalid",
    }[state]


__all__ = ["MonitoringObservation", "MonitoringPolicy", "MonitoringService"]
