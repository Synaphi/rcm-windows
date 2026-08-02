from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
from threading import Event, RLock
import time
from typing import Callable, Protocol


class RuntimeState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    FAILED = "failed"


class CancellationToken:
    """Thread-safe cooperative cancellation owned by RuntimeCoordinator."""

    def __init__(self) -> None:
        self._event = Event()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise RuntimeCancelledError("runtime operation was cancelled")


class LifecycleComponent(Protocol):
    def start(self, cancellation: CancellationToken) -> None: ...

    def stop(self, timeout_seconds: float) -> None: ...

    def join(self, timeout_seconds: float) -> bool: ...


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeUnit:
    name: str
    component: LifecycleComponent

    def __post_init__(self) -> None:
        if (
            not isinstance(self.name, str) or not self.name
            or any(ord(character) < 33 for character in self.name)
        ):
            raise ValueError("runtime unit name must be a safe token")
        for method in ("start", "stop", "join"):
            if not callable(getattr(self.component, method, None)):
                raise ValueError(
                    f"runtime component must provide {method}()"
                )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeSnapshot:
    state: RuntimeState
    configured: tuple[str, ...]
    active: tuple[str, ...]
    cancellation_requested: bool
    failure_code: str | None = None


class RuntimeLifecycleError(RuntimeError):
    pass


class RuntimeCancelledError(RuntimeLifecycleError):
    pass


class RuntimeStartError(RuntimeLifecycleError):
    pass


class RuntimeShutdownError(RuntimeLifecycleError):
    pass


def _timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError("timeout_seconds must be finite and non-negative")
    return float(value)


class RuntimeCoordinator:
    """The sole lifecycle owner for long-lived application components."""

    def __init__(
        self, units: tuple[RuntimeUnit, ...],
        *,
        shutdown_timeout_seconds: float = 10.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(units, tuple):
            raise ValueError("units must be a tuple")
        if any(not isinstance(unit, RuntimeUnit) for unit in units):
            raise ValueError("units must contain RuntimeUnit values")
        names = tuple(unit.name for unit in units)
        if len(set(names)) != len(names):
            raise ValueError("runtime unit names must be unique")
        if not callable(monotonic):
            raise ValueError("monotonic must be callable")
        self._units = units
        self._shutdown_timeout = _timeout(shutdown_timeout_seconds)
        self._monotonic = monotonic
        self._lock = RLock()
        self._transition = RLock()
        self._state = RuntimeState.STOPPED
        self._active: list[RuntimeUnit] = []
        self._cancellation = CancellationToken()
        self._failure_code: str | None = None

    @property
    def cancellation(self) -> CancellationToken:
        return self._cancellation

    def snapshot(self) -> RuntimeSnapshot:
        with self._lock:
            return RuntimeSnapshot(
                self._state, tuple(unit.name for unit in self._units),
                tuple(unit.name for unit in self._active),
                self._cancellation.cancelled, self._failure_code,
            )

    def start(self) -> RuntimeSnapshot:
        with self._transition:
            return self._start()

    def _start(self) -> RuntimeSnapshot:
        with self._lock:
            if self._state is RuntimeState.RUNNING:
                return self.snapshot()
            if self._state in (RuntimeState.STARTING, RuntimeState.STOPPING):
                raise RuntimeLifecycleError(
                    "runtime lifecycle transition is already in progress"
                )
            if self._active:
                raise RuntimeLifecycleError(
                    "runtime has unresolved active components"
                )
            self._state = RuntimeState.STARTING
            self._failure_code = None
            self._cancellation = CancellationToken()

        try:
            for unit in self._units:
                self._cancellation.raise_if_cancelled()
                with self._lock:
                    self._active.append(unit)
                unit.component.start(self._cancellation)
                self._cancellation.raise_if_cancelled()
            with self._lock:
                self._state = RuntimeState.RUNNING
                return self.snapshot()
        except BaseException as exc:
            code = "start_error"
            self._cancellation.cancel()
            with self._lock:
                self._failure_code = code
            shutdown_error = self._shutdown(
                timeout_seconds=self._shutdown_timeout,
                final_state=RuntimeState.FAILED,
            )
            if shutdown_error is not None:
                with self._lock:
                    self._failure_code = shutdown_error
            with self._lock:
                self._state = RuntimeState.FAILED
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise RuntimeStartError(
                f"runtime start failed ({code})"
            ) from None

    def cancel(self) -> None:
        self._cancellation.cancel()

    def stop(
        self,
        timeout_seconds: float | None = None,
    ) -> RuntimeSnapshot:
        self._cancellation.cancel()
        with self._transition:
            return self._stop(timeout_seconds)

    def _stop(
        self, timeout_seconds: float | None,
    ) -> RuntimeSnapshot:
        timeout = (
            self._shutdown_timeout
            if timeout_seconds is None
            else _timeout(timeout_seconds)
        )
        with self._lock:
            if self._state is RuntimeState.STOPPED and not self._active:
                return self.snapshot()
            if self._state is RuntimeState.STOPPING:
                return self.snapshot()
            self._state = RuntimeState.STOPPING
            self._cancellation.cancel()

        failure = self._shutdown(
            timeout_seconds=timeout,
            final_state=RuntimeState.STOPPED,
        )
        if failure is not None:
            with self._lock:
                self._state = RuntimeState.FAILED
                self._failure_code = failure
            raise RuntimeShutdownError(
                f"runtime shutdown failed ({failure})"
            )
        return self.snapshot()

    def _shutdown(
        self, *, timeout_seconds: float, final_state: RuntimeState,
    ) -> str | None:
        deadline = self._monotonic() + timeout_seconds
        with self._lock:
            active = tuple(reversed(self._active))
        first_failure: str | None = None

        for unit in active:
            remaining = max(0.0, deadline - self._monotonic())
            try:
                unit.component.stop(remaining)
            except BaseException:
                if first_failure is None:
                    first_failure = f"{unit.name}:stop:error"

        unresolved: list[RuntimeUnit] = []
        for unit in active:
            remaining = max(0.0, deadline - self._monotonic())
            try:
                joined = unit.component.join(remaining)
            except BaseException:
                joined = False
                if first_failure is None:
                    first_failure = f"{unit.name}:join:error"
            if not isinstance(joined, bool):
                joined = False
                if first_failure is None:
                    first_failure = f"{unit.name}:join:invalid_result"
            if not joined:
                unresolved.append(unit)
                if first_failure is None:
                    first_failure = f"{unit.name}:join:timeout"

        unresolved_names = {unit.name for unit in unresolved}
        with self._lock:
            self._active = [unit for unit in self._active
                            if unit.name in unresolved_names]
            if first_failure is None:
                self._state = final_state
                if final_state is RuntimeState.STOPPED:
                    self._failure_code = None
        return first_failure
