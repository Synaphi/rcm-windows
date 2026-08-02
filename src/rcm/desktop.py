"""Import-safe desktop lifecycle ports and state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import get_ident
from typing import Callable, Protocol

from .identity import ApplicationIdentity
from .ui.scheduler import SchedulePort
from .ui.state import RenderState, UiCommand, UiVisibility


class DesktopPhase(StrEnum):
    NEW = "new"
    ACQUIRING = "acquiring"
    STARTING = "starting"
    RUNNING = "running"
    RESTARTING = "restarting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class LifecycleScenario(StrEnum):
    VISIBLE_QUIT = "visible-quit"
    CLOSE_SHOW_QUIT = "close-show-quit"
    MINIMIZED_SHOW_QUIT = "minimized-show-quit"


class LifecycleAction(StrEnum):
    WINDOW_CLOSE = "window-close"
    TRAY_SHOW = "tray-show"
    TRAY_QUIT = "tray-quit"


@dataclass(frozen=True, slots=True)
class ScheduledLifecycleCommand:
    delay_ms: int
    action: LifecycleAction


def lifecycle_scenario_commands(
    scenario: LifecycleScenario | None,
) -> tuple[ScheduledLifecycleCommand, ...]:
    if scenario is None:
        return ()
    if not isinstance(scenario, LifecycleScenario):
        raise TypeError("scenario must be a LifecycleScenario or None")
    if scenario is LifecycleScenario.VISIBLE_QUIT:
        return (ScheduledLifecycleCommand(1_000, LifecycleAction.TRAY_QUIT),)
    if scenario is LifecycleScenario.CLOSE_SHOW_QUIT:
        return (
            ScheduledLifecycleCommand(250, LifecycleAction.WINDOW_CLOSE),
            ScheduledLifecycleCommand(1_000, LifecycleAction.TRAY_SHOW),
            ScheduledLifecycleCommand(1_750, LifecycleAction.TRAY_QUIT),
        )
    return (
        ScheduledLifecycleCommand(1_000, LifecycleAction.TRAY_SHOW),
        ScheduledLifecycleCommand(1_750, LifecycleAction.TRAY_QUIT),
    )


@dataclass(frozen=True, slots=True)
class SingletonLease:
    identity: str
    release: Callable[[], None]

    def __post_init__(self) -> None:
        if not self.identity or not callable(self.release):
            raise ValueError("singleton lease requires identity and release")


class SingletonPort(Protocol):
    def acquire(self, identity: ApplicationIdentity) -> SingletonLease | None: ...


class AutostartPort(Protocol):
    def enabled(self, identity: ApplicationIdentity) -> bool: ...

    def set_enabled(
        self,
        identity: ApplicationIdentity,
        *,
        enabled: bool,
        executable: str,
    ) -> None: ...


class DesktopHost(SchedulePort, Protocol):
    def bind(self, command: Callable[[UiCommand], None]) -> None: ...

    def lifecycle_action(self, action: LifecycleAction) -> None: ...

    def render(self, state: RenderState) -> None: ...

    def set_visibility(self, visibility: UiVisibility) -> None: ...

    def run(self) -> int | None: ...

    def quit(self) -> None: ...

    def dispose(self) -> None: ...


class ShutdownFallback(Protocol):
    def __call__(
        self,
        component_names: tuple[str, ...],
        timeout_seconds: float,
    ) -> bool | None: ...


@dataclass(frozen=True, slots=True)
class DesktopLifecycleSnapshot:
    phase: DesktopPhase
    visibility: UiVisibility
    restart_requested: bool
    graceful_complete: bool
    fallback_used: bool
    failure_code: str | None


class UiThreadGuard:
    def __init__(self, identity: int | None = None) -> None:
        self._identity = get_ident() if identity is None else identity

    @property
    def identity(self) -> int:
        return self._identity

    def assert_current(self) -> None:
        if get_ident() != self._identity:
            raise RuntimeError("widget mutation is restricted to the UI thread")


class DesktopLifecycle:
    def __init__(self) -> None:
        self._phase = DesktopPhase.NEW
        self._visibility = UiVisibility.VISIBLE
        self._restart = False
        self._graceful = False
        self._fallback = False
        self._failure: str | None = None

    def snapshot(self) -> DesktopLifecycleSnapshot:
        return DesktopLifecycleSnapshot(
            self._phase,
            self._visibility,
            self._restart,
            self._graceful,
            self._fallback,
            self._failure,
        )

    def begin_acquire(self) -> None:
        self._transition({DesktopPhase.NEW}, DesktopPhase.ACQUIRING)

    def begin_start(self) -> None:
        self._transition({DesktopPhase.ACQUIRING}, DesktopPhase.STARTING)

    def running(self, *, visibility: UiVisibility) -> None:
        self._transition(
            {DesktopPhase.STARTING, DesktopPhase.RESTARTING},
            DesktopPhase.RUNNING,
        )
        self.set_visibility(visibility)

    def set_visibility(self, visibility: UiVisibility) -> None:
        if self._phase is not DesktopPhase.RUNNING:
            raise RuntimeError("visibility changes require a running desktop")
        if not isinstance(visibility, UiVisibility):
            raise TypeError("visibility must be a UiVisibility")
        self._visibility = visibility

    def request_restart(self) -> None:
        self._transition({DesktopPhase.RUNNING}, DesktopPhase.RESTARTING)
        self._restart = True

    def begin_shutdown(self) -> None:
        self._transition(
            {
                DesktopPhase.RUNNING,
                DesktopPhase.RESTARTING,
                DesktopPhase.STARTING,
            },
            DesktopPhase.STOPPING,
        )

    def shutdown_complete(self, *, fallback_used: bool = False) -> None:
        self._transition({DesktopPhase.STOPPING}, DesktopPhase.STOPPED)
        self._graceful = not fallback_used
        self._fallback = fallback_used

    def fail(self, code: str) -> None:
        if not isinstance(code, str) or not code:
            raise ValueError("failure code must be non-empty")
        self._phase = DesktopPhase.FAILED
        self._failure = code

    def _transition(
        self,
        allowed: set[DesktopPhase],
        target: DesktopPhase,
    ) -> None:
        if self._phase not in allowed:
            raise RuntimeError(
                f"invalid desktop transition: {self._phase.value}->{target.value}"
            )
        self._phase = target
