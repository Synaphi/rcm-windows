from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class FakeScheduleToken:
    value: int


class FakeSchedulePort:
    def __init__(self) -> None:
        self._next_token = 1
        self._scheduled: dict[
            FakeScheduleToken,
            tuple[int, int, Callable[[], None]],
        ] = {}

    def call_later(
        self,
        delay_ms: int,
        callback: Callable[[], None],
    ) -> FakeScheduleToken:
        if (
            isinstance(delay_ms, bool)
            or not isinstance(delay_ms, int)
            or delay_ms < 0
        ):
            raise ValueError("delay_ms must be a non-negative integer")
        if not callable(callback):
            raise TypeError("callback must be callable")
        token = FakeScheduleToken(self._next_token)
        self._next_token += 1
        self._scheduled[token] = (delay_ms, token.value, callback)
        return token

    def cancel(self, token: FakeScheduleToken) -> None:
        if not isinstance(token, FakeScheduleToken):
            raise TypeError("token must be a FakeScheduleToken")
        self._scheduled.pop(token, None)

    def run_next(self) -> bool:
        if not self._scheduled:
            return False
        token = min(
            self._scheduled,
            key=lambda item: self._scheduled[item][:2],
        )
        _delay, _sequence, callback = self._scheduled.pop(token)
        callback()
        return True

    def run_all(self, limit: int = 1_000) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        completed = 0
        while completed < limit and self.run_next():
            completed += 1
        if self._scheduled:
            raise RuntimeError("fake schedule run limit was exhausted")
        return completed

    @property
    def pending_count(self) -> int:
        return len(self._scheduled)

    def clear(self) -> None:
        self._scheduled.clear()
        self._next_token = 1


class FakeDesktopHost(FakeSchedulePort):
    def __init__(self) -> None:
        super().__init__()
        self.command_sink: Callable[[object], None] | None = None
        self.rendered_states: list[object] = []
        self.visibility: list[object] = []
        self.events: list[tuple[str, object | None]] = []
        self.running = False
        self.disposed = False

    def bind(self, command_sink: Callable[[object], None]) -> None:
        if not callable(command_sink):
            raise TypeError("command_sink must be callable")
        self.command_sink = command_sink
        self.events.append(("bind", None))

    def render(self, state: object) -> None:
        if self.disposed:
            raise RuntimeError("fake desktop host is disposed")
        self.rendered_states.append(state)
        self.events.append(("render", state))

    def set_visibility(self, value: object) -> None:
        if self.disposed:
            raise RuntimeError("fake desktop host is disposed")
        self.visibility.append(value)
        self.events.append(("visibility", value))

    def run(self) -> None:
        if self.disposed:
            raise RuntimeError("fake desktop host is disposed")
        self.running = True
        self.events.append(("run", None))

    def quit(self) -> None:
        self.running = False
        self.events.append(("quit", None))

    def dispose(self) -> None:
        self.quit()
        self.clear()
        self.command_sink = None
        self.disposed = True
        self.events.append(("dispose", None))

    def safe_snapshot(self) -> dict[str, object]:
        return {
            "render_count": len(self.rendered_states),
            "visibility_count": len(self.visibility),
            "event_names": [name for name, _value in self.events],
            "pending_count": self.pending_count,
            "running": self.running,
            "disposed": self.disposed,
        }

    def resource_count(self) -> int:
        return self.pending_count + int(self.running)


class FakeSingletonLease:
    def __init__(self, owner: FakeSingleton, identity: object) -> None:
        self._owner = owner
        self.identity = identity
        self.released = False

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        self._owner._release(self)

    def __enter__(self) -> FakeSingletonLease:
        return self

    def __exit__(self, *_args: object) -> bool:
        self.release()
        return False


class FakeSingleton:
    def __init__(self) -> None:
        self._lease: FakeSingletonLease | None = None
        self.events: list[tuple[str, object]] = []

    def acquire(self, identity: object) -> FakeSingletonLease | None:
        if self._lease is not None and not self._lease.released:
            self.events.append(("rejected", identity))
            return None
        lease = FakeSingletonLease(self, identity)
        self._lease = lease
        self.events.append(("acquired", identity))
        return lease

    def _release(self, lease: FakeSingletonLease) -> None:
        if self._lease is lease:
            self.events.append(("released", lease.identity))
            self._lease = None

    def clear(self) -> None:
        if self._lease is not None:
            self._lease.release()
        self.events.clear()

    def safe_snapshot(self) -> dict[str, object]:
        return {
            "held": self._lease is not None,
            "event_names": [name for name, _identity in self.events],
        }

    def resource_count(self) -> int:
        return int(self._lease is not None)


class FakeShutdownFallback:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[object, ...], float]] = []

    def invoke(
        self,
        components: tuple[object, ...],
        timeout_seconds: float,
    ) -> None:
        if not isinstance(components, tuple):
            raise TypeError("components must be a tuple")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds < 0
        ):
            raise ValueError("timeout_seconds must be non-negative")
        self.calls.append((components, float(timeout_seconds)))

    __call__ = invoke

    def clear(self) -> None:
        self.calls.clear()

    def safe_snapshot(self) -> dict[str, object]:
        return {"call_count": len(self.calls)}

    def resource_count(self) -> int:
        return 0


__all__ = [
    "FakeDesktopHost",
    "FakeSchedulePort",
    "FakeScheduleToken",
    "FakeShutdownFallback",
    "FakeSingleton",
    "FakeSingletonLease",
]
