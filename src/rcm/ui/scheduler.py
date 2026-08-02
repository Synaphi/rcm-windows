"""One-shot, bounded scheduling for UI-thread event delivery."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Callable, Generic, Protocol, TypeVar

from .state import UiVisibility


T = TypeVar("T")


class SchedulePort(Protocol):
    def call_later(self, delay_ms: int, callback: Callable[[], None]) -> object: ...

    def cancel(self, token: object) -> None: ...


class PostStatus(StrEnum):
    ADDED = "added"
    COALESCED = "coalesced"
    FULL = "full"


@dataclass(frozen=True, slots=True)
class QueueEntry(Generic[T]):
    value: T
    coalesce_key: str | None = None


class BoundedEventQueue(Generic[T]):
    def __init__(self, maximum: int = 1_024) -> None:
        if type(maximum) is not int or not 1 <= maximum <= 1_024:
            raise ValueError("queue maximum must be between 1 and 1024")
        self._maximum = maximum
        self._items: deque[QueueEntry[T]] = deque()
        self._lock = RLock()
        self._dropped = 0

    @property
    def maximum(self) -> int:
        return self._maximum

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def post(self, value: T, *, coalesce_key: str | None = None) -> PostStatus:
        with self._lock:
            if coalesce_key is not None:
                for index in range(len(self._items) - 1, -1, -1):
                    if self._items[index].coalesce_key == coalesce_key:
                        self._items[index] = QueueEntry(value, coalesce_key)
                        return PostStatus.COALESCED
            if len(self._items) >= self._maximum:
                self._dropped += 1
                return PostStatus.FULL
            self._items.append(QueueEntry(value, coalesce_key))
            return PostStatus.ADDED

    def drain(self, maximum: int | None = None) -> tuple[T, ...]:
        limit = self._maximum if maximum is None else maximum
        if type(limit) is not int or limit <= 0:
            raise ValueError("drain maximum must be a positive integer")
        with self._lock:
            count = min(limit, len(self._items))
            return tuple(self._items.popleft().value for _index in range(count))


class UiScheduler(Generic[T]):
    def __init__(
        self,
        *,
        port: SchedulePort,
        consume: Callable[[T], None],
        maximum_queue: int = 1_024,
        visible_interval_ms: int = 1_000,
        batch_size: int = 128,
    ) -> None:
        if not callable(consume):
            raise TypeError("consume must be callable")
        if type(visible_interval_ms) is not int or visible_interval_ms <= 0:
            raise ValueError("visible_interval_ms must be positive")
        if type(batch_size) is not int or not 1 <= batch_size <= maximum_queue:
            raise ValueError("batch_size is outside the queue bound")
        self._port = port
        self._consume = consume
        self._queue: BoundedEventQueue[T] = BoundedEventQueue(maximum_queue)
        self._visible_interval = visible_interval_ms
        self._batch_size = batch_size
        self._visibility = UiVisibility.VISIBLE
        self._token: object | None = None
        self._stopped = True
        self._lock = RLock()

    @property
    def queue_depth(self) -> int:
        return len(self._queue)

    @property
    def dropped(self) -> int:
        return self._queue.dropped

    @property
    def pending_callback(self) -> bool:
        with self._lock:
            return self._token is not None

    def start(self) -> None:
        with self._lock:
            self._stopped = False
            if len(self._queue):
                self._schedule_locked(0)
            elif self._visibility is UiVisibility.VISIBLE:
                self._schedule_locked(self._visible_interval)

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            if self._token is not None:
                self._port.cancel(self._token)
                self._token = None
        self._queue.drain()

    def set_visibility(self, visibility: UiVisibility) -> None:
        if not isinstance(visibility, UiVisibility):
            raise TypeError("visibility must be a UiVisibility")
        with self._lock:
            self._visibility = visibility
            if visibility is UiVisibility.VISIBLE:
                self._schedule_locked(0)
            elif len(self._queue) == 0 and self._token is not None:
                self._port.cancel(self._token)
                self._token = None

    def post(self, value: T, *, coalesce_key: str | None = None) -> PostStatus:
        status = self._queue.post(value, coalesce_key=coalesce_key)
        if status is not PostStatus.FULL:
            with self._lock:
                self._schedule_locked(0)
        return status

    def drain_now(self) -> None:
        self._drain()

    def _schedule_locked(self, delay_ms: int) -> None:
        if self._stopped or self._token is not None:
            return
        self._token = self._port.call_later(delay_ms, self._drain)

    def _drain(self) -> None:
        with self._lock:
            self._token = None
            if self._stopped:
                return
        for item in self._queue.drain(self._batch_size):
            self._consume(item)
        with self._lock:
            if len(self._queue):
                self._schedule_locked(0)
            elif self._visibility is UiVisibility.VISIBLE:
                self._schedule_locked(self._visible_interval)
