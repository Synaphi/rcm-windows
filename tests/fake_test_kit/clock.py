from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation


_NANOSECONDS_PER_SECOND = 1_000_000_000
_DEFAULT_EPOCH = datetime(2020, 1, 1, tzinfo=UTC)


def _nanoseconds(value: int | float | Decimal) -> int:
    if isinstance(value, bool) or not isinstance(
        value,
        (int, float, Decimal),
    ):
        raise ValueError("duration must be numeric")
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("duration must be numeric") from exc
    if not decimal_value.is_finite():
        raise ValueError("duration must be finite")
    nanoseconds = decimal_value * _NANOSECONDS_PER_SECOND
    if nanoseconds != nanoseconds.to_integral_value():
        raise ValueError("duration must resolve to whole nanoseconds")
    result = int(nanoseconds)
    if result < 0:
        raise ValueError("duration must be non-negative")
    return result


class FakeClock:
    def __init__(self, *, seed: int) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("seed must be a non-negative integer")
        self._initial_wall = _DEFAULT_EPOCH + timedelta(seconds=seed)
        self._elapsed_ns = 0
        self._sleeps_ns: list[int] = []

    def now(self) -> datetime:
        return self._initial_wall + timedelta(
            microseconds=self._elapsed_ns // 1_000
        )

    def monotonic_ns(self) -> int:
        return self._elapsed_ns

    def monotonic(self) -> float:
        return self._elapsed_ns / _NANOSECONDS_PER_SECOND

    def advance(self, seconds: int | float | Decimal) -> None:
        self._elapsed_ns += _nanoseconds(seconds)

    def sleep(self, seconds: int | float | Decimal) -> None:
        duration_ns = _nanoseconds(seconds)
        self._sleeps_ns.append(duration_ns)
        self._elapsed_ns += duration_ns

    def reset(self) -> None:
        self._elapsed_ns = 0
        self._sleeps_ns.clear()

    def snapshot(self) -> dict[str, object]:
        return {
            "wall_time": self.now().isoformat(),
            "monotonic_ns": self._elapsed_ns,
            "sleeps_ns": list(self._sleeps_ns),
        }

    def resource_count(self) -> int:
        return len(self._sleeps_ns)
