from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class FakeSensorReading:
    temperature: int
    load_percent: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, int)
            or not -100 <= self.temperature <= 200
        ):
            raise ValueError("temperature is outside the synthetic range")
        if (
            isinstance(self.load_percent, bool)
            or not isinstance(self.load_percent, int)
            or not 0 <= self.load_percent <= 100
        ):
            raise ValueError("load percent must be between 0 and 100")

    def snapshot(self) -> dict[str, int]:
        return asdict(self)


class FakeSensor:
    def __init__(self) -> None:
        self._series: dict[str, tuple[FakeSensorReading, ...]] = {}
        self._positions: dict[str, int] = {}
        self._events: list[tuple[str, int]] = []

    def set_series(
        self,
        node_id: str,
        readings: tuple[FakeSensorReading, ...],
        *,
        replace: bool = False,
    ) -> None:
        if not isinstance(node_id, str) or not node_id:
            raise ValueError("node must be a non-empty string")
        if (
            not isinstance(readings, tuple)
            or not readings
            or any(
                not isinstance(reading, FakeSensorReading)
                for reading in readings
            )
        ):
            raise ValueError("readings must be a non-empty reading tuple")
        if not isinstance(replace, bool):
            raise ValueError("replace must be a boolean")
        if node_id in self._series and not replace:
            raise ValueError("fake sensor series already exists")
        self._series[node_id] = tuple(readings)
        self._positions[node_id] = 0

    def sample(self, node_id: str) -> FakeSensorReading:
        try:
            readings = self._series[node_id]
            position = self._positions[node_id]
        except KeyError as exc:
            raise LookupError("unknown fake sensor node") from exc
        selected = readings[min(position, len(readings) - 1)]
        self._positions[node_id] = min(position + 1, len(readings))
        self._events.append((node_id, position))
        return selected

    def clear(self) -> None:
        self._series.clear()
        self._positions.clear()
        self._events.clear()

    def snapshot(self) -> dict[str, object]:
        series = {}
        for node_id in sorted(self._series):
            series[node_id] = [
                reading.snapshot() for reading in self._series[node_id]
            ]
        return {
            "series": series,
            "positions": {
                node_id: self._positions[node_id]
                for node_id in sorted(self._positions)
            },
            "events": [list(event) for event in self._events],
        }

    def resource_count(self) -> int:
        return len(self._series)
