"""Lazy host sensor adapters."""

from __future__ import annotations

import math
from typing import Any

from ..core import (
    MetricSnapshot,
    PermissionDeniedError,
    UnavailableError,
    UnsupportedError,
)
from ..ports import Clock


class PsutilSensor:
    def __init__(
        self,
        *,
        clock: Clock,
        psutil_module: Any | None = None,
    ) -> None:
        self._clock = clock
        self._psutil_module = psutil_module

    def _psutil(self) -> Any:
        if self._psutil_module is None:
            import psutil

            self._psutil_module = psutil
        return self._psutil_module

    def sample(self, node_id: str) -> MetricSnapshot:
        if (
            type(node_id) is not str or not node_id or len(node_id) > 128
            or any(ord(character) < 32 for character in node_id)
        ):
            raise ValueError("node_id must be a safe non-empty string")
        psutil = self._psutil()
        try:
            cpu = float(psutil.cpu_percent(interval=None))
            memory = float(psutil.virtual_memory().percent)
        except psutil.AccessDenied:
            raise PermissionDeniedError(
                "permission is required to read local sensors"
            ) from None
        except (AttributeError, NotImplementedError):
            raise UnsupportedError("local sensors are unsupported") from None
        except (OSError, RuntimeError, ValueError):
            raise UnavailableError("local sensors are unavailable") from None
        temperature = _temperature(psutil)
        try:
            return MetricSnapshot(
                node_id=node_id,
                observed_at_ns=self._clock.monotonic_ns(),
                cpu_percent=cpu,
                memory_percent=memory,
                temperature_celsius=temperature,
            )
        except (TypeError, ValueError):
            raise UnavailableError("local sensor data is invalid") from None


def _temperature(psutil: Any) -> float | None:
    reader = getattr(psutil, "sensors_temperatures", None)
    if reader is None:
        return None
    try:
        groups = reader()
    except (
        getattr(psutil, "AccessDenied", PermissionError),
        NotImplementedError,
        OSError,
        RuntimeError,
        ValueError,
    ):
        return None
    if not isinstance(groups, dict):
        return None
    readings: list[float] = []
    for entries in groups.values():
        for entry in entries:
            value = getattr(entry, "current", None)
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                and -273.15 <= value <= 1_000
            ):
                readings.append(float(value))
    return max(readings) if readings else None


__all__ = ["PsutilSensor"]
