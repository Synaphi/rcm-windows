from __future__ import annotations

import hashlib
import json
from types import TracebackType

from .clock import FakeClock
from .credentials import FakeCredentialStore
from .desktop import FakeDesktopHost, FakeShutdownFallback, FakeSingleton
from .filesystem import FakeFilesystem
from .guard import NoLiveAccessGuard
from .http import FakeHttpTransport
from .nodes import SyntheticNode, nodes_snapshot, synthetic_nodes
from .processes import FakeProcessTable
from .privilege import FakePrivilegeBoundary
from .ray import FakeRayAdapter
from .sensor import FakeSensor, FakeSensorReading


DEFAULT_TEST_SEED = 20_260_728


class DeterministicFakeTestKit:
    def __init__(
        self,
        *,
        seed: int = DEFAULT_TEST_SEED,
        node_count: int = 8,
    ) -> None:
        self.seed = seed
        self.nodes: tuple[SyntheticNode, ...] = synthetic_nodes(
            node_count,
            seed=seed,
        )
        self.clock = FakeClock(seed=seed)
        self.filesystem = FakeFilesystem()
        self.processes = FakeProcessTable(seed=seed)
        self.credentials = FakeCredentialStore()
        self.desktop = FakeDesktopHost()
        self.singleton = FakeSingleton()
        self.shutdown_fallback = FakeShutdownFallback()
        self.privilege = FakePrivilegeBoundary()
        self.http = FakeHttpTransport()
        self.ray = FakeRayAdapter(self.nodes)
        self.sensor = FakeSensor()
        for index, node in enumerate(self.nodes):
            baseline = node.sensor_baseline
            self.sensor.set_series(
                node.node_id,
                (
                    FakeSensorReading(baseline, (index * 7) % 101),
                    FakeSensorReading(baseline + 1, (index * 7 + 11) % 101),
                ),
            )
        self.guard = NoLiveAccessGuard()
        self.closed = False

    def __enter__(self) -> DeterministicFakeTestKit:
        if self.closed:
            raise RuntimeError("deterministic fake test kit is closed")
        self.guard.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        try:
            self._clear_fakes()
        finally:
            self.guard.__exit__(exc_type, exc, traceback)
            self.closed = True
        return False

    def _clear_fakes(self) -> None:
        self.clock.reset()
        self.filesystem.clear()
        self.processes.clear()
        self.credentials.clear()
        self.desktop.dispose()
        self.singleton.clear()
        self.shutdown_fallback.clear()
        self.privilege.clear()
        self.http.clear()
        self.ray.clear()
        self.sensor.clear()
        self.nodes = ()

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._clear_fakes()
        finally:
            if self.guard.active:
                self.guard.__exit__(None, None, None)
            self.closed = True

    def snapshot(self) -> dict[str, object]:
        if self.closed:
            raise RuntimeError("deterministic fake test kit is closed")
        return {
            "seed": self.seed,
            "nodes": nodes_snapshot(self.nodes),
            "clock": self.clock.snapshot(),
            "filesystem": self.filesystem.snapshot(),
            "processes": self.processes.snapshot(),
            "credentials": self.credentials.snapshot(),
            "http": self.http.snapshot(),
            "ray": self.ray.snapshot(),
            "sensor": self.sensor.snapshot(),
        }

    def fingerprint(self) -> str:
        canonical = json.dumps(
            self.snapshot(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()

    def resource_count(self) -> int:
        return sum(
            (
                len(self.nodes),
                self.clock.resource_count(),
                self.filesystem.resource_count(),
                self.processes.resource_count(),
                self.credentials.resource_count(),
                self.desktop.resource_count(),
                self.singleton.resource_count(),
                self.shutdown_fallback.resource_count(),
                self.privilege.resource_count(),
                self.http.resource_count(),
                self.ray.resource_count(),
                self.sensor.resource_count(),
                self.guard.resource_count(),
            )
        )
