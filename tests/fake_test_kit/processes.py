from __future__ import annotations

from dataclasses import asdict, dataclass, replace


@dataclass(frozen=True, slots=True)
class FakeProcess:
    pid: int
    name: str
    arguments: tuple[str, ...]
    running: bool = True
    exit_code: int | None = None

    def snapshot(self) -> dict[str, object]:
        data = asdict(self)
        data["arguments"] = list(self.arguments)
        return data


class FakeProcessTable:
    def __init__(self, *, seed: int) -> None:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ValueError("seed must be a non-negative integer")
        self._next_pid = 10_000 + seed % 10_000
        self._processes: dict[int, FakeProcess] = {}
        self._events: list[tuple[str, int]] = []

    def spawn(
        self,
        name: str,
        arguments: tuple[str, ...] = (),
        *,
        pid: int | None = None,
    ) -> FakeProcess:
        if not isinstance(name, str) or not name:
            raise ValueError("process name must be a non-empty string")
        if (
            not isinstance(arguments, tuple)
            or any(not isinstance(argument, str) for argument in arguments)
        ):
            raise ValueError("process arguments must be a tuple of strings")
        selected_pid = self._next_pid if pid is None else pid
        if (
            isinstance(selected_pid, bool)
            or not isinstance(selected_pid, int)
            or selected_pid <= 0
        ):
            raise ValueError("pid must be a positive integer")
        if selected_pid in self._processes:
            raise ValueError("pid already exists")
        if pid is None:
            self._next_pid += 1
        process = FakeProcess(selected_pid, name, tuple(arguments))
        self._processes[selected_pid] = process
        self._events.append(("spawn", selected_pid))
        return process

    def get(self, pid: int) -> FakeProcess:
        try:
            return self._processes[pid]
        except KeyError as exc:
            raise ProcessLookupError(pid) from exc

    def running(self) -> tuple[FakeProcess, ...]:
        return tuple(
            self._processes[pid]
            for pid in sorted(self._processes)
            if self._processes[pid].running
        )

    def terminate(self, pid: int, *, exit_code: int = 0) -> FakeProcess:
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise ValueError("exit code must be an integer")
        process = self.get(pid)
        if not process.running:
            raise ProcessLookupError(pid)
        terminated = replace(process, running=False, exit_code=exit_code)
        self._processes[pid] = terminated
        self._events.append(("terminate", pid))
        return terminated

    def clear(self) -> None:
        self._processes.clear()
        self._events.clear()

    def snapshot(self) -> dict[str, object]:
        return {
            "processes": [
                self._processes[pid].snapshot()
                for pid in sorted(self._processes)
            ],
            "events": [list(event) for event in self._events],
        }

    def resource_count(self) -> int:
        return len(self._processes)
