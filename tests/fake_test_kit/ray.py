from __future__ import annotations

from dataclasses import asdict, dataclass, replace

from .nodes import SyntheticNode


@dataclass(frozen=True, slots=True)
class FakeRayNodeState:
    node_id: str
    role: str
    state: str = "stopped"
    head_id: str | None = None

    def snapshot(self) -> dict[str, str | None]:
        return asdict(self)


class FakeRayAdapter:
    def __init__(self, nodes: tuple[SyntheticNode, ...]) -> None:
        if not nodes:
            raise ValueError("fake Ray adapter requires at least one node")
        if len({node.node_id for node in nodes}) != len(nodes):
            raise ValueError("fake Ray node identifiers must be unique")
        if sum(node.role == "head" for node in nodes) != 1:
            raise ValueError("fake Ray topology must contain exactly one head")
        if any(node.role not in {"head", "worker"} for node in nodes):
            raise ValueError("fake Ray roles must be head or worker")
        self._states = {
            node.node_id: FakeRayNodeState(node.node_id, node.role)
            for node in nodes
        }
        self._events: list[tuple[str, str, str | None]] = []

    def state(self, node_id: str) -> FakeRayNodeState:
        try:
            return self._states[node_id]
        except KeyError as exc:
            raise LookupError("unknown fake Ray node") from exc

    def start_head(self, node_id: str) -> FakeRayNodeState:
        current = self.state(node_id)
        if current.role != "head":
            raise ValueError("only the synthetic head can start a fake cluster")
        if current.state != "stopped":
            raise ValueError("fake Ray node is already active")
        updated = replace(current, state="head", head_id=node_id)
        self._states[node_id] = updated
        self._events.append(("start_head", node_id, None))
        return updated

    def join_worker(
        self,
        node_id: str,
        *,
        head_id: str,
    ) -> FakeRayNodeState:
        current = self.state(node_id)
        head = self.state(head_id)
        if current.role != "worker":
            raise ValueError("synthetic head cannot join as a worker")
        if current.state != "stopped":
            raise ValueError("fake Ray node is already active")
        if head.state != "head":
            raise ValueError("fake Ray head must be active before join")
        updated = replace(current, state="worker", head_id=head_id)
        self._states[node_id] = updated
        self._events.append(("join_worker", node_id, head_id))
        return updated

    def stop(self, node_id: str) -> FakeRayNodeState:
        current = self.state(node_id)
        if current.state == "stopped":
            raise ValueError("fake Ray node is already stopped")
        updated = replace(current, state="stopped", head_id=None)
        self._states[node_id] = updated
        self._events.append(("stop", node_id, None))
        return updated

    def active_nodes(self) -> tuple[FakeRayNodeState, ...]:
        return tuple(
            self._states[node_id]
            for node_id in sorted(self._states)
            if self._states[node_id].state != "stopped"
        )

    def clear(self) -> None:
        self._states.clear()
        self._events.clear()

    def snapshot(self) -> dict[str, object]:
        return {
            "states": [
                self._states[node_id].snapshot()
                for node_id in sorted(self._states)
            ],
            "events": [list(event) for event in self._events],
        }

    def resource_count(self) -> int:
        return len(self._states)
