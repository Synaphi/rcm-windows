"""Compact deterministic status-board presentation."""

from __future__ import annotations

from dataclasses import dataclass

from .state import RenderState
from .status_content import cluster_summary, node_status_line


@dataclass(frozen=True, slots=True)
class StatusBoardModel:
    headline: str
    lines: tuple[str, ...]
    severity: str


class StatusBoardView:
    def __init__(self, *, maximum_lines: int = 34) -> None:
        if type(maximum_lines) is not int or not 1 <= maximum_lines <= 64:
            raise ValueError("maximum_lines must be between 1 and 64")
        self._maximum_lines = maximum_lines

    def render(self, state: RenderState) -> StatusBoardModel:
        if not isinstance(state, RenderState):
            raise TypeError("state must be a RenderState")
        result = state.last_result
        severity = (
            "error" if result is not None and not result.ok
            else "busy" if state.busy
            else "normal"
        )
        rows = tuple(node_status_line(node) for node in state.nodes)
        return StatusBoardModel(
            headline=cluster_summary(state.nodes),
            lines=rows[: self._maximum_lines],
            severity=severity,
        )
