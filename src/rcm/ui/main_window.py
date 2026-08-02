"""Declarative model for the compact classic main window."""

from __future__ import annotations

from dataclasses import dataclass

from .status_content import node_status_line
from .state import CommandKind, RenderState, Surface


@dataclass(frozen=True, slots=True)
class MainAction:
    label: str
    command: CommandKind
    surface: Surface | None = None
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class MainWindowModel:
    title: str
    status: str
    node_lines: tuple[str, ...]
    actions: tuple[MainAction, ...]
    selected_node_id: str
    busy: bool


class MainWindowView:
    _ACTIONS = (
        MainAction("Start", CommandKind.START),
        MainAction("Stop", CommandKind.STOP),
        MainAction("Restart", CommandKind.RESTART),
        MainAction("Status", CommandKind.OPEN_SURFACE, Surface.STATUS),
        MainAction("Settings", CommandKind.OPEN_SURFACE, Surface.SETTINGS),
        MainAction("Node", CommandKind.OPEN_SURFACE, Surface.NODE),
        MainAction("Remote Desktop", CommandKind.OPEN_SURFACE, Surface.RDP),
        MainAction("Cleanup", CommandKind.OPEN_SURFACE, Surface.CLEANUP),
        MainAction("Help", CommandKind.OPEN_SURFACE, Surface.HELP),
    )

    def render(self, state: RenderState) -> MainWindowModel:
        if not isinstance(state, RenderState):
            raise TypeError("state must be a RenderState")
        actions = tuple(
            MainAction(
                action.label,
                action.command,
                action.surface,
                enabled=(
                    not state.busy
                    and (
                        action.surface is None
                        or action.surface not in {Surface.NODE, Surface.RDP}
                        or bool(state.selected_node_id)
                    )
                ),
            )
            for action in self._ACTIONS
        )
        return MainWindowModel(
            title="Ray Cluster Manager",
            status=state.status_message,
            node_lines=tuple(node_status_line(node) for node in state.nodes),
            actions=actions,
            selected_node_id=state.selected_node_id,
            busy=state.busy,
        )
