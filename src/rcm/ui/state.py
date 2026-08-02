"""Immutable, non-secret desktop render state and typed UI events."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import math, re
from typing import TypeAlias


_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FORBIDDEN_FIELD_PARTS = ("password", "secret", "credential_value")
_MAX_TEXT = 2_048
_MAX_FIELDS = 32


class UiVisibility(StrEnum):
    VISIBLE = "visible"
    MINIMIZED = "minimized"
    HIDDEN = "hidden"


class LifecyclePhase(StrEnum):
    NEW = "new"
    STARTING = "starting"
    RUNNING = "running"
    RESTARTING = "restarting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class Surface(StrEnum):
    MAIN = "main"
    STATUS = "status"
    SETTINGS = "settings"
    NODE = "node"
    RDP = "rdp"
    CLEANUP = "cleanup"
    HELP = "help"


class CommandKind(StrEnum):
    SHOW = "show"
    HIDE = "hide"
    MINIMIZE = "minimize"
    OPEN_SURFACE = "open_surface"
    CLOSE_SURFACE = "close_surface"
    SAVE_SETTINGS = "save_settings"
    UPSERT_NODE = "upsert_node"
    REMOVE_NODE = "remove_node"
    OPEN_RDP = "open_rdp"
    APPLY_RDP_HOST = "apply_rdp_host"
    APPLY_PRIVATE_FIREWALL = "apply_private_firewall"
    SCAN_CLEANUP = "scan_cleanup"
    APPLY_CLEANUP = "apply_cleanup"
    START = "start"
    STOP = "stop"
    RESTART = "restart"
    SET_AUTOSTART = "set_autostart"
    QUIT = "quit"


class ResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


FieldValue: TypeAlias = str | int | float | bool | None
Fields: TypeAlias = tuple[tuple[str, FieldValue], ...]


def _text(value: object, name: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    if (not allow_empty and not value) or len(value) > _MAX_TEXT:
        raise ValueError(f"{name} has an invalid length")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _field_value(value: object) -> FieldValue:
    if value is None or type(value) in {str, int, float, bool}:
        if isinstance(value, str):
            return _text(value, "field value")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("numeric field values must be finite")
        return value
    raise TypeError("field values must be scalar presentation values")


def safe_fields(values: Fields = ()) -> Fields:
    if type(values) is not tuple or len(values) > _MAX_FIELDS:
        raise ValueError(f"fields must be a tuple with at most {_MAX_FIELDS} items")
    result: list[tuple[str, FieldValue]] = []
    seen: set[str] = set()
    for item in values:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError("fields must contain two-item tuples")
        key, value = item
        if not isinstance(key, str) or _FIELD_NAME.fullmatch(key) is None:
            raise ValueError("field names must be safe lowercase identifiers")
        if any(part in key for part in _FORBIDDEN_FIELD_PARTS):
            raise ValueError("secret-bearing UI fields are forbidden")
        if key in seen:
            raise ValueError("field names must be unique")
        seen.add(key)
        result.append((key, _field_value(value)))
    return tuple(result)


@dataclass(frozen=True, slots=True, repr=False)
class UiCommand:
    command_id: int
    kind: CommandKind
    fields: Fields = ()

    def __post_init__(self) -> None:
        if type(self.command_id) is not int or self.command_id < 0:
            raise ValueError("command_id must be a non-negative integer")
        if not isinstance(self.kind, CommandKind):
            raise TypeError("kind must be a CommandKind")
        object.__setattr__(self, "fields", safe_fields(self.fields))

    def field(self, name: str, default: FieldValue = None) -> FieldValue:
        return dict(self.fields).get(name, default)


@dataclass(frozen=True, slots=True, repr=False)
class CommandResult:
    command_id: int
    status: ResultStatus
    code: str
    message: str = ""
    fields: Fields = ()

    def __post_init__(self) -> None:
        if type(self.command_id) is not int or self.command_id < 0:
            raise ValueError("command_id must be a non-negative integer")
        if not isinstance(self.status, ResultStatus):
            raise TypeError("status must be a ResultStatus")
        if not isinstance(self.code, str) or _FIELD_NAME.fullmatch(self.code) is None:
            raise ValueError("result code must be a safe lowercase identifier")
        _text(self.message, "result message")
        object.__setattr__(self, "fields", safe_fields(self.fields))

    @property
    def ok(self) -> bool:
        return self.status is ResultStatus.SUCCEEDED


@dataclass(frozen=True, slots=True, repr=False)
class NodeRenderState:
    node_id: str
    name: str
    role: str
    status: str
    cpu_percent: float | None = None
    memory_percent: float | None = None
    temperature_celsius: float | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("node_id", self.node_id),
            ("name", self.name),
            ("role", self.role),
            ("status", self.status),
        ):
            _text(value, name, allow_empty=False)
        for name, value in (
            ("cpu_percent", self.cpu_percent),
            ("memory_percent", self.memory_percent),
            ("temperature_celsius", self.temperature_celsius),
        ):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} must be finite or None")


@dataclass(frozen=True, slots=True, repr=False)
class SettingsRenderState:
    theme: str = "system"
    scale_percent: int = 100
    compact_view: bool = False
    start_minimized: bool = False
    autostart: bool = False
    monitoring_interval_ms: int = 1_000

    def __post_init__(self) -> None:
        _text(self.theme, "theme", allow_empty=False)
        if type(self.scale_percent) is not int or not 50 <= self.scale_percent <= 300:
            raise ValueError("scale_percent must be between 50 and 300")
        if type(self.monitoring_interval_ms) is not int or not (
            100 <= self.monitoring_interval_ms <= 3_600_000
        ):
            raise ValueError("monitoring_interval_ms is outside its supported range")
        for name in ("compact_view", "start_minimized", "autostart"):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")


@dataclass(frozen=True, slots=True, repr=False)
class RenderState:
    revision: int = 0
    lifecycle: LifecyclePhase = LifecyclePhase.NEW
    visibility: UiVisibility = UiVisibility.VISIBLE
    active_surface: Surface = Surface.MAIN
    busy: bool = False
    status_message: str = "Ready"
    nodes: tuple[NodeRenderState, ...] = ()
    selected_node_id: str = ""
    settings: SettingsRenderState = SettingsRenderState()
    open_surfaces: tuple[Surface, ...] = ()
    last_result: CommandResult | None = None
    queue_depth: int = 0
    dropped_events: int = 0
    forced_shutdown: bool = False

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision must be a non-negative integer")
        if not isinstance(self.lifecycle, LifecyclePhase):
            raise TypeError("lifecycle must be a LifecyclePhase")
        if not isinstance(self.visibility, UiVisibility):
            raise TypeError("visibility must be a UiVisibility")
        if not isinstance(self.active_surface, Surface):
            raise TypeError("active_surface must be a Surface")
        if type(self.busy) is not bool or type(self.forced_shutdown) is not bool:
            raise TypeError("render flags must be bool values")
        _text(self.status_message, "status_message")
        nodes = tuple(self.nodes)
        if any(not isinstance(node, NodeRenderState) for node in nodes):
            raise TypeError("nodes must contain NodeRenderState values")
        identifiers = tuple(node.node_id for node in nodes)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("node identifiers must be unique")
        if self.selected_node_id and self.selected_node_id not in identifiers:
            raise ValueError("selected_node_id must identify a rendered node")
        if not isinstance(self.settings, SettingsRenderState):
            raise TypeError("settings must be a SettingsRenderState")
        surfaces = tuple(self.open_surfaces)
        if any(not isinstance(item, Surface) for item in surfaces):
            raise TypeError("open_surfaces must contain Surface values")
        if len(surfaces) != len(set(surfaces)):
            raise ValueError("open_surfaces must be unique")
        if self.last_result is not None and not isinstance(
            self.last_result, CommandResult
        ):
            raise TypeError("last_result must be a CommandResult or None")
        for name in ("queue_depth", "dropped_events"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "open_surfaces", surfaces)

    def evolve(self, **changes: object) -> RenderState:
        changes.setdefault("revision", self.revision + 1)
        return replace(self, **changes)


@dataclass(frozen=True, slots=True, repr=False)
class SnapshotEvent:
    state: RenderState

    def __post_init__(self) -> None:
        if not isinstance(self.state, RenderState):
            raise TypeError("state must be a RenderState")


@dataclass(frozen=True, slots=True, repr=False)
class ResultEvent:
    result: CommandResult

    def __post_init__(self) -> None:
        if not isinstance(self.result, CommandResult):
            raise TypeError("result must be a CommandResult")


UiEvent: TypeAlias = SnapshotEvent | ResultEvent


def reduce_event(state: RenderState, event: UiEvent) -> RenderState:
    if isinstance(event, SnapshotEvent):
        return event.state if event.state.revision >= state.revision else state
    if isinstance(event, ResultEvent):
        return state.evolve(
            busy=False,
            last_result=event.result,
            status_message=event.result.message or event.result.code,
        )
    raise TypeError("event must be a typed UI event")
