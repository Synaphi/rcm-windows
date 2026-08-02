"""Import-safe desktop UI contracts."""

from typing import TYPE_CHECKING

from .geometry import (
    WorkArea,
    WindowGeometry,
    content_fit_geometry,
    fit_scale,
    fit_width,
    scaled_px,
)
from .state import (
    CommandKind,
    CommandResult,
    LifecyclePhase,
    NodeRenderState,
    RenderState,
    ResultStatus,
    SettingsRenderState,
    Surface,
    UiCommand,
    UiVisibility,
)

if TYPE_CHECKING:
    from .app import UiApplication


def __getattr__(name: str) -> object:
    if name == "UiApplication":
        from .app import UiApplication

        return UiApplication
    raise AttributeError(name)


__all__ = (
    "CommandKind",
    "CommandResult",
    "LifecyclePhase",
    "NodeRenderState",
    "RenderState",
    "ResultStatus",
    "SettingsRenderState",
    "Surface",
    "UiApplication",
    "UiCommand",
    "UiVisibility",
    "WindowGeometry",
    "WorkArea",
    "content_fit_geometry",
    "fit_scale",
    "fit_width",
    "scaled_px",
)
