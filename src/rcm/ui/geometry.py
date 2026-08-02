"""Pure DPI and monitor geometry calculations for the desktop UI."""

from __future__ import annotations

from dataclasses import dataclass
import math


AUTO_UI_SCALING_FLOOR = 96.0 / 72.0
AUTO_UI_SCALING_CEILING = 3.0
MAIN_BASE_WIDTH = 1_120
MAIN_MIN_WIDTH = 620


@dataclass(frozen=True, slots=True)
class WorkArea:
    x: int
    y: int
    width: int
    height: int

    def __post_init__(self) -> None:
        if type(self.width) is not int or type(self.height) is not int:
            raise TypeError("work area dimensions must be integers")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("work area dimensions must be positive")


@dataclass(frozen=True, slots=True)
class WindowGeometry:
    x: int
    y: int
    width: int
    height: int
    desired_width: int
    desired_height: int
    horizontal_scroll: bool
    vertical_scroll: bool
    visible_rows: int

    def to_dict(self) -> dict[str, int | bool]:
        return {
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "desired_width": self.desired_width,
            "desired_height": self.desired_height,
            "horizontal_scroll": self.horizontal_scroll,
            "vertical_scroll": self.vertical_scroll,
            "visible_rows": self.visible_rows,
        }


def comfort_floor_for_screen(
    screen_width: object,
    floor: float = AUTO_UI_SCALING_FLOOR,
) -> float:
    try:
        width = int(screen_width)
    except (TypeError, ValueError, OverflowError):
        return floor
    tier = (
        2.0 if width >= 3_840
        else 1.67 if width >= 2_560
        else 1.5 if width >= 1_920
        else floor
    )
    return max(floor, tier)


def clamp_scaling(
    value: object,
    floor: float = AUTO_UI_SCALING_FLOOR,
    ceiling: float = AUTO_UI_SCALING_CEILING,
) -> float:
    try:
        measured = float(value)
    except (TypeError, ValueError, OverflowError):
        return floor
    if not math.isfinite(measured) or measured <= 0:
        return floor
    return max(floor, min(ceiling, measured))


def fit_scale(dpi: object, screen_width: object) -> float:
    try:
        measured_dpi = float(dpi or 0.0)
    except (TypeError, ValueError, OverflowError):
        measured_dpi = 0.0
    measured = (
        clamp_scaling(measured_dpi / 72.0)
        if math.isfinite(measured_dpi) and measured_dpi > 0
        else clamp_scaling(comfort_floor_for_screen(screen_width))
    )
    return round(measured, 3)


def fit_width(
    scale: float,
    screen_width: object,
    base_width: int = MAIN_BASE_WIDTH,
    minimum_width: int = MAIN_MIN_WIDTH,
) -> int:
    scaled = round(base_width * (float(scale) / AUTO_UI_SCALING_FLOOR))
    try:
        screen_max = max(minimum_width, int(screen_width) - 40)
    except (TypeError, ValueError, OverflowError):
        screen_max = scaled
    return max(minimum_width, min(scaled, screen_max))


def scaled_px(pixels: int, scale: float) -> int:
    try:
        return round(int(pixels) * float(scale) / AUTO_UI_SCALING_FLOOR)
    except (TypeError, ValueError, OverflowError):
        return int(pixels)


def content_fit_geometry(
    text_width_px: int,
    char_width_px: int,
    node_count: int,
    row_height_px: int,
    chrome_width_px: int,
    chrome_height_px: int,
    work_area: WorkArea | tuple[int, int, int, int],
    current_xy: tuple[int, int] = (0, 0),
    min_size: tuple[int, int] = (620, 430),
    right_margin_chars: int = 2,
    spare_rows: int = 1,
    vertical_scrollbar_width_px: int = 0,
    horizontal_scrollbar_height_px: int = 0,
) -> WindowGeometry:
    if isinstance(work_area, WorkArea):
        area = work_area
    else:
        try:
            area = WorkArea(*(int(value) for value in work_area))
        except (TypeError, ValueError):
            area = WorkArea(0, 0, 1_920, 1_080)
    minimum_w, minimum_h = (max(1, int(value)) for value in min_size)
    rows = max(0, int(node_count)) + max(0, int(spare_rows))
    base_width = max(
        minimum_w,
        int(chrome_width_px) + max(0, int(text_width_px))
        + max(0, int(right_margin_chars)) * max(1, int(char_width_px)),
    )
    base_height = max(
        minimum_h,
        int(chrome_height_px) + rows * max(1, int(row_height_px)),
    )
    vertical_bar = max(0, int(vertical_scrollbar_width_px))
    horizontal_bar = max(0, int(horizontal_scrollbar_height_px))
    horizontal = base_width > area.width
    vertical = base_height > area.height
    for _iteration in range(2):
        horizontal |= base_width + (vertical_bar if vertical else 0) > area.width
        vertical |= base_height + (horizontal_bar if horizontal else 0) > area.height
    desired_width = base_width + (vertical_bar if vertical else 0)
    desired_height = base_height + (horizontal_bar if horizontal else 0)
    width = min(desired_width, area.width)
    height = min(desired_height, area.height)
    try:
        current_x, current_y = (int(value) for value in current_xy)
    except (TypeError, ValueError):
        current_x, current_y = area.x, area.y
    x = max(area.x, min(current_x, area.x + area.width - width))
    y = max(area.y, min(current_y, area.y + area.height - height))
    return WindowGeometry(
        x, y, width, height, desired_width, desired_height,
        horizontal, vertical, rows,
    )
