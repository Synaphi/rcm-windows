from __future__ import annotations

import unittest

from rcm.ui.geometry import (
    WorkArea,
    clamp_scaling,
    comfort_floor_for_screen,
    content_fit_geometry,
    fit_scale,
    fit_width,
    scaled_px,
)


class GeometryTests(unittest.TestCase):
    def test_frozen_dpi_scale_values(self) -> None:
        self.assertEqual(1.333, fit_scale(96, 1366))
        self.assertEqual(1.667, fit_scale(120, 1920))
        self.assertEqual(2.0, fit_scale(144, 3840))
        self.assertEqual(2.667, fit_scale(192, 1366))
        self.assertEqual(3.0, fit_scale(240, 3840))

    def test_invalid_dpi_uses_resolution_only_as_fallback(self) -> None:
        self.assertEqual(2.0, fit_scale(None, 3840))
        self.assertEqual(1.5, fit_scale(float("nan"), 1920))
        self.assertAlmostEqual(96 / 72, comfort_floor_for_screen("bad"))
        self.assertAlmostEqual(96 / 72, clamp_scaling(-1))

    def test_frozen_width_values(self) -> None:
        self.assertEqual(1120, fit_width(96 / 72, 1920))
        self.assertEqual(1680, fit_width(2.0, 3840))
        self.assertEqual(760, fit_width(3.0, 800))
        self.assertEqual(150, scaled_px(100, 2.0))

    def test_compact_content_fit_contract(self) -> None:
        geometry = content_fit_geometry(
            700,
            8,
            5,
            18,
            100,
            300,
            WorkArea(0, 0, 1920, 1080),
            current_xy=(30, 40),
        )
        self.assertEqual(
            {
                "x": 30,
                "y": 40,
                "width": 816,
                "height": 430,
                "desired_width": 816,
                "desired_height": 430,
                "horizontal_scroll": False,
                "vertical_scroll": False,
                "visible_rows": 6,
            },
            geometry.to_dict(),
        )

    def test_clamped_content_fit_propagates_both_scrollbars(self) -> None:
        geometry = content_fit_geometry(
            2_100,
            9,
            50,
            20,
            120,
            260,
            WorkArea(1920, -200, 1366, 728),
            current_xy=(4000, -900),
        )
        self.assertEqual(
            {
                "x": 1920,
                "y": -200,
                "width": 1366,
                "height": 728,
                "desired_width": 2238,
                "desired_height": 1280,
                "horizontal_scroll": True,
                "vertical_scroll": True,
                "visible_rows": 51,
            },
            geometry.to_dict(),
        )


if __name__ == "__main__":
    unittest.main()
