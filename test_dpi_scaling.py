"""Regression tests for stable text scale across RDP resolution changes.

Pytest-free (mirrors test_stale_owner_recovery.py): plain asserts + a main()
that prints JSON and returns an exit code. Wired into build.ps1 (runs before
PyInstaller) and verify_release.py, so the build FAILS if the scaling invariant
regresses.

The invariant it pins: when Windows reports a valid effective DPI, resolution
must not influence text size. Screen width remains a fallback only when DPI is
unavailable; geometry is fitted separately.
"""
import json
import sys

import ray_monitor as rm

FLOOR = rm.AUTO_UI_SCALING_FLOOR   # 96/72 = 1.3333...
CEIL = rm.AUTO_UI_SCALING_CEILING  # 3.0


def approx(a, b, tol=5e-4):
    # tol >= 5e-4 because round(_, 3) puts the floor at 1.333, ~3.3e-4 below
    # the unrounded 96/72.
    return abs(float(a) - float(b)) <= tol


def test_comfort_floor_tiers():
    for sw, exp in [(3840, 2.00), (5120, 2.00), (3839, 1.67), (2560, 1.67),
                    (2559, 1.50), (1920, 1.50), (1919, FLOOR), (1366, FLOOR),
                    (1024, FLOOR)]:
        got = rm.comfort_floor_for_screen(sw)
        assert approx(got, exp), f"comfort_floor_for_screen({sw})={got} != {exp}"


def test_fit_scale_matrix():
    for dpi, sw, exp in [(96, 3840, FLOOR), (120, 3840, 1.667), (144, 3840, 2.0),
                         (192, 3840, 2.667), (216, 3840, 3.0), (288, 3840, 3.0),
                         (144, 2560, 2.0), (96, 2560, FLOOR), (96, 1920, FLOOR),
                         (96, 1366, FLOOR), (None, 3840, 2.0), (0, 3840, 2.0)]:
        got = rm.fit_scale(dpi, sw)
        assert approx(got, exp), f"fit_scale({dpi},{sw})={got} != {exp}"


def test_fit_width_matrix():
    for scale, sw, exp in [(2.0, 3840, 1680), (1.5, 1920, 1260),
                           (FLOOR, 1366, 1120), (2.667, 3840, 2240),
                           (3.0, 3840, 2520), (1.67, 2560, 1403)]:
        got = rm.fit_width(scale, sw)
        assert got == exp, f"fit_width({scale},{sw})={got} != {exp}"


def test_resolution_does_not_change_text_scale_when_dpi_known():
    for dpi in (96, 120, 144, 192, 216):
        values = {rm.fit_scale(dpi, width)
                  for width in (1024, 1366, 1920, 2560, 2880, 3840, 5120)}
        assert len(values) == 1, f"dpi={dpi} changed with resolution: {values}"
    # Width tiers remain only as the no-DPI fallback.
    assert approx(rm.fit_scale(None, 3840), 2.0)
    assert approx(rm.fit_scale(None, 1920), 1.5)
    assert approx(rm.fit_scale(96, 3840), FLOOR)
    # Clamp bounds hold.
    assert approx(rm.clamp_scaling(0.1), FLOOR) and approx(rm.clamp_scaling(99), CEIL)
    assert approx(rm.clamp_scaling(float("nan")), FLOOR)


def test_pure_functions_are_wired():
    # Anti-drift: the GUI must delegate to these pure functions so they cannot
    # diverge from shipped behavior. Fails if the refactor is reverted.
    src = open(rm.__file__, encoding="utf-8").read()
    for needle in ("def comfort_floor_for_screen(", "def fit_scale(",
                   "def fit_width(", "def clamp_scaling(",
                   "def _fit_to_monitor(", "def _auto_fit_monitor("):
        assert needle in src, f"missing required definition: {needle}"
    # The GUI methods must delegate, not re-implement.
    assert "return clamp_scaling(value)" in src, "_clamped_ui_scaling must delegate"
    assert "return comfort_floor_for_screen(screen_w)" in src, \
        "_comfort_floor_scaling must delegate"


def main():
    tests = [test_comfort_floor_tiers, test_fit_scale_matrix, test_fit_width_matrix,
             test_resolution_does_not_change_text_scale_when_dpi_known,
             test_pure_functions_are_wired]
    results, failed = [], 0
    for t in tests:
        try:
            t()
            results.append({"test": t.__name__, "ok": True})
        except AssertionError as e:
            failed += 1
            results.append({"test": t.__name__, "ok": False, "error": str(e)})
    print(json.dumps({"suite": "dpi_scaling", "version": rm.APP_VERSION,
                      "passed": len(tests) - failed, "failed": failed,
                      "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
