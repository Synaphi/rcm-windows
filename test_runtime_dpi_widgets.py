"""Headed Windows/Tk regressions for live RDP DPI/font/layout recovery."""
import copy
import json
import time
import tkinter as tk
from contextlib import ExitStack
from unittest import mock

import ray_monitor as rm


def _destroy_cleanly(widget):
    """Cancel pending callbacks so another headed test can reuse Tcl safely."""
    try:
        for after_id in widget.tk.call("after", "info"):
            try:
                widget.after_cancel(after_id)
            except tk.TclError:
                pass
        widget.update_idletasks()
    finally:
        widget.destroy()


def _metric_snapshot(app, widgets):
    app.update_idletasks()
    return {
        "default_w": app._ui_fonts["default"].measure("Remote Desktop"),
        "bold_h": app._ui_fonts["bold"].metrics("linespace"),
        "mono_w": app._ui_fonts["mono"].measure("0000000000"),
        "diag_h": app._ui_fonts["diag"].metrics("linespace"),
        "label_req": (widgets[0].winfo_reqwidth(), widgets[0].winfo_reqheight()),
        "button_req": (widgets[1].winfo_reqwidth(), widgets[1].winfo_reqheight()),
        "list_req": (widgets[2].winfo_reqwidth(), widgets[2].winfo_reqheight()),
    }


def _set_scale(app, value):
    app.tk.call("tk", "scaling", float(value))
    app._refresh_ui_fonts()
    app.update_idletasks()


def test_named_fonts_follow_live_scaling_and_round_trip():
    app = rm.RayApp.__new__(rm.RayApp)
    tk.Tk.__init__(app)
    try:
        app.withdraw()
        app.cfg = {"diagnostic_font": "Consolas"}
        app._closing = False
        app._ui_fonts = {}
        app._init_ui_fonts()
        app.option_add("*Font", "RCMDefaultFont")
        label = tk.Label(app, text="Remote Desktop")
        button = tk.Button(app, text="Fit Screen", font=app._font_name("bold"))
        listing = tk.Listbox(app, font=app._font_name("mono"), width=20, height=2)
        listing.insert("end", "SYNTHETIC_NODE_G  0/16  49C")
        widgets = (label, button, listing)
        for widget in widgets:
            widget.pack()

        _set_scale(app, 2.0)
        low = _metric_snapshot(app, widgets)
        _set_scale(app, 2.667)
        high = _metric_snapshot(app, widgets)
        assert high["default_w"] > low["default_w"]
        assert high["bold_h"] > low["bold_h"]
        assert high["mono_w"] > low["mono_w"]
        assert high["diag_h"] > low["diag_h"]
        assert high["label_req"][0] > low["label_req"][0]
        assert high["button_req"][1] > low["button_req"][1]
        assert high["list_req"][0] > low["list_req"][0]

        _set_scale(app, 2.0)
        restored = _metric_snapshot(app, widgets)
        for key in ("default_w", "bold_h", "mono_w", "diag_h"):
            assert abs(restored[key] - low[key]) <= 1, (key, low[key], restored[key])
        for key in ("label_req", "button_req", "list_req"):
            assert all(abs(a - b) <= 1 for a, b in zip(restored[key], low[key])), \
                (key, low[key], restored[key])
    finally:
        _destroy_cleanly(app)


def test_fit_screen_repeated_clicks_are_geometry_idempotent():
    """A monitor-width prefit must not race the expanding node Listbox.

    The packaged 1.07.22a live log showed consecutive Fit Screen clicks
    alternating between 968px and 1680px.  This headed test gives Tk time to
    deliver each real Configure event, so the former implementation fails in
    the same way instead of hiding the race behind pure geometry tests.
    """
    cfg = copy.deepcopy(rm.DEFAULT_CONFIG)
    cfg.update({
        "main_width": 968,
        "start_on_launch": False,
        "autostart_login": False,
        "temp_enabled": False,
        "metrics_enabled": False,
        "watchdog_enabled": False,
    })
    app = None
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(rm, "load_config", return_value=cfg))
        # Fit Screen persists its final width in production.  This headed test
        # uses a synthetic config and must never overwrite the operator's real
        # %APPDATA% config while exercising that path.
        stack.enter_context(mock.patch.object(
            rm, "save_config", lambda _cfg: None))
        for name in (
                "_start_monitor", "_build_tray", "_sync_metrics_runtime",
                "_sync_watchdog_runtime", "_check_ray_exe",
                "_schedule_ui_scaling_guard", "_schedule_duplicate_guard",
                "_auto_fit_startup"):
            stack.enter_context(mock.patch.object(
                rm.RayApp, name, lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(
            rm.RayApp, "apply_login_autostart",
            lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(
            rm.RayApp, "_log", lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(rm, "_HAS_SENSOR", False))
        stack.enter_context(mock.patch.object(rm, "_HAS_TRAY", False))
        try:
            app = rm.RayApp()
            app._monitor_dpi_for_window = lambda: 144.0
            app._monitor_width_for_window = lambda: 3840
            app._monitor_work_area_for_window = lambda: (0, 0, 3840, 2088)
            app.nodes_header.configure(
                text="Node R Ray | CPU Tmp | RAM | Disk C: / SSD | D/U/s | Png | Cn")
            app.nodes_list.delete(0, "end")
            for index in range(7):
                app.nodes_list.insert(
                    "end", f"node{index} W 0/16 | 3% 49° | 8/22 | "
                    "C [##--]38% 46° | 22K/14K | 32 | Wi:TP_Miho_5")
            app.geometry("968x541+100+100")
            app.update()

            widths = []
            for _ in range(5):
                app._do_fit_monitor()
                app.update()
                time.sleep(0.06)
                app.update()
                widths.append(int(app.winfo_width()))
            assert max(widths) - min(widths) <= 1, widths
        finally:
            if app is not None:
                app._closing = True
                _destroy_cleanly(app)


def test_fit_screen_keeps_full_action_row_visible_when_metrics_are_off():
    """A narrow node table must not make Fit Screen clip its own controls."""
    cfg = copy.deepcopy(rm.DEFAULT_CONFIG)
    cfg.update({
        "main_width": 620,
        "start_on_launch": False,
        "autostart_login": False,
        "temp_enabled": False,
        "metrics_enabled": False,
        "watchdog_enabled": False,
    })
    app = None
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(rm, "load_config", return_value=cfg))
        stack.enter_context(mock.patch.object(
            rm, "save_config", lambda _cfg: None))
        for name in (
                "_start_monitor", "_build_tray", "_sync_metrics_runtime",
                "_sync_watchdog_runtime", "_check_ray_exe",
                "_schedule_ui_scaling_guard", "_schedule_duplicate_guard",
                "_auto_fit_startup"):
            stack.enter_context(mock.patch.object(
                rm.RayApp, name, lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(
            rm.RayApp, "apply_login_autostart",
            lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(
            rm.RayApp, "_log", lambda self, *args, **kwargs: None))
        stack.enter_context(mock.patch.object(rm, "_HAS_SENSOR", False))
        stack.enter_context(mock.patch.object(rm, "_HAS_TRAY", False))
        try:
            app = rm.RayApp()
            app._monitor_dpi_for_window = lambda: 144.0
            app._monitor_width_for_window = lambda: 3840
            app._monitor_work_area_for_window = lambda: (0, 0, 3840, 2088)
            app.nodes_header.configure(text="Node R Ray Temp")
            app.nodes_list.delete(0, "end")
            for name in ("SYNTHETIC_NODE_A", "SYNTHETIC_NODE_C", "SYNTHETIC_NODE_D", "SYNTHETIC_NODE_G", "SYNTHETIC_NODE_E"):
                app.nodes_list.insert("end", f"{name} W Ray 0/16 ---")
            app.geometry("620x541+100+100")
            app.update()

            layout = app._fit_to_content(persist=False)
            app.update()
            def descendants(widget):
                for child in widget.winfo_children():
                    yield child
                    yield from descendants(child)

            fit_button = next(
                widget for widget in descendants(app)
                if isinstance(widget, tk.Button)
                and str(widget.cget("text")) == "Fit Screen")
            utility_row = fit_button.master
            btnrow = utility_row.master
            required = int(btnrow.winfo_reqwidth()) + 16
            assert layout is not None
            assert int(app.winfo_width()) >= required, (
                app.winfo_width(), required)
            assert int(utility_row.winfo_width()) >= int(
                utility_row.winfo_reqwidth()), (
                utility_row.winfo_width(), utility_row.winfo_reqwidth())
        finally:
            if app is not None:
                app._closing = True
                _destroy_cleanly(app)


def main():
    tests = [test_named_fonts_follow_live_scaling_and_round_trip,
             test_fit_screen_repeated_clicks_are_geometry_idempotent,
             test_fit_screen_keeps_full_action_row_visible_when_metrics_are_off]
    results = []
    failed = 0
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except Exception as exc:
            failed += 1
            results.append({"test": test.__name__, "ok": False,
                            "error": f"{type(exc).__name__}: {exc}"})
    print(json.dumps({"suite": "runtime_dpi_widgets",
                      "passed": len(tests) - failed, "failed": failed,
                      "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
