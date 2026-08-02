"""Fake-only regression for retirement of legacy remote self-update."""

import inspect
import json
from unittest import mock

import ray_monitor
from src.rcm import legacy_compat


def _app():
    app = object.__new__(ray_monitor.RayApp)
    app.cfg = {
        "official_exe_path": "synthetic-forbidden.exe",
        "temp_enabled": False,
        "metrics_enabled": False,
        "update_controller_ips": ["192.0.2.20"],
    }
    return app


def test_direct_self_update_shim_returns_exact_code_with_zero_effects():
    app = _app()
    forbidden = AssertionError("retired self-update effect")
    with (
        mock.patch.object(legacy_compat.os.path, "isfile", side_effect=forbidden),
        mock.patch.object(legacy_compat, "file_sha256", side_effect=forbidden),
        mock.patch.object(legacy_compat.shutil, "copy2", side_effect=forbidden),
        mock.patch.object(legacy_compat.subprocess, "Popen", side_effect=forbidden),
        mock.patch.object(legacy_compat.threading.Thread, "start",
                          side_effect=forbidden),
    ):
        result = app._handle_self_update("A" * 64, "official")
    assert result == {
        "_status": 410,
        "ok": False,
        "accepted": False,
        "reason": "legacy_remote_retired",
    }


def test_retired_update_helpers_do_not_touch_files_or_processes():
    app = _app()
    with (
        mock.patch.object(
            legacy_compat.shutil, "copy2",
            side_effect=AssertionError("copy forbidden")) as copy,
        mock.patch.object(
            legacy_compat.subprocess, "Popen",
            side_effect=AssertionError("process forbidden")) as popen,
    ):
        assert app._launch_self_update_helper("a", "b", "c") is None
        assert app._perform_self_update("a", "b") is None
    copy.assert_not_called()
    popen.assert_not_called()


def test_control_only_config_cannot_keep_server_alive():
    assert not ray_monitor.needs_rcm_control_server({
        "temp_enabled": False,
        "metrics_enabled": False,
        "credential_controller_ips": ["192.0.2.10"],
        "update_controller_ips": ["192.0.2.11"],
        "cluster_controller_ips": ["192.0.2.12"],
    }, controller_only=False)
    assert ray_monitor.needs_rcm_control_server({
        "temp_enabled": False,
        "metrics_enabled": True,
    }, controller_only=False)


def test_self_update_rejects_arbitrary_inputs_with_same_exact_code():
    result = _app()._handle_self_update("", "synthetic")
    assert result["_status"] == 410
    assert result["reason"] == "legacy_remote_retired"


def test_fleet_update_surfaces_retirement_without_remote_effects():
    app = _app()
    with (
        mock.patch.object(legacy_compat.messagebox, "showinfo",
                          return_value=None) as shown,
        mock.patch.object(legacy_compat.requests, "get",
                          side_effect=AssertionError("GET forbidden")) as get,
        mock.patch.object(legacy_compat.requests, "post",
                          side_effect=AssertionError("POST forbidden")) as post,
    ):
        result = app._do_fleet_update()
    assert result == ray_monitor.ActionResult(
        False, "legacy_remote_retired")
    shown.assert_called_once()
    get.assert_not_called()
    post.assert_not_called()


def test_retirement_precedes_preserved_legacy_helper_source():
    source = inspect.getsource(
        legacy_compat.LegacyRayAppMixin._launch_self_update_helper)
    assert source.index("return") < source.index("self_update_helper.ps1")


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(json.dumps({"suite": "self_update_retirement",
                      "passed": len(tests), "failed": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
