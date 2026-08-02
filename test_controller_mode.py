"""Regression tests for schema-14 LEGACY_NODE worker behavior.

The tests isolate config persistence in a temporary directory and replace all
dashboard/repair I/O with fakes.  They never contact or modify a real node.
"""
from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

import ray_monitor as rm


LEGACY_NODE_IP = "192.0.2.25"


def test_schema_12_migrates_legacy_node_to_worker_once() -> None:
    original_path = rm.CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="rcm-controller-test-") as tmp:
            config_path = Path(tmp) / "config.json"
            rm.CONFIG_PATH = str(config_path)
            ray_nodes = [
                copy.deepcopy(node)
                for node in rm.DEFAULT_CONFIG["nodes"]
                if node.get("ip") != LEGACY_NODE_IP
            ]
            config_path.write_text(json.dumps({
                "schema_version": 12,
                "cluster_manifest_path": str(Path(tmp) / "cluster.json"),
                "this": {"ip": LEGACY_NODE_IP, "mode": "controller", "role": "worker"},
                "nodes": ray_nodes + [{
                    "name": "LEGACY_NODE", "ip": LEGACY_NODE_IP,
                    "mode": "rdp-client", "role": "worker",
                    "num_cpus": 4, "rdp_user": r"LEGACY_NODE\legacy",
                }],
            }), encoding="utf-8")

            migrated = rm.load_config()
            legacy_node = [
                node for node in migrated["nodes"]
                if isinstance(node, dict) and node.get("ip") == LEGACY_NODE_IP
            ]
            assert migrated["schema_version"] == 15
            assert migrated["this"]["mode"] == "ray"
            assert len(legacy_node) == 1
            assert legacy_node[0]["mode"] == "ray"
            assert legacy_node[0]["role"] == "worker"
            assert legacy_node[0]["num_cpus"] == 4
            assert legacy_node[0]["rdp_user"] == ""
            assert LEGACY_NODE_IP not in migrated["credential_controller_ips"]

            persisted = json.loads(config_path.read_text(encoding="utf-8"))
            assert sum(
                isinstance(node, dict) and node.get("ip") == LEGACY_NODE_IP
                for node in persisted["nodes"]
            ) == 1

            again = rm.load_config()
            assert again["schema_version"] == 15
            assert sum(node.get("ip") == LEGACY_NODE_IP
                       for node in again["nodes"] if isinstance(node, dict)) == 1
    finally:
        rm.CONFIG_PATH = original_path


def test_schema_less_config_does_not_seed_legacy_node_or_authority() -> None:
    original_path = rm.CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="rcm-schema-less-test-") as tmp:
            config_path = Path(tmp) / "config.json"
            rm.CONFIG_PATH = str(config_path)
            config_path.write_text(json.dumps({
                "cluster_manifest_path": str(Path(tmp) / "cluster.json"),
                "nodes": [{
                    "name": "SYNTHETIC_NODE_A", "ip": "192.0.2.27",
                    "role": "head", "mode": "ray", "num_cpus": 12,
                }],
            }), encoding="utf-8")

            migrated = rm.load_config()
            assert migrated["schema_version"] == 15
            assert all(
                node.get("ip") != LEGACY_NODE_IP
                for node in migrated["nodes"] if isinstance(node, dict))
            assert migrated["credential_controller_ips"] == []

            again = rm.load_config()
            assert all(
                node.get("ip") != LEGACY_NODE_IP
                for node in again["nodes"] if isinstance(node, dict))
    finally:
        rm.CONFIG_PATH = original_path


def test_schema_11_canonicalizes_aliases_and_deduplicates_legacy_node() -> None:
    original_path = rm.CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="rcm-controller-alias-test-") as tmp:
            config_path = Path(tmp) / "config.json"
            rm.CONFIG_PATH = str(config_path)
            config_path.write_text(json.dumps({
                "schema_version": 11,
                "cluster_manifest_path": str(Path(tmp) / "cluster.json"),
                "this": {
                    "ip": LEGACY_NODE_IP, "mode": "ray", "role": "worker",
                },
                "nodes": [
                    {"name": "LEGACY_NODE-first", "ip": LEGACY_NODE_IP,
                     "mode": "ray", "rdp_user": r"LEGACY_NODE\legacy"},
                    {"name": "LEGACY_NODE-duplicate", "ip": LEGACY_NODE_IP,
                     "mode": "rdp-client", "rdp_user": r"LEGACY_NODE\duplicate"},
                    {"name": "Old controller", "ip": "192.0.2.19",
                     "mode": "rdp", "rdp_user": ""},
                ],
            }), encoding="utf-8")

            cfg = rm.load_config()
            assert cfg["this"]["mode"] == "ray"
            legacy_node = [node for node in cfg["nodes"]
                     if isinstance(node, dict) and node.get("ip") == LEGACY_NODE_IP]
            assert len(legacy_node) == 1
            assert legacy_node[0]["name"] == "LEGACY_NODE-first"
            assert legacy_node[0]["mode"] == "ray"
            assert legacy_node[0]["role"] == "worker"
            assert legacy_node[0]["rdp_user"] == ""
            old = next(node for node in cfg["nodes"]
                       if isinstance(node, dict) and node.get("ip") == "192.0.2.19")
            assert old["mode"] == "controller"
    finally:
        rm.CONFIG_PATH = original_path


def test_schema_12_repairs_existing_legacy_node_and_current_schema_respects_user_mode() -> None:
    original_path = rm.CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="rcm-schema12-legacy_node-test-") as tmp:
            config_path = Path(tmp) / "config.json"
            rm.CONFIG_PATH = str(config_path)
            config_path.write_text(json.dumps({
                "schema_version": 12,
                "cluster_manifest_path": str(Path(tmp) / "cluster.json"),
                "this": {"ip": LEGACY_NODE_IP, "mode": "ray", "role": "worker"},
                "nodes": [
                    {"name": "LEGACY_NODE-first", "ip": LEGACY_NODE_IP,
                     "mode": "ray", "rdp_user": r"LEGACY_NODE\unsafe"},
                    {"name": "LEGACY_NODE-second", "ip": LEGACY_NODE_IP,
                     "mode": "rdp-client", "rdp_user": r"LEGACY_NODE\duplicate"},
                    {"name": "Legacy client", "ip": "192.0.2.18",
                     "mode": "rdp-client", "rdp_user": ""},
                ],
            }), encoding="utf-8")

            cfg = rm.load_config()
            assert cfg["this"]["mode"] == "ray"
            legacy_node = [node for node in cfg["nodes"]
                     if isinstance(node, dict) and node.get("ip") == LEGACY_NODE_IP]
            assert len(legacy_node) == 1
            assert legacy_node[0]["name"] == "LEGACY_NODE-first"
            assert legacy_node[0]["mode"] == "ray"
            assert legacy_node[0]["rdp_user"] == ""
            legacy = next(node for node in cfg["nodes"]
                          if isinstance(node, dict)
                          and node.get("ip") == "192.0.2.18")
            assert legacy["mode"] == "controller"

            persisted = json.loads(config_path.read_text(encoding="utf-8"))
            assert persisted["schema_version"] == 15
            assert persisted["this"]["mode"] == "ray"
            assert sum(node.get("ip") == LEGACY_NODE_IP
                       for node in persisted["nodes"] if isinstance(node, dict)) == 1

            # Once the current schema is persisted, LEGACY_NODE is no longer
            # IP-special. A
            # user's explicit generic mode/account settings are preserved.
            persisted["this"]["mode"] = "controller"
            persisted["nodes"][0]["mode"] = "ray"
            persisted["nodes"][0]["rdp_user"] = r"LEGACY_NODE\user"
            config_path.write_text(json.dumps(persisted), encoding="utf-8")
            current = rm.load_config()
            assert current["this"]["mode"] == "controller"
            current_legacy_node = next(node for node in current["nodes"]
                                 if node.get("ip") == LEGACY_NODE_IP)
            assert current_legacy_node["mode"] == "ray"
            assert current_legacy_node["rdp_user"] == r"LEGACY_NODE\user"

            # Explicit current-schema operator revocation is respected even though
            # LEGACY_NODE remains in the Ray inventory.
            current["credential_controller_ips"] = ["192.0.2.10"]
            config_path.write_text(json.dumps(current), encoding="utf-8")
            revoked = rm.load_config()
            assert revoked["credential_controller_ips"] == ["192.0.2.10"]
            assert "192.0.2.18" not in revoked["credential_controller_ips"]
            assert LEGACY_NODE_IP not in revoked["credential_controller_ips"]
    finally:
        rm.CONFIG_PATH = original_path


def test_controller_normalization_is_pure_generic_and_settings_reuses_it() -> None:
    original = {
        "this": {"ip": LEGACY_NODE_IP, "mode": "ray"},
        "nodes": [
            {"name": "LEGACY_NODE", "ip": LEGACY_NODE_IP, "mode": "ray",
             "rdp_user": r"LEGACY_NODE\unsafe"},
            {"name": "Alias", "ip": "192.0.2.17", "mode": "rdp"},
        ],
    }
    untouched = copy.deepcopy(original)
    normalized = rm.normalize_controller_config(original)
    assert original == untouched
    assert normalized["this"]["mode"] == "ray"
    assert normalized["nodes"][0]["mode"] == "ray"
    assert normalized["nodes"][0]["rdp_user"] == r"LEGACY_NODE\unsafe"
    assert normalized["nodes"][1]["mode"] == "controller"
    save_source = inspect.getsource(rm.SettingsDialog._save)
    assert "normalize_controller_config" in save_source
    assert "is_controller_node(rec)" in save_source


def test_all_controller_mode_aliases_share_one_predicate() -> None:
    for spelling in ("controller", "CONTROLLER", "rdp-client", "RDP"):
        assert rm.is_controller_mode(spelling)
        cfg = {"head_ip": "192.0.2.10", "this": {"ip": "192.0.2.15"},
               "nodes": [{"ip": "192.0.2.15", "mode": spelling,
                           "rdp_user": r"SYNTHETIC_PC\must-not-target"}]}
        assert rm.is_controller_config(cfg, "192.0.2.15")
        assert rm.rdp_password_targets(cfg["nodes"]) == []
        assert rm.credential_controller_allowlist(
            cfg["head_ip"], cfg["nodes"]) == []
    for spelling in (None, "", "ray", "worker"):
        assert not rm.is_controller_mode(spelling)
    assert not rm.is_controller_node({"ip": LEGACY_NODE_IP, "mode": "ray"})
    assert rm.credential_controller_allowlist(
        "192.0.2.10", [{"ip": LEGACY_NODE_IP, "mode": "ray"}], [LEGACY_NODE_IP]
    ) == [LEGACY_NODE_IP]


def test_controller_tray_has_no_ray_actions_and_quit_never_requests_stop() -> None:
    captured = {}

    class FakeMenuItem:
        def __init__(self, text, action, **_kwargs):
            self.text = text
            self.action = action

    class FakeMenu:
        SEPARATOR = object()

        def __init__(self, *items):
            self.items = items
            captured["menu"] = self

    class FakeIcon:
        def __init__(self, *_args):
            pass

        def run(self):
            return None

    fake_pystray = SimpleNamespace(
        Menu=FakeMenu, MenuItem=FakeMenuItem, Icon=FakeIcon)
    fake_image = SimpleNamespace(
        open=lambda _path: object(),
        new=lambda *_args, **_kwargs: object())
    app = SimpleNamespace(
        tray=None, controller_only=True, role="worker", _closing=False,
        _post=lambda fn: fn(), _show_window=lambda: None,
        _open_dashboard=lambda: None, _open_process_cleanup=lambda: None,
        _open_logs=lambda: None,
        _log=lambda _message: None)
    quit_calls = []
    app._quit = lambda **kwargs: quit_calls.append(kwargs)

    old = (rm._HAS_TRAY, rm.pystray, rm.Image)
    rm._HAS_TRAY, rm.pystray, rm.Image = True, fake_pystray, fake_image
    try:
        assert rm.RayApp._build_tray(app) is True
        # Let the tiny fake tray thread finish before globals are restored.
        time.sleep(0.02)
    finally:
        rm._HAS_TRAY, rm.pystray, rm.Image = old

    items = [item for item in captured["menu"].items
             if isinstance(item, FakeMenuItem)]
    labels = [item.text for item in items]
    assert labels == [
        "Show", "Dashboard", "Process Cleanup", "Logs", "Quit"]
    next(item for item in items if item.text == "Quit").action()
    assert quit_calls == [{"stop_ray": False, "source": "tray"}]
    quit_source = inspect.getsource(rm.RayApp._quit)
    assert "and not self.controller_only" in quit_source


def test_worker_tray_quit_honors_stop_on_quit_setting() -> None:
    """v1.07.16b [cleanquit]: tray Quit follows the Settings checkbox."""

    class FakeMenuItem:
        def __init__(self, text, action, **_kwargs):
            self.text = text
            self.action = action

    class FakeMenu:
        SEPARATOR = object()

        def __init__(self, *items):
            self.items = items

    class FakeIcon:
        def __init__(self, *_args):
            pass

        def run(self):
            return None

    fake_pystray = SimpleNamespace(
        Menu=FakeMenu, MenuItem=FakeMenuItem, Icon=FakeIcon)
    fake_image = SimpleNamespace(
        open=lambda _path: object(),
        new=lambda *_args, **_kwargs: object())

    for stop_on_quit, expected in ((False, False), (True, True)):
        captured = {}

        class CapturingMenu(FakeMenu):
            def __init__(self, *items):
                super().__init__(*items)
                captured["menu"] = self

        fake_pystray.Menu = CapturingMenu
        quit_calls = []
        app = SimpleNamespace(
            tray=None, controller_only=False, role="worker", _closing=False,
            cfg={"stop_on_quit": stop_on_quit},
            _post=lambda fn: fn(), _show_window=lambda: None,
            _do_start=lambda: None, _do_stop=lambda: None,
            _do_reset=lambda: None,
            _open_dashboard=lambda: None,
            _open_process_cleanup=lambda: None, _open_logs=lambda: None,
            _log=lambda _message: None)
        app._quit = lambda **kwargs: quit_calls.append(kwargs)

        old = (rm._HAS_TRAY, rm.pystray, rm.Image)
        rm._HAS_TRAY, rm.pystray, rm.Image = True, fake_pystray, fake_image
        try:
            assert rm.RayApp._build_tray(app) is True
            time.sleep(0.02)
        finally:
            rm._HAS_TRAY, rm.pystray, rm.Image = old

        items = [item for item in captured["menu"].items
                 if isinstance(item, FakeMenuItem)]
        next(item for item in items if item.text == "Quit").action()
        assert quit_calls == [{"stop_ray": expected, "source": "tray"}], (
            f"stop_on_quit={stop_on_quit} must pass stop_ray={expected}, "
            f"got {quit_calls}")

    quit_source = inspect.getsource(rm.RayApp._build_tray)
    assert 'bool(self.cfg.get("stop_on_quit", False))' in quit_source


def test_controller_startup_never_opens_or_reads_sensor_poller() -> None:
    init_source = inspect.getsource(rm.RayApp.__init__)
    guarded = init_source.index("if _HAS_SENSOR and not self.controller_only")
    open_call = init_source.index("sensor_poller.get_poller().open()")
    read_call = init_source.index("sensor_poller.get_poller().read()")
    controller_skip = init_source.index("sensor_poller: skipped (controller mode)")
    assert guarded < open_call < read_call < controller_skip
    sync_source = inspect.getsource(rm.RayApp._sync_metrics_runtime)
    assert "and not self.controller_only" in sync_source


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.content = b"{}"

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def test_legacy_node_worker_is_included_in_ray_view_totals_and_optional_rdp_targets() -> None:
    cfg = copy.deepcopy(rm.DEFAULT_CONFIG)
    cfg["head_ip"] = "192.0.2.27"
    cfg["nodes"] = [
        {"name": "SYNTHETIC_NODE_A", "ip": cfg["head_ip"],
         "role": "head", "mode": "ray", "num_cpus": 12,
         "rdp_user": ""},
        {"name": "LEGACY_NODE", "ip": LEGACY_NODE_IP,
         "role": "worker", "mode": "ray", "num_cpus": 4,
         "rdp_user": ""},
    ]
    cfg["this"] = {
        "role": "head",
        "mode": "ray",
        "ip": cfg["head_ip"],
        "num_cpus": 12,
    }
    cfg["temp_enabled"] = False
    cfg["metrics_enabled"] = False
    legacy_node_cfg = next(node for node in cfg["nodes"]
                     if node.get("ip") == LEGACY_NODE_IP)
    assert legacy_node_cfg["mode"] == "ray"
    assert legacy_node_cfg["rdp_user"] == ""

    dashboard_rows = [
        {
            "node_ip": cfg["head_ip"],
            "node_name": "SYNTHETIC_NODE_A",
            "node_id": "head-id",
            "state": "ALIVE",
            "is_head_node": True,
            "resources_total": {"CPU": 12},
        },
        {
            "node_ip": LEGACY_NODE_IP,
            "node_name": "LEGACY_NODE",
            "node_id": "controller-id",
            "state": "ALIVE",
            "is_head_node": False,
            "resources_total": {"CPU": 4},
        },
    ]

    def fake_get(url: str, *args, **kwargs) -> _FakeResponse:
        if url.endswith("/api/v0/nodes"):
            return _FakeResponse({
                "data": {"result": {"result": dashboard_rows}},
            })
        if url.endswith("/api/cluster_status"):
            return _FakeResponse({})
        raise AssertionError(f"unexpected dashboard URL: {url}")

    original_get = rm.requests.get
    rm.requests.get = fake_get
    try:
        view = rm.ClusterMonitor(cfg, lambda _view: None).fetch()
    finally:
        rm.requests.get = original_get

    assert view.reachable is True
    assert view.alive_nodes == 2
    assert view.total_cpu == 16
    view_ips = [node.ip for node in view.nodes]
    assert cfg["head_ip"] in view_ips
    assert LEGACY_NODE_IP in view_ips
    assert rm.is_controller_config(cfg, LEGACY_NODE_IP) is False
    assert LEGACY_NODE_IP not in [node["ip"] for node in rm.rdp_password_targets(cfg["nodes"])]
    legacy_node_cfg["rdp_user"] = r"LEGACY_NODE\user"
    assert LEGACY_NODE_IP in [node["ip"] for node in rm.rdp_password_targets(cfg["nodes"])]
    display = rm.complete_ray_display_nodes([], cfg, this_ip=cfg["head_ip"])
    assert LEGACY_NODE_IP in [node.ip for node in display]


def test_cluster_repair_is_local_only_and_never_targets_workers() -> None:
    cfg = {
        "head_ip": "192.0.2.27",
        "nodes": [
            {"name": "SYNTHETIC_NODE_A", "ip": "192.0.2.27", "role": "head", "mode": "ray"},
            {"name": "SYNTHETIC_NODE_D", "ip": "192.0.2.23", "role": "worker", "mode": "ray"},
            {"name": "LEGACY_NODE", "ip": LEGACY_NODE_IP, "role": "worker", "mode": "ray",
             "rdp_user": ""},
        ],
    }

    class FakeApp:
        role = "head"
        ip = "192.0.2.27"

        def __init__(self):
            self.cfg = cfg
            self.targets = []

        def _repair_local_ray(self):
            return rm.ActionResult(True, "local repaired")

        def _request_remote_repair(self, node, alive_ips, checked):
            raise AssertionError("remote repair forbidden")

        def _clear_monitor_metric_cache(self):
            return None

    fake = FakeApp()
    with mock.patch.object(
            rm, "_dashboard_alive_ips",
            side_effect=AssertionError("remote dashboard scan forbidden")):
        result = rm.RayApp._repair_cluster(fake)

    assert result.ok is True
    assert result.message == "local repaired"
    assert fake.targets == []


class _Api500Response:
    ok = False


def test_head_alive_fallback_requires_gcs_and_dashboard_tcp() -> None:
    cfg = {
        "head_ip": "192.0.2.27", "head_port": 6379,
        "dashboard_port": 8265,
    }
    controller = rm.RayController(cfg, lambda _message: None)

    def only_gcs(_host, port, timeout=0.5):
        return int(port) == 6379

    with mock.patch.object(rm.requests, "get", return_value=_Api500Response()), \
            mock.patch.object(rm, "_tcp_open", side_effect=only_gcs):
        assert controller.head_alive(timeout=0.1) is False

    with mock.patch.object(rm.requests, "get", return_value=_Api500Response()), \
            mock.patch.object(rm, "_tcp_open", return_value=True):
        assert controller.head_alive(timeout=0.1) is True


def test_head_repair_resets_half_start_and_keeps_tcp_healthy_head() -> None:
    cfg = {
        "head_ip": "192.0.2.27", "head_port": 6379,
        "dashboard_port": 8265,
    }

    class FakeApp:
        role = "head"
        ip = "192.0.2.27"

        def __init__(self, controller):
            self.cfg = cfg
            self.controller = controller
            self._auto_pause_fired = False
            self._cool_streak = 0
            self.statuses = []
            self.logs = []
            self.cache_clears = 0

        def _set_repair_status(self, *args, **kwargs):
            self.statuses.append((args, kwargs))

        def _log(self, message):
            self.logs.append(message)

        def _clear_monitor_metric_cache(self):
            self.cache_clears += 1

    half = rm.RayController(cfg, lambda _message: None)
    half.clean_reset = mock.Mock(return_value=rm.ActionResult(True, "reset"))
    half.start_head = mock.Mock(return_value=rm.ActionResult(True, "started"))
    app = FakeApp(half)
    with mock.patch.object(rm.requests, "get", return_value=_Api500Response()), \
            mock.patch.object(
                rm, "_tcp_open", side_effect=lambda _host, port, timeout=0.5:
                int(port) == 6379), \
            mock.patch.object(rm.time, "sleep", return_value=None):
        result = rm.RayApp._repair_local_ray(app)
    assert result.ok is True
    half.clean_reset.assert_called_once_with()
    half.start_head.assert_called_once_with()
    assert app.cache_clears == 1

    # A dashboard API 500 is not a reset trigger when both TCP listeners are
    # open. This exercises the real RayController fallback through Repair.
    healthy_controller = rm.RayController(cfg, lambda _message: None)
    healthy_controller.clean_reset = mock.Mock(
        side_effect=AssertionError("healthy head must not reset"))
    healthy_controller.start_head = mock.Mock(
        side_effect=AssertionError("healthy head must not restart"))
    healthy_app = FakeApp(healthy_controller)
    with mock.patch.object(rm.requests, "get", return_value=_Api500Response()), \
            mock.patch.object(rm, "_tcp_open", return_value=True):
        result = rm.RayApp._repair_local_ray(healthy_app)
    assert result.ok is True
    assert "already healthy" in result.message
    healthy_controller.clean_reset.assert_not_called()
    healthy_controller.start_head.assert_not_called()


def main() -> int:
    tests = [
        test_schema_12_migrates_legacy_node_to_worker_once,
        test_schema_less_config_does_not_seed_legacy_node_or_authority,
        test_schema_11_canonicalizes_aliases_and_deduplicates_legacy_node,
        test_schema_12_repairs_existing_legacy_node_and_current_schema_respects_user_mode,
        test_controller_normalization_is_pure_generic_and_settings_reuses_it,
        test_all_controller_mode_aliases_share_one_predicate,
        test_controller_tray_has_no_ray_actions_and_quit_never_requests_stop,
        test_worker_tray_quit_honors_stop_on_quit_setting,
        test_controller_startup_never_opens_or_reads_sensor_poller,
        test_legacy_node_worker_is_included_in_ray_view_totals_and_optional_rdp_targets,
        test_cluster_repair_is_local_only_and_never_targets_workers,
        test_head_alive_fallback_requires_gcs_and_dashboard_tcp,
        test_head_repair_resets_half_start_and_keeps_tcp_healthy_head,
    ]
    results = []
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except Exception as exc:
            results.append({
                "test": test.__name__,
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
    failed = sum(not result["ok"] for result in results)
    print(json.dumps({
        "suite": "controller_mode",
        "passed": len(results) - failed,
        "failed": failed,
        "results": results,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
