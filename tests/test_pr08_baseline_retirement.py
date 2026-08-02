from __future__ import annotations

import ast
import hashlib
import importlib
import inspect
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import textwrap
import types
import unittest
from unittest import mock


def _unexpected_request(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("unpatched request adapter reached")


ROOT = Path(__file__).resolve().parents[1]
LEGACY_REMOTE_RETIRED = "legacy_remote_retired"
NOT_FOUND = b'{"error":"not_found","ok":false}'
CAPABILITIES = (
    "repair",
    "rdp_password_change_v1",
    "self_update_v1",
    "cluster_config_v1",
)


def _load_ray_monitor() -> types.ModuleType:
    try:
        return importlib.import_module("ray_monitor")
    except ModuleNotFoundError as exc:
        if exc.name != "requests":
            raise
    synthetic_requests = types.ModuleType("requests")
    synthetic_requests.get = _unexpected_request
    synthetic_requests.post = _unexpected_request
    sys.modules["requests"] = synthetic_requests
    try:
        return importlib.import_module("ray_monitor")
    finally:
        sys.modules.pop("requests", None)


def _load_temps_server() -> types.ModuleType:
    return importlib.import_module("temps_server")


class _RemoteNode:
    ip = "192.0.2.21"
    is_this = False

    def __init__(self) -> None:
        ray_monitor = _load_ray_monitor()
        for name in ray_monitor.ClusterMonitor._METRIC_CACHE_FIELDS:
            setattr(self, name, [] if name == "disks" else None)


class PrFix08BaselineRetirementTests(unittest.TestCase):
    def test_bind_rejects_before_any_socket_constructor(self) -> None:
        temps_server = _load_temps_server()
        forbidden = AssertionError("socket construction forbidden")
        for bind in (
                "", "0.0.0.0", "localhost", "::1", "::", "192.0.2.20"):
            with self.subTest(bind=bind), mock.patch.object(
                    temps_server, "ThreadingHTTPServer",
                    side_effect=forbidden) as http_server:
                with self.assertRaisesRegex(
                        ValueError, "exact IPv4 loopback"):
                    temps_server.TempsServer(port=0, bind=bind)
                http_server.assert_not_called()
        signature = inspect.signature(temps_server.TempsServer)
        self.assertEqual("127.0.0.1", signature.parameters["bind"].default)
        source = Path(temps_server.__file__).read_text(encoding="utf-8")
        module_doc = ast.get_docstring(ast.parse(source)) or ""
        self.assertNotIn("0.0.0.0", module_doc)
        self.assertNotIn("another machine", source)
        self.assertIn(
            "serving locally on http://127.0.0.1:{srv.port}/temps",
            source)

    def test_handler_ast_has_exact_routes_and_body_free_post(self) -> None:
        temps_server = _load_temps_server()
        get_source = inspect.getsource(temps_server._TempsHandler.do_GET)
        get_tree = ast.parse(textwrap.dedent(get_source))
        strings = {
            node.value for node in ast.walk(get_tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertTrue({"/temps", "/metrics", "/health", "/ping"} <= strings)
        self.assertNotIn("/repair", strings)
        self.assertNotIn("rstrip", get_source)
        post_source = inspect.getsource(temps_server._TempsHandler.do_POST)
        self.assertIn("self._send_not_found()", post_source)
        for forbidden in ("rfile", "headers", "_post_", "handler"):
            self.assertNotIn(forbidden, post_source)
        run_source = inspect.getsource(temps_server.TempsServer.run)
        self.assertIn("self._server.health_provider", run_source)
        for name in (
                "repair_handler", "repair_status_provider",
                "repair_allowed_hosts", "rdp_password_handler",
                "control_allowed_hosts", "self_update_handler",
                "update_allowed_hosts", "cluster_config_handler",
                "cluster_allowed_hosts"):
            self.assertNotIn(f"self._server.{name}", run_source)

    def test_direct_legacy_post_helpers_are_error_only(self) -> None:
        temps_server = _load_temps_server()
        handler = object.__new__(temps_server._TempsHandler)
        calls = []
        handler._send_not_found = lambda: calls.append(NOT_FOUND)
        for name in (
                "_post_cluster_config",
                "_post_self_update",
                "_post_rdp_password"):
            self.assertIsNone(getattr(handler, name)())
        self.assertEqual([NOT_FOUND] * 3, calls)

    def test_health_capability_floor_is_applied_after_provider(self) -> None:
        temps_server = _load_temps_server()
        captured = []
        handler = object.__new__(temps_server._TempsHandler)
        handler.path = "/health?synthetic=1"
        handler.server = SimpleNamespace(
            health_provider=lambda: {
                **{name: True for name in CAPABILITIES},
                "local_identity": "synthetic",
            })
        handler._send_json = (
            lambda code, payload: captured.append((code, dict(payload))))
        with (
            mock.patch.object(
                temps_server.socket, "gethostname",
                return_value="SYNTHETIC_HOST"),
            mock.patch.object(temps_server.os, "getpid", return_value=7),
            mock.patch.object(
                temps_server, "_current_binary_path",
                return_value="synthetic.exe"),
            mock.patch.object(
                temps_server, "_binary_sha256",
                return_value="A" * 64),
        ):
            handler.do_GET()
        status, payload = captured[0]
        self.assertEqual(200, status)
        self.assertEqual("synthetic", payload["local_identity"])
        self.assertTrue(all(payload[name] is False for name in CAPABILITIES))

    def test_runtime_wires_only_read_only_loopback_server(self) -> None:
        ray_monitor = _load_ray_monitor()
        source = inspect.getsource(ray_monitor.RayApp._sync_metrics_runtime)
        self.assertIn('bind="127.0.0.1"', source)
        self.assertIn("health_provider=self._health_snapshot", source)
        for forbidden in (
                "repair_handler=", "repair_status_provider=",
                "rdp_password_handler=", "self_update_handler=",
                "cluster_config_handler=", "allowed_hosts="):
            self.assertNotIn(forbidden, source)

    def test_remote_metrics_create_no_request_or_thread(self) -> None:
        ray_monitor = _load_ray_monitor()
        monitor = ray_monitor.ClusterMonitor(
            {"temp_port": 8866, "metrics_enabled": True,
             "temp_enabled": True}, lambda _view: None)
        node = _RemoteNode()
        with (
            mock.patch.object(
                ray_monitor.requests, "get",
                side_effect=AssertionError("remote GET forbidden")) as get,
            mock.patch.object(
                ray_monitor.threading, "Thread",
                side_effect=AssertionError("remote thread forbidden")) as thread,
        ):
            monitor._enrich_metrics([node])
        get.assert_not_called()
        thread.assert_not_called()
        self.assertEqual(LEGACY_REMOTE_RETIRED, node.temp_error)
        self.assertEqual(LEGACY_REMOTE_RETIRED, node.metrics_error)
        probe_environment = os.environ.copy()
        probe_environment["PYTHONDONTWRITEBYTECODE"] = "1"
        probe_environment["PYTHONPATH"] = os.pathsep.join(
            (str(ROOT), str(ROOT / "src")))
        probe = subprocess.run(
            [
                sys.executable,
                "-B",
                "-S",
                "-c",
                "import tests.test_pr08_baseline_retirement as suite; "
                "assert suite._load_ray_monitor().__name__ == 'ray_monitor'",
            ],
            cwd=ROOT,
            env=probe_environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(
            0, probe.returncode,
            f"dependency-free import probe failed: {probe.stderr}")

    def test_rdp_probe_never_touches_legacy_port(self) -> None:
        ray_monitor = _load_ray_monitor()
        calls = []
        with mock.patch.object(
                ray_monitor, "tcp_probe_state",
                side_effect=lambda host, port, timeout:
                calls.append((host, port, timeout)) or "open"):
            result = ray_monitor.probe_remote_access(
                "192.0.2.30", 3390, 8866, 0.25)
        self.assertEqual([("192.0.2.30", 3390, 0.25)], calls)
        self.assertEqual({
            "rdp": "open",
            "rcm": LEGACY_REMOTE_RETIRED,
        }, result)

    def test_legacy_config_values_derive_no_authority(self) -> None:
        ray_monitor = _load_ray_monitor()
        nodes = [{"ip": "192.0.2.40", "mode": "controller"}]
        self.assertEqual(
            [],
            ray_monitor.credential_controller_allowlist(
                "192.0.2.10", nodes, []))
        self.assertEqual(
            ["192.0.2.41"],
            ray_monitor.credential_controller_allowlist(
                "192.0.2.10", nodes, ["192.0.2.41", "invalid"]))
        self.assertFalse(ray_monitor.needs_rcm_control_server({
            "temp_enabled": False,
            "metrics_enabled": False,
            "credential_controller_ips": ["192.0.2.41"],
            "update_controller_ips": ["192.0.2.42"],
            "cluster_controller_ips": ["192.0.2.43"],
        }, controller_only=False))

    def test_pr04_and_pr07_fixtures_remain_byte_exact(self) -> None:
        expected = {
            "tests/fixtures/characterization_contract.json":
                "956e45fe54524ae3d4602a56a2e73caa6c24b237e9edeb59ae613d064ec57573",
            "tests/fixtures/pr07_ui_contract.json":
                "76e7b40680f989c342524310573fc54c7961621de8accb335a21dc4b2828bb8e",
        }
        for relative, digest in expected.items():
            with self.subTest(path=relative):
                actual = hashlib.sha256(
                    (ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(digest, actual)


if __name__ == "__main__":
    unittest.main()
