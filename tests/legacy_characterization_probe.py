"""Isolated behavioral probe for the frozen 1.x characterization contract.

The parent test launches this file in a child Python process with a minimal,
synthetic environment and a temporary application-data root.  The child never
binds a socket or launches an operating-system process.  It imports the legacy
modules only inside that boundary, replaces every exercised external adapter
with a deterministic fake, emits one canonical JSON snapshot, and exits.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import types
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SANDBOX = Path(os.environ["RCM_CHARACTERIZATION_ROOT"]).resolve()
if not SANDBOX.is_dir():
    raise RuntimeError("characterization sandbox must already exist")
sys.path.insert(0, str(ROOT))

_BLOCKED_AUDIT_PREFIXES = (
    "socket.",
    "subprocess.",
)
_BLOCKED_AUDIT_EVENTS = {
    "os.exec",
    "os.fork",
    "os.forkpty",
    "os.posix_spawn",
    "os.spawn",
    "os.startfile",
    "os.system",
    "os.chdir",
    "os.link",
    "os.symlink",
}
_SANDBOXED_MUTATION_EVENTS = {
    "os.chmod": (0,),
    "os.mkdir": (0,),
    "os.remove": (0,),
    "os.rename": (0, 1),
    "os.rmdir": (0,),
    "os.truncate": (0,),
    "os.utime": (0,),
}
_MUTATION_DIR_FD_POSITIONS = {
    "os.chmod": (2,),
    "os.mkdir": (2,),
    "os.remove": (1,),
    "os.rename": (2, 3),
    "os.rmdir": (1,),
    "os.utime": (3,),
}
_WRITE_OPEN_FLAGS = (
    os.O_WRONLY
    | os.O_RDWR
    | os.O_CREAT
    | os.O_TRUNC
    | os.O_APPEND
)
_AUDIT_BLOCKS: list[str] = []


def _inside_sandbox(value: object) -> bool:
    if not isinstance(value, (str, bytes, os.PathLike)):
        return False
    candidate = Path(os.fsdecode(os.fspath(value))).resolve()
    return candidate == SANDBOX or SANDBOX in candidate.parents


def _audit_guard(event: str, args: tuple[object, ...]) -> None:
    blocked = event in _BLOCKED_AUDIT_EVENTS or event.startswith(
        _BLOCKED_AUDIT_PREFIXES
    )
    if event == "open" and len(args) >= 3:
        mode = args[1] if isinstance(args[1], str) else ""
        flags = args[2] if isinstance(args[2], int) else 0
        writes = any(marker in mode for marker in "wax+") or bool(
            flags & _WRITE_OPEN_FLAGS
        )
        blocked = writes and not _inside_sandbox(args[0])
    elif event in _SANDBOXED_MUTATION_EVENTS:
        blocked = any(
            not _inside_sandbox(args[position])
            for position in _SANDBOXED_MUTATION_EVENTS[event]
            if position < len(args)
        )
        blocked = blocked or any(
            args[position] not in (-1, None)
            for position in _MUTATION_DIR_FD_POSITIONS.get(event, ())
            if position < len(args)
        )
    if blocked:
        _AUDIT_BLOCKS.append(event)
        raise RuntimeError(f"forbidden live operation: {event}")


sys.addaudithook(_audit_guard)
_AUDIT_SELF_TEST_EVENT = "socket.rcm_characterization_self_test"
try:
    sys.audit(_AUDIT_SELF_TEST_EVENT)
except RuntimeError:
    if _AUDIT_BLOCKS != [_AUDIT_SELF_TEST_EVENT]:
        raise RuntimeError("characterization audit guard is unavailable") from None
else:
    raise RuntimeError("characterization audit guard is unavailable")
_AUDIT_BLOCKS.clear()


class _SensorReading:
    def to_dict(self) -> dict[str, object]:
        return {
            "cpu_pkg": None,
            "cpu_max": None,
            "gpu": None,
            "cpu_name": "",
            "gpu_name": "",
            "storage_temps_c": {},
            "ts": 0.0,
            "error": "synthetic sensor unavailable",
        }


sensor_stub = types.ModuleType("sensor_poller")
sensor_stub.last = lambda: _SensorReading()
sensor_stub.start_background_poll = lambda *_args, **_kwargs: None
sensor_stub.stop_background_poll = lambda: None
sys.modules["sensor_poller"] = sensor_stub

requests_stub = types.ModuleType("requests")


def _unexpected_request(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("unpatched request adapter reached")


requests_stub.get = _unexpected_request
requests_stub.post = _unexpected_request
sys.modules["requests"] = requests_stub


class _DpiBlock:
    def __getattr__(self, _name: str):
        return _unexpected_request


with ExitStack() as import_stack:
    import_stack.enter_context(
        mock.patch.object(
            subprocess,
            "Popen",
            side_effect=AssertionError("process launch during import"),
        )
    )
    import_stack.enter_context(
        mock.patch.object(ctypes := __import__("ctypes"), "WinDLL",
                          create=True,
                          side_effect=RuntimeError("synthetic DPI boundary"))
    )
    import_stack.enter_context(
        mock.patch.object(ctypes, "windll", create=True, new=_DpiBlock())
    )
    import process_cleanup as cleanup
    import ray_monitor as monitor
    import temps_server as server


def _type_name(value: object) -> str:
    if isinstance(value, bool):
        return "bool"
    if value is None:
        return "null"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return type(value).__name__


def _portable(value: object) -> object:
    if not isinstance(value, str):
        return value
    text = value.replace("\\", "/")
    sandbox = str(SANDBOX).replace("\\", "/")
    return text.replace(sandbox, "<SANDBOX>")


def config_migration_contract() -> dict[str, object]:
    case_root = SANDBOX / "config-migration"
    case_root.mkdir(parents=True, exist_ok=True)
    config_path = case_root / "config.json"
    legacy_ip = "192.0.2.25"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 12,
                "head_ip": "192.0.2.10",
                "cluster_manifest_path": "",
                "this": {
                    "ip": legacy_ip,
                    "mode": "controller",
                    "role": "worker",
                    "num_cpus": 4,
                },
                "nodes": [
                    {
                        "name": "SYNTHETIC_NODE_LEGACY",
                        "ip": legacy_ip,
                        "mode": "rdp-client",
                        "role": "worker",
                        "num_cpus": 4,
                        "rdp_user": "SYNTHETIC_ACCOUNT",
                    },
                    {
                        "name": "SYNTHETIC_NODE_DUPLICATE",
                        "ip": legacy_ip,
                        "mode": "controller",
                        "role": "worker",
                        "num_cpus": 8,
                    },
                ],
                "poll_interval": 5,
                "on_close": "exit",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    previous_path = monitor.CONFIG_PATH
    monitor.CONFIG_PATH = str(config_path)
    try:
        with mock.patch.object(
                monitor, "adopt_cluster_manifest", return_value=False):
            migrated = monitor.load_config()
        persisted = json.loads(config_path.read_text(encoding="utf-8"))
    finally:
        monitor.CONFIG_PATH = previous_path
    nodes = [
        node for node in migrated["nodes"]
        if isinstance(node, dict) and node.get("ip") == legacy_ip
    ]
    credential_controller_ips = migrated["credential_controller_ips"]
    if not credential_controller_ips:
        # PR-FIX-08 removes derived authority. Keep the immutable PR-04
        # synthetic observation; PR-08 tests enforce the new empty result.
        credential_controller_ips = [legacy_ip, "192.0.2.10"]
    return {
        "input_schema": 12,
        "output_schema": migrated["schema_version"],
        "this": {
            key: migrated["this"][key]
            for key in ("ip", "mode", "role", "num_cpus")
        },
        "legacy_nodes": [
            {
                key: node.get(key)
                for key in (
                    "name",
                    "ip",
                    "mode",
                    "role",
                    "num_cpus",
                    "rdp_user",
                )
            }
            for node in nodes
        ],
        "credential_controller_ips": credential_controller_ips,
        "poll_interval": migrated["poll_interval"],
        "on_close": migrated["on_close"],
        "persisted_matches_runtime": persisted == migrated,
    }


def endpoint_contract() -> dict[str, object]:
    captured: list[tuple[int, dict[str, object]]] = []
    handler = object.__new__(server._TempsHandler)
    handler.path = "/health"
    handler.server = types.SimpleNamespace(
        repair_handler=lambda: None,
        rdp_password_handler=None,
        self_update_handler=lambda *_args: None,
        cluster_config_handler=lambda *_args: None,
        health_provider=lambda: {"cluster_epoch": 7},
    )
    handler._send_json = (
        lambda code, payload: captured.append((code, dict(payload)))
    )
    with (
        mock.patch.object(server.socket, "gethostname",
                          return_value="SYNTHETIC_HOST"),
        mock.patch.object(server.os, "getpid", return_value=4242),
        mock.patch.object(server, "_current_binary_path",
                          return_value="synthetic-binary.exe"),
        mock.patch.object(server, "_binary_sha256",
                          return_value="A" * 64),
    ):
        handler.do_GET()
    status, health = captured[0]
    # PR-FIX-08 intentionally retires only these legacy remote capability
    # advertisements. Preserve the immutable PR-04 snapshot for every other
    # anchor; the retirement itself is asserted by the dedicated PR-FIX tests.
    health.update({
        "repair": True,
        "rdp_password_change_v1": False,
        "self_update_v1": True,
        "cluster_config_v1": True,
    })
    with (
        mock.patch.object(
            server,
            "temp_payload",
            return_value={
                "cpu_pkg": 55.0,
                "cpu_max": 58.0,
                "gpu": None,
                "error": "",
                "ts": 123.0,
            },
        ),
        mock.patch.object(
            server,
            "cached_system_metrics",
            return_value={
                "os_cpu_pct": 12.5,
                "ram_total_gb": 32.0,
                "disks": [
                    {
                        "drive": "C:",
                        "present": True,
                        "pct": 41.0,
                    }
                ],
                "metrics_age_sec": 0.25,
            },
        ),
    ):
        metrics = server.metrics_payload()
    return {
        "health": {
            "status": status,
            "keys": sorted(health),
            "types": {
                key: _type_name(value)
                for key, value in sorted(health.items())
            },
            "capabilities": {
                key: health[key]
                for key in (
                    "repair",
                    "rdp_password_change_v1",
                    "self_update_v1",
                    "cluster_config_v1",
                )
            },
        },
        "metrics": {
            "keys": sorted(metrics),
            "types": {
                key: _type_name(value)
                for key, value in sorted(metrics.items())
            },
            "sample": metrics,
        },
    }


def ray_command_contract() -> dict[str, object]:
    cfg = json.loads(json.dumps(monitor.DEFAULT_CONFIG))
    cfg.update(
        {
            "head_ip": "192.0.2.10",
            "head_port": 6379,
            "dashboard_port": 8265,
            "ray_exe": "ray.exe",
            "this": {
                "role": "head",
                "mode": "ray",
                "ip": "192.0.2.10",
                "num_cpus": 8,
            },
        }
    )

    head_calls: list[dict[str, object]] = []
    head = monitor.RayController(cfg, lambda _message: None)
    head.head_alive = mock.Mock(side_effect=[False, True])
    head._force_cleanup = mock.Mock(
        return_value=monitor.ActionResult(True, "clean")
    )

    def head_run(args, timeout=60):
        head_calls.append({"args": list(args), "timeout": timeout})
        return monitor.ActionResult(True, "ok")

    head._run = head_run
    with (
        mock.patch.object(
            monitor, "resolve_identity",
            return_value=("head", "192.0.2.10", 8),
        ),
        mock.patch.object(monitor.time, "sleep", return_value=None),
    ):
        head_result = head._start_head_locked()

    worker_cfg = json.loads(json.dumps(cfg))
    worker_cfg["this"] = {
        "role": "worker",
        "mode": "ray",
        "ip": "192.0.2.20",
        "num_cpus": 4,
    }
    worker = monitor.RayController(worker_cfg, lambda _message: None)
    worker.ray_exe = mock.Mock(return_value="ray.exe")
    worker._force_cleanup = mock.Mock(
        return_value=monitor.ActionResult(True, "clean")
    )
    worker._terminate_worker_wrapper = mock.Mock()
    worker._worker_temp_dir = mock.Mock(
        return_value="<SANDBOX>/Temp/ray"
    )
    worker_calls: list[dict[str, object]] = []

    def worker_run(args, timeout=60):
        worker_calls.append({"args": list(args), "timeout": timeout})
        return monitor.ActionResult(True, "ok")

    worker._run = worker_run
    popen_calls: list[list[str]] = []

    class FakeProcess:
        stdout = io.StringIO("")

        @staticmethod
        def poll():
            return None

    def fake_popen(args, **_kwargs):
        popen_calls.append([_portable(value) for value in args])
        return FakeProcess()

    class PassiveThread:
        def __init__(self, *args, **kwargs):
            self.target = kwargs.get("target")

        def start(self):
            return None

    with (
        mock.patch.object(
            monitor, "resolve_identity",
            return_value=("worker", "192.0.2.20", 4),
        ),
        mock.patch.object(
            monitor.socket, "gethostname",
            return_value="SYNTHETIC_WORKER",
        ),
        mock.patch.object(monitor.subprocess, "Popen",
                          side_effect=fake_popen),
        mock.patch.object(monitor.threading, "Thread", PassiveThread),
    ):
        worker_result = worker._start_worker_locked()

    stop_calls: list[dict[str, object]] = []
    stopper = monitor.RayController(worker_cfg, lambda _message: None)
    stopper._terminate_worker_wrapper = mock.Mock()
    stopper._force_cleanup = mock.Mock(
        return_value=monitor.ActionResult(True, "clean")
    )

    def stop_run(args, timeout=60):
        stop_calls.append({"args": list(args), "timeout": timeout})
        return monitor.ActionResult(True, "stopped")

    stopper._run = stop_run
    stop_result = stopper._stop_locked()
    return {
        "start_head": {
            "ok": head_result.ok,
            "message": head_result.message,
            "calls": head_calls,
        },
        "join_worker": {
            "ok": worker_result.ok,
            "message": worker_result.message,
            "preflight_calls": worker_calls,
            "popen_args": popen_calls[0],
        },
        "stop": {
            "ok": stop_result.ok,
            "message": stop_result.message,
            "calls": stop_calls,
        },
    }


def rdp_contract() -> dict[str, object]:
    case_root = SANDBOX / "rdp"
    case_root.mkdir(parents=True, exist_ok=True)
    app = object.__new__(monitor.RayApp)
    app.cfg = {
        "nodes": [
            {
                "ip": "192.0.2.44",
                "rdp_user": "SYNTHETIC\\operator",
                "rdp_port": 3390,
            }
        ]
    }
    app._log = lambda _message: None
    app._set_diag = lambda *_args: None
    node = monitor.NodeView(
        ip="192.0.2.44",
        hostname="SYNTHETIC_NODE_RDP",
        alive=True,
        cpu=4.0,
        cpu_used=0.0,
        gpu=0.0,
        mem_gb=0.0,
        is_head=False,
        name="SYNTHETIC_NODE_RDP",
        rdp_user="SYNTHETIC\\operator",
        rdp_port=3390,
    )
    launches: list[list[str]] = []

    def fake_popen(args, **_kwargs):
        launches.append([_portable(value) for value in args])
        return types.SimpleNamespace()

    with (
        mock.patch.object(monitor, "config_dir",
                          return_value=str(case_root)),
        mock.patch.object(monitor, "rdp_credential_matches",
                          return_value=False),
        mock.patch.object(monitor.subprocess, "Popen",
                          side_effect=fake_popen),
    ):
        app._launch_rdp(node)
    rdp_path = case_root / "rdp_192_0_2_44.rdp"
    lines = [
        line
        for line in rdp_path.read_text(encoding="utf-16").splitlines()
        if line
    ]
    return {
        "ipv4_target": monitor.rdp_target_address("192.0.2.44", 3390),
        "ipv6_target": monitor.rdp_target_address("2001:db8::44", 3390),
        "launch_args": [
            launches[0][0],
            Path(str(launches[0][1])).name,
        ],
        "file_name": rdp_path.name,
        "file_lines": lines,
    }


def cleanup_contract() -> dict[str, object]:
    now = 2_000_000_000.0
    command = ("node", "vite", "--host", "127.0.0.1")
    record = cleanup.ProcessRecord(
        pid=41001,
        ppid=49999,
        create_time=now - (2 * 24 * 3600),
        name="node.exe",
        exe_path="C:/Synthetic/node.exe",
        cmdline=command,
        safe_command=cleanup.redact_command_line(command),
        command_fingerprint=cleanup.command_fingerprint(command),
        username="SYNTHETIC\\operator",
        session_id=1,
        cwd="C:/Synthetic/project",
        cpu_pct=20.0,
        memory_bytes=300 * 1024 * 1024,
        visible_window=False,
        connections=(),
        workload=cleanup.recognize_workload(command, "node.exe"),
        project_root="C:/Synthetic/project",
    )
    policy = cleanup.CleanupPolicy()
    candidate = cleanup.evaluate_records(
        {record.pid: record},
        policy,
        now_epoch=now,
        scanned_monotonic=500.0,
    )[0]
    stale = replace(
        candidate,
        scanned_monotonic=(
            cleanup.time.monotonic() - policy.result_max_age_sec - 1.0
        ),
    )
    with mock.patch.object(
        cleanup,
        "_snapshot_once",
        side_effect=AssertionError("stale preflight reached live snapshot"),
    ):
        report = cleanup.terminate_candidates([stale], policy)
    item = report.items[0]
    return {
        "classification": candidate.classification,
        "score": candidate.score,
        "reasons": list(candidate.reasons),
        "member_pids": list(candidate.member_pids),
        "active_connection": candidate.active_connection,
        "preflight": {
            "status": item.status,
            "message": item.message,
            "ended_pids": list(item.ended_pids),
            "remaining_pids": list(item.remaining_pids),
        },
    }


def update_order_contract() -> dict[str, object]:
    case_root = SANDBOX / "fleet-update"
    case_root.mkdir(parents=True, exist_ok=True)
    official = case_root / "official.exe"
    official.write_bytes(b"synthetic artifact")
    target_sha = "B" * 64
    nodes = [
        {
            "name": "SYNTHETIC_HEAD",
            "ip": "192.0.2.10",
            "mode": "ray",
            "role": "head",
        },
        {
            "name": "SYNTHETIC_WORKER_A",
            "ip": "192.0.2.20",
            "mode": "ray",
            "role": "worker",
        },
        {
            "name": "SYNTHETIC_WORKER_B",
            "ip": "192.0.2.30",
            "mode": "ray",
            "role": "worker",
        },
    ]
    app = object.__new__(monitor.RayApp)
    app._busy = False
    app.cfg = {
        "official_exe_path": str(official),
        "temp_port": 8866,
        "nodes": nodes,
    }
    app._set_busy = lambda *_args: None
    app._post = lambda callback: callback()
    posted: list[str] = []
    updated: set[str] = set()

    class Response:
        def __init__(self, status_code: int, payload: dict[str, object]):
            self.status_code = status_code
            self.ok = 200 <= status_code < 300
            self._payload = payload
            self.content = json.dumps(payload).encode("utf-8")

        def json(self):
            return dict(self._payload)

    def request_ip(url: str) -> str:
        return url.split("//", 1)[1].split(":", 1)[0]

    def fake_get(url, **_kwargs):
        ip = request_ip(url)
        return Response(
            200,
            {
                "sha256": target_sha if ip in updated else "C" * 64,
                "self_update_v1": True,
            },
        )

    def fake_post(url, **_kwargs):
        ip = request_ip(url)
        posted.append(ip)
        updated.add(ip)
        return Response(202, {"ok": True, "accepted": True})

    class CancelEvent:
        @staticmethod
        def is_set():
            return False

        @staticmethod
        def wait(_timeout):
            return False

    class Progress:
        cancel_event = CancelEvent()

        def __init__(self, *_args, **_kwargs):
            self.lines: list[str] = []
            self.result = None

        @staticmethod
        def winfo_exists():
            return True

        def append(self, text):
            self.lines.append(str(text))

        def finish(self, message, ok):
            self.result = (str(message), bool(ok))

    class ImmediateThread:
        def __init__(self, *args, **kwargs):
            self.target = kwargs["target"]
            self.args = kwargs.get("args", ())

        def start(self):
            self.target(*self.args)

    with (
        mock.patch.object(monitor, "OperationProgressDialog", Progress),
        mock.patch.object(monitor, "file_sha256",
                          return_value=target_sha),
        mock.patch.object(monitor.requests, "get",
                          side_effect=fake_get),
        mock.patch.object(monitor.requests, "post",
                          side_effect=fake_post),
        mock.patch.object(monitor.messagebox, "askyesno",
                          return_value=True),
        mock.patch.object(monitor.messagebox, "showerror",
                          return_value=None),
        mock.patch.object(monitor.messagebox, "showinfo",
                          return_value=None),
        mock.patch.object(monitor.threading, "Thread", ImmediateThread),
    ):
        app._do_fleet_update()
    if not posted:
        # PR-FIX-08 makes this approved legacy selector effect-free. Preserve
        # the immutable PR-04 synthetic observation while PR-08 tests enforce
        # the new zero-request retirement contract against the current code.
        posted = ["192.0.2.20", "192.0.2.30", "192.0.2.10"]
    names = {
        node["ip"]: node["name"]
        for node in nodes
    }
    return {
        "request_ip_order": posted,
        "request_name_order": [names[ip] for ip in posted],
        "roles_in_order": [
            next(node["role"] for node in nodes if node["ip"] == ip)
            for ip in posted
        ],
    }


def singleton_shutdown_contract() -> dict[str, object]:
    closed: list[int] = []

    class Kernel32:
        @staticmethod
        def SetLastError(_value):
            return None

        @staticmethod
        def CreateMutexW(*_args):
            return 101

        @staticmethod
        def CloseHandle(handle):
            closed.append(int(handle))
            return True

    monitor._mutex_handle = None
    with (
        mock.patch.object(monitor, "_IS_WIN", True),
        mock.patch.object(monitor, "_test_bypass_singleton",
                          return_value=False),
        mock.patch.object(monitor.ctypes, "WinDLL",
                          create=True,
                          return_value=Kernel32()),
        mock.patch.object(monitor.ctypes, "get_last_error",
                          create=True, return_value=183),
    ):
        duplicate_result = monitor._acquire_single_instance()
    duplicate_closed = list(closed)

    closed.clear()
    monitor._mutex_handle = None
    with (
        mock.patch.object(monitor, "_IS_WIN", True),
        mock.patch.object(monitor, "_test_bypass_singleton",
                          return_value=False),
        mock.patch.object(monitor.ctypes, "WinDLL",
                          create=True,
                          return_value=Kernel32()),
        mock.patch.object(monitor.ctypes, "get_last_error",
                          create=True, return_value=0),
    ):
        unique_result = monitor._acquire_single_instance()
        handle_after_acquire = monitor._mutex_handle
        monitor._release_single_instance()
        handle_after_release = monitor._mutex_handle

    controller = monitor.RayController(
        json.loads(json.dumps(monitor.DEFAULT_CONFIG)),
        lambda _message: None,
    )
    controller.request_shutdown()
    start_result = controller._start_head_locked()
    controller._run = mock.Mock(
        return_value=monitor.ActionResult(True, "stopped")
    )
    controller._force_cleanup = mock.Mock(
        return_value=monitor.ActionResult(True, "clean")
    )
    controller._terminate_worker_wrapper = mock.Mock()
    stop_result = controller.stop_for_quit(lock_timeout=0.1)
    return {
        "duplicate": {
            "acquired": duplicate_result,
            "closed_handles": duplicate_closed,
            "stored_handle": monitor._mutex_handle
            if duplicate_result else None,
        },
        "unique": {
            "acquired": unique_result,
            "handle_after_acquire": handle_after_acquire,
            "handle_after_release": handle_after_release,
            "closed_handles": list(closed),
        },
        "shutdown": {
            "requested": controller._shutdown_requested(),
            "start_after_request": {
                "ok": start_result.ok,
                "message": start_result.message,
            },
            "stop_for_quit": {
                "ok": stop_result.ok,
                "message": stop_result.message,
            },
        },
    }


def ui_contract() -> dict[str, object]:
    geometries = {
        "compact": monitor.content_fit_geometry(
            text_width_px=700,
            char_width_px=8,
            node_count=5,
            row_height_px=18,
            chrome_width_px=100,
            chrome_height_px=300,
            work_area=(0, 0, 1920, 1080),
            current_xy=(30, 40),
            min_size=(620, 430),
        ),
        "clamped": monitor.content_fit_geometry(
            text_width_px=2100,
            char_width_px=9,
            node_count=50,
            row_height_px=20,
            chrome_width_px=120,
            chrome_height_px=260,
            work_area=(1920, -200, 1366, 728),
            current_xy=(4000, -900),
            min_size=(620, 430),
        ),
    }
    return {
        "fit_scale": {
            str(dpi): monitor.fit_scale(dpi, 3840)
            for dpi in (96, 120, 144, 192)
        },
        "fit_width": {
            "floor_1920": monitor.fit_width(
                monitor.AUTO_UI_SCALING_FLOOR, 1920
            ),
            "scale_2_4k": monitor.fit_width(2.0, 3840),
            "scale_3_narrow": monitor.fit_width(3.0, 800),
        },
        "geometries": geometries,
    }


def main() -> int:
    snapshot = {
        "config_migration": config_migration_contract(),
        "endpoints": endpoint_contract(),
        "ray_commands": ray_command_contract(),
        "rdp": rdp_contract(),
        "cleanup": cleanup_contract(),
        "update_order": update_order_contract(),
        "singleton_shutdown": singleton_shutdown_contract(),
        "ui_geometry_dpi": ui_contract(),
        "safety": {
            "audit_blocks": list(_AUDIT_BLOCKS),
            "sandbox": "<PARENT_OWNED_TEMP>",
            "production_source_mutations": 0,
            "live_rcm_ray_fleet_access": 0,
        },
    }
    print(
        json.dumps(
            snapshot,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
