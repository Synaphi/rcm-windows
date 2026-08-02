"""
temps_server.py - retired legacy diagnostics endpoint.

The compatibility server is local read-only diagnostics only. It binds exact
IPv4 loopback and is never a node-to-node, tailnet, or remote control surface.

Bind:  exact 127.0.0.1 only; every other value fails before socket creation.
Endpoints:
    GET /temps
    GET /metrics
    GET /health
    GET /ping
Every other path and method returns the exact retired not-found response.
"""
from __future__ import annotations

import json
import os
import hashlib
import ipaddress
import socket
import subprocess
import sys
import threading
import time
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional

from release_info import (
    BUILD_DATE as _APP_BUILD_DATE,
    BUILD_TAG as _APP_BUILD_TAG,
    DISPLAY_VERSION as _APP_VERSION,
)

try:
    import sensor_poller
    _HAS_SENSOR_POLLER = True
    _SENSOR_IMPORT_ERROR = ""
except Exception as _sensor_exc:
    sensor_poller = None
    _HAS_SENSOR_POLLER = False
    _SENSOR_IMPORT_ERROR = f"{type(_sensor_exc).__name__}: {_sensor_exc}"

try:
    import psutil
    _HAS_PSUTIL = True
except Exception as _psutil_exc:
    psutil = None
    _HAS_PSUTIL = False
    _PSUTIL_IMPORT_ERROR = f"{type(_psutil_exc).__name__}: {_psutil_exc}"


DEFAULT_PORT = 8866
_SERVER_START_TS = time.time()
_HEALTH_BINARY_PATH = None
_HEALTH_BINARY_SHA256 = None
_METRICS_LIFECYCLE_LOCK = threading.Lock()
_METRICS_LOCK = threading.Lock()
_METRICS_CACHE: dict = {}
_METRICS_STOP: Optional[threading.Event] = None
_METRICS_THREAD: Optional[threading.Thread] = None
_METRICS_GENERATION = 0
_DISK_IO_LOCK = threading.Lock()
_DISK_IO_LAST = None
_NET_IO_LOCK = threading.Lock()
_NET_IO_BASE = None
_NET_IO_LAST = None
_CONN_LOCK = threading.Lock()
_CONN_CACHE = None
_STORAGE_TEMP_MAX_AGE_SEC = 10.0


def _current_binary_path() -> str:
    if getattr(sys, "frozen", False):
        return sys.executable
    return os.path.abspath(__file__)


def _binary_sha256() -> str:
    global _HEALTH_BINARY_PATH, _HEALTH_BINARY_SHA256
    path = _current_binary_path()
    if _HEALTH_BINARY_PATH == path and _HEALTH_BINARY_SHA256:
        return _HEALTH_BINARY_SHA256
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        _HEALTH_BINARY_PATH = path
        _HEALTH_BINARY_SHA256 = h.hexdigest().upper()
        return _HEALTH_BINARY_SHA256
    except Exception as exc:
        return f"<sha unavailable: {type(exc).__name__}>"


def _safe_round(value, digits=1):
    try:
        if value is None:
            return None
        return round(float(value), digits)
    except Exception:
        return None


def _empty_system_metrics() -> dict:
    return {
        "os_cpu_pct": None,
        "ram_total_gb": None,
        "ram_used_gb": None,
        "ram_available_gb": None,
        "ram_pct": None,
        "disks": [],
        "disk_io_bps": None,
        "disk_active": False,
        "disk_error": "",
        "net_down_bps": None,
        "net_up_bps": None,
        "net_down_total_bytes": None,
        "net_up_total_bytes": None,
        "metrics_uptime_sec": _safe_round(time.time() - _SERVER_START_TS, 1),
        "conn_label": "",
        "conn_type": "",
        "conn_name": "",
        "conn_category": "",
        "conn_error": "",
        "net_error": "",
        "metrics_ts": time.time(),
        "metrics_error": "",
        "host": socket.gethostname(),
    }


def _system_metrics() -> dict:
    """Return lightweight OS metrics. Never raises."""
    payload = _empty_system_metrics()
    payload.update(_connection_summary())
    if not _HAS_PSUTIL:
        payload["metrics_error"] = _PSUTIL_IMPORT_ERROR
        return payload
    try:
        vm = psutil.virtual_memory()
        # interval=None can stay pinned at 0.0 in the onefile process on some
        # Windows boots; the tiny sample now runs on the background metrics
        # poller so /metrics responses stay fast under CPU contention.
        cpu_pct = psutil.cpu_percent(interval=None)
        if cpu_pct == 0.0:
            cpu_pct = psutil.cpu_percent(interval=0.05)
        payload.update({
            "os_cpu_pct": _safe_round(cpu_pct, 1),
            "ram_total_gb": _safe_round(vm.total / (1024 ** 3), 1),
            "ram_used_gb": _safe_round((vm.total - vm.available) / (1024 ** 3), 1),
            "ram_available_gb": _safe_round(vm.available / (1024 ** 3), 1),
            "ram_pct": _safe_round(vm.percent, 1),
        })
        payload.update(_disk_metrics())
        payload.update(_net_metrics())
    except Exception as exc:
        payload["metrics_error"] = f"{type(exc).__name__}: {exc}"
    return payload


def _norm_drive(name: str) -> str:
    text = str(name or "").strip().upper()
    if not text:
        return ""
    if len(text) == 1:
        return f"{text}:"
    return text[:2] if text[1:2] == ":" else text


def _disk_activity() -> tuple[Optional[float], bool]:
    global _DISK_IO_LAST
    if not _HAS_PSUTIL:
        return None, False
    try:
        cur = psutil.disk_io_counters()
        if cur is None:
            return None, False
        now = time.time()
        read_bytes = int(getattr(cur, "read_bytes", 0) or 0)
        write_bytes = int(getattr(cur, "write_bytes", 0) or 0)
        with _DISK_IO_LOCK:
            prev = _DISK_IO_LAST
            _DISK_IO_LAST = (now, read_bytes, write_bytes)
        if not prev:
            return 0.0, False
        prev_ts, prev_read, prev_write = prev
        dt = max(0.001, now - float(prev_ts))
        delta = max(0, read_bytes - int(prev_read)) + max(0, write_bytes - int(prev_write))
        bps = delta / dt
        return _safe_round(bps, 1), bps >= 64 * 1024
    except Exception:
        return None, False


def _disk_metrics() -> dict:
    payload = {
        "disks": [],
        "disk_io_bps": None,
        "disk_active": False,
        "disk_error": "",
    }
    if not _HAS_PSUTIL:
        payload["disk_error"] = _PSUTIL_IMPORT_ERROR
        return payload
    io_bps, active = _disk_activity()
    storage_temps = _latest_storage_temperatures()
    payload["disk_io_bps"] = io_bps
    payload["disk_active"] = active
    for drive in ("C:", "G:"):
        root = drive + "\\" if os.name == "nt" else drive
        rec = {
            "drive": _norm_drive(drive),
            "present": False,
            "total_gb": None,
            "used_gb": None,
            "free_gb": None,
            "pct": None,
            "active": False,
            "io_bps": io_bps,
            "temperature_c": _safe_round(
                storage_temps.get(_norm_drive(drive)), 1),
        }
        try:
            usage = psutil.disk_usage(root)
            rec.update({
                "present": True,
                "total_gb": _safe_round(usage.total / (1024 ** 3), 1),
                "used_gb": _safe_round(usage.used / (1024 ** 3), 1),
                "free_gb": _safe_round(usage.free / (1024 ** 3), 1),
                "pct": _safe_round(usage.percent, 1),
                "active": active,
            })
        except Exception as exc:
            rec["error"] = f"{type(exc).__name__}"
        payload["disks"].append(rec)
    return payload


def _latest_storage_temperatures() -> dict[str, float]:
    """Return fresh logical-drive SSD temperatures from the shared LHM poller."""
    if not _HAS_SENSOR_POLLER:
        return {}
    try:
        reading = sensor_poller.last()
        age = time.time() - float(getattr(reading, "ts", 0.0) or 0.0)
        if age < 0 or age > _STORAGE_TEMP_MAX_AGE_SEC:
            return {}
        values = getattr(reading, "storage_temps_c", {})
        if not isinstance(values, dict):
            return {}
        result = {}
        for drive, value in values.items():
            normalized = _norm_drive(drive)
            rounded = _safe_round(value, 1)
            if normalized and rounded is not None and 0 < rounded < 150:
                result[normalized] = rounded
        return result
    except Exception:
        return {}


def _run_hidden(args, timeout=2.0) -> str:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(args, capture_output=True, text=True, errors="replace",
                       timeout=timeout,
                       creationflags=flags)
    return p.stdout or ""


def _powershell_profiles() -> list[dict]:
    if os.name != "nt":
        return []
    cmd = (
        "Get-NetConnectionProfile -ErrorAction SilentlyContinue | "
        "Select-Object Name,InterfaceAlias,NetworkCategory,"
        "IPv4Connectivity,IPv6Connectivity | ConvertTo-Json -Compress")
    out = _run_hidden(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-Command", cmd],
        timeout=2.0).strip()
    if not out:
        return []
    data = json.loads(out)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    return []


def _wifi_ssid() -> str:
    if os.name != "nt":
        return ""
    try:
        out = _run_hidden(["netsh", "wlan", "show", "interfaces"],
                          timeout=2.0)
    except Exception:
        return ""
    for raw in out.splitlines():
        line = raw.strip()
        if not line.lower().startswith("ssid"):
            continue
        if line.lower().startswith("bssid"):
            continue
        if ":" in line:
            ssid = line.split(":", 1)[1].strip()
            if ssid:
                return ssid
    return ""


def _conn_kind(alias: str, name: str) -> str:
    text = f"{alias} {name}".lower()
    if "tailscale" in text:
        return "TS"
    if "wi-fi" in text or "wifi" in text or "wireless" in text or "wlan" in text:
        return "Wi"
    if "ethernet" in text:
        return "Eth"
    return "Local"


def _conn_category(value) -> str:
    if value == 0 or str(value).strip() == "0":
        return "Pub"
    if value == 1 or str(value).strip() == "1":
        return "Priv"
    if value == 2 or str(value).strip() == "2":
        return "Domain"
    text = str(value or "").strip()
    if text.lower().startswith("priv"):
        return "Priv"
    if text.lower().startswith("pub"):
        return "Pub"
    return text[:6] if text else ""


def _conn_connectivity(profile: dict) -> str:
    vals = [profile.get("IPv4Connectivity"), profile.get("IPv6Connectivity")]
    if any(v == 4 or str(v).strip() == "4" for v in vals):
        return "Internet"
    if any(v == 3 or str(v).strip() == "3" for v in vals):
        return "Local"
    if any(v == 0 or str(v).strip() == "0" for v in vals):
        return "Offline"
    vals = [str(v or "") for v in vals]
    joined = " ".join(vals)
    if "Internet" in joined:
        return "Internet"
    if "LocalNetwork" in joined:
        return "Local"
    if "Disconnected" in joined:
        return "Offline"
    return joined or ""


def _profile_score(profile: dict) -> tuple:
    alias = str(profile.get("InterfaceAlias") or "")
    name = str(profile.get("Name") or "")
    kind = _conn_kind(alias, name)
    conn = _conn_connectivity(profile)
    is_ts = kind == "TS"
    is_internet = conn == "Internet"
    is_local = conn == "Local"
    kind_rank = {"Wi": 0, "Eth": 1, "Local": 2, "TS": 3}.get(kind, 2)
    return (
        0 if is_internet and not is_ts else
        1 if is_local and not is_ts else
        2 if is_ts else 3,
        kind_rank,
        alias.lower(),
    )


def _compact_conn_label(kind: str, name: str, category: str,
                        connectivity: str) -> str:
    if connectivity == "Offline":
        return "Offline"
    # Windows NCSI frequently reports ``LocalNetwork`` on otherwise usable
    # connections (notably on low-power nodes). That describes reachability, not the
    # adapter type.  Preserve the useful Wi-Fi/Ethernet identity and reserve
    # ``Local`` for genuinely unclassified adapters.
    if kind == "Wi":
        clean = str(name or "").strip()
        if not clean or clean.lower() in ("network", "unidentified network"):
            clean = category or "Wi"
        return f"Wi:{clean}"[:12]
    if kind == "Eth":
        return f"Eth:{category or 'net'}"[:12]
    if kind == "TS":
        return "TS"
    return "Local"


def _adapter_fallback_label() -> str:
    if not _HAS_PSUTIL:
        return "Offline"
    try:
        stats = psutil.net_if_stats()
        active = [name for name, st in stats.items()
                  if getattr(st, "isup", False)
                  and "loopback" not in name.lower()]
        if not active:
            return "Offline"
        if any("tailscale" not in name.lower() for name in active):
            return "Local"
        return "TS"
    except Exception:
        return "Offline"


def _connection_summary() -> dict:
    global _CONN_CACHE
    now = time.time()
    with _CONN_LOCK:
        if _CONN_CACHE and now - _CONN_CACHE[0] < 30.0:
            return dict(_CONN_CACHE[1])
    payload = {
        "conn_label": "",
        "conn_type": "",
        "conn_name": "",
        "conn_category": "",
        "conn_connectivity": "",
        "conn_error": "",
    }
    try:
        profiles = _powershell_profiles()
        if not profiles:
            payload["conn_label"] = _adapter_fallback_label()
            payload["conn_type"] = payload["conn_label"]
        else:
            profiles.sort(key=_profile_score)
            chosen = profiles[0]
            alias = str(chosen.get("InterfaceAlias") or "")
            name = str(chosen.get("Name") or "")
            kind = _conn_kind(alias, name)
            category = _conn_category(chosen.get("NetworkCategory"))
            connectivity = _conn_connectivity(chosen)
            if kind == "Wi":
                name = _wifi_ssid() or name
            label = _compact_conn_label(kind, name, category, connectivity)
            payload.update({
                "conn_label": label,
                "conn_type": kind,
                "conn_name": name,
                "conn_category": category,
                "conn_connectivity": connectivity,
            })
    except Exception as exc:
        payload["conn_label"] = _adapter_fallback_label()
        payload["conn_error"] = f"{type(exc).__name__}: {exc}"
    with _CONN_LOCK:
        _CONN_CACHE = (now, dict(payload))
    return payload


def _net_metrics() -> dict:
    """Return network throughput and totals since this metrics server started."""
    global _NET_IO_BASE, _NET_IO_LAST
    payload = {
        "net_down_bps": None,
        "net_up_bps": None,
        "net_down_total_bytes": None,
        "net_up_total_bytes": None,
        "net_error": "",
    }
    if not _HAS_PSUTIL:
        payload["net_error"] = _PSUTIL_IMPORT_ERROR
        return payload
    try:
        cur = psutil.net_io_counters()
        if cur is None:
            payload["net_error"] = "net counters unavailable"
            return payload
        now = time.time()
        recv = int(getattr(cur, "bytes_recv", 0) or 0)
        sent = int(getattr(cur, "bytes_sent", 0) or 0)
        with _NET_IO_LOCK:
            if _NET_IO_BASE is None:
                _NET_IO_BASE = (recv, sent)
            prev = _NET_IO_LAST
            _NET_IO_LAST = (now, recv, sent)
            base_recv, base_sent = _NET_IO_BASE
        payload["net_down_total_bytes"] = max(0, recv - int(base_recv))
        payload["net_up_total_bytes"] = max(0, sent - int(base_sent))
        if prev is None:
            payload["net_down_bps"] = 0.0
            payload["net_up_bps"] = 0.0
            return payload
        prev_ts, prev_recv, prev_sent = prev
        dt = max(0.001, now - float(prev_ts))
        payload["net_down_bps"] = _safe_round(
            max(0, recv - int(prev_recv)) / dt, 1)
        payload["net_up_bps"] = _safe_round(
            max(0, sent - int(prev_sent)) / dt, 1)
    except Exception as exc:
        payload["net_error"] = f"{type(exc).__name__}: {exc}"
    return payload


def metrics_payload() -> dict:
    payload = temp_payload()
    payload.update(cached_system_metrics())
    return payload


def start_background_metrics(interval_sec: float = 1.5):
    """Refresh OS metrics off the HTTP request path."""
    global _METRICS_THREAD, _METRICS_STOP, _METRICS_GENERATION, _METRICS_CACHE
    with _METRICS_LIFECYCLE_LOCK:
        if _METRICS_THREAD is not None and _METRICS_THREAD.is_alive():
            return
        _METRICS_GENERATION += 1
        generation = _METRICS_GENERATION
        stop_event = threading.Event()
        _METRICS_STOP = stop_event
        with _METRICS_LOCK:
            if not _METRICS_CACHE:
                _METRICS_CACHE = _empty_system_metrics()

    def loop():
        global _METRICS_CACHE
        while not stop_event.is_set():
            try:
                payload = _system_metrics()
            except Exception:
                payload = None
            if payload is not None:
                with _METRICS_LIFECYCLE_LOCK:
                    active = (
                        generation == _METRICS_GENERATION
                        and _METRICS_STOP is stop_event
                    )
                if active:
                    with _METRICS_LOCK:
                        _METRICS_CACHE = payload
            if stop_event.wait(timeout=interval_sec):
                break

    thread = threading.Thread(target=loop, daemon=True, name="SysMetricsPoll")
    with _METRICS_LIFECYCLE_LOCK:
        _METRICS_THREAD = thread
    thread.start()


def stop_background_metrics():
    global _METRICS_THREAD, _METRICS_STOP, _METRICS_GENERATION
    with _METRICS_LIFECYCLE_LOCK:
        t = _METRICS_THREAD
        stop_event = _METRICS_STOP
        _METRICS_GENERATION += 1
        _METRICS_THREAD = None
        _METRICS_STOP = None
    if stop_event is not None:
        stop_event.set()
    if t is not None and t.is_alive():
        try:
            t.join(timeout=6.0)
        except Exception:
            pass


def cached_system_metrics() -> dict:
    with _METRICS_LOCK:
        data = dict(_METRICS_CACHE) if _METRICS_CACHE else _empty_system_metrics()
    if isinstance(data.get("disks"), list):
        data["disks"] = [
            dict(item) for item in data["disks"] if isinstance(item, dict)
        ]
    # Cross-PC wall clocks can differ by several seconds. Report cache age on
    # the producing PC so a peer can distinguish fresh data from a stalled
    # poller without subtracting timestamps from two different clocks.
    try:
        data["metrics_age_sec"] = _safe_round(
            max(0.0, time.time() - float(data.get("metrics_ts"))), 3)
    except (TypeError, ValueError):
        data["metrics_age_sec"] = None
    return data


def temp_payload() -> dict:
    if not _HAS_SENSOR_POLLER:
        return {
            "cpu_pkg": None,
            "cpu_max": None,
            "gpu": None,
            "cpu_name": "",
            "gpu_name": "",
            "storage_temps_c": {},
            "ts": time.time(),
            "error": _SENSOR_IMPORT_ERROR,
        }
    return sensor_poller.last().to_dict()


class _TempsHandler(BaseHTTPRequestHandler):
    # silence stdlib logging to stderr
    def log_message(self, format, *args):
        pass

    def setup(self):
        super().setup()
        try:
            self.connection.settimeout(5.0)
        except Exception:
            pass

    def _send_json(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_not_found(self):
        body = b'{"error":"not_found","ok":false}'
        self.send_response(404)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = (self.path or "").split("?", 1)[0]
        if path == "/temps":
            try:
                payload = temp_payload()
            except Exception as exc:
                payload = {"error": f"{type(exc).__name__}: {exc}"}
            self._send_json(200, payload)
        elif path == "/metrics":
            try:
                payload = metrics_payload()
            except Exception as exc:
                payload = {"error": f"{type(exc).__name__}: {exc}"}
            self._send_json(200, payload)
        elif path == "/health":
            payload = {
                "ok": True,
                "version": _APP_VERSION,
                "build_date": _APP_BUILD_DATE,
                "build_tag": _APP_BUILD_TAG,
                "host": socket.gethostname(),
                "pid": os.getpid(),
                "binary": _current_binary_path(),
                "sha256": _binary_sha256(),
                "repair": callable(getattr(self.server, "repair_handler", None)),
                "rdp_password_change_v1": callable(
                    getattr(self.server, "rdp_password_handler", None)),
                "self_update_v1": callable(
                    getattr(self.server, "self_update_handler", None)),
                "cluster_config_v1": callable(
                    getattr(self.server, "cluster_config_handler", None)),
            }
            provider = getattr(self.server, "health_provider", None)
            if callable(provider):
                try:
                    extra = provider()
                    if isinstance(extra, dict):
                        payload.update(extra)
                except Exception as exc:
                    payload["health_provider_error"] = (
                        f"{type(exc).__name__}: {exc}")
            payload.update({
                "repair": False,
                "rdp_password_change_v1": False,
                "self_update_v1": False,
                "cluster_config_v1": False,
            })
            self._send_json(200, payload)
        elif path == "/ping":
            body = b"pong"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_not_found()

    def _repair_client_allowed(self) -> bool:
        try:
            raw = str(self.client_address[0] or "")
        except Exception:
            raw = ""
        try:
            if ipaddress.ip_address(raw).is_loopback:
                return True
        except Exception:
            pass
        allowed = getattr(self.server, "repair_allowed_hosts", None) or set()
        return raw in allowed

    def _control_client_allowed(self) -> bool:
        try:
            raw = str(self.client_address[0] or "")
        except Exception:
            raw = ""
        # Password control never grants an implicit loopback bypass.  The
        # local UI calls the native helper directly; HTTP callers must be in
        # the explicit Tailscale controller allow-list.
        allowed = getattr(self.server, "control_allowed_hosts", None) or set()
        return raw in allowed

    def _update_client_allowed(self) -> bool:
        try:
            raw = str(self.client_address[0] or "")
        except Exception:
            raw = ""
        # Self-update is a distinct privilege boundary and fail-closed.
        allowed = getattr(self.server, "update_allowed_hosts", None) or set()
        return raw in allowed

    def _cluster_client_allowed(self) -> bool:
        try:
            raw = str(self.client_address[0] or "")
        except Exception:
            raw = ""
        allowed = getattr(self.server, "cluster_allowed_hosts", None) or set()
        return raw in allowed

    def _post_cluster_config(self) -> None:
        self._send_not_found()
        return
        if not self._cluster_client_allowed():
            self._send_json(403, {
                "ok": False, "accepted": False, "reason": "forbidden",
                "host": socket.gethostname(),
            })
            return
        if self.headers.get("X-RCM-Cluster") != "v1":
            self._send_json(403, {
                "ok": False, "accepted": False,
                "reason": "header_missing", "host": socket.gethostname(),
            })
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0 or length > 16 * 1024:
            self._send_json(413 if length > 16 * 1024 else 400, {
                "ok": False, "accepted": False, "reason": "invalid_size",
                "host": socket.gethostname(),
            })
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete body")
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {
                "ok": False, "accepted": False, "reason": "invalid_json",
                "host": socket.gethostname(),
            })
            return
        handler = getattr(self.server, "cluster_config_handler", None)
        if not callable(handler):
            self._send_json(503, {
                "ok": False, "accepted": False,
                "reason": "handler_unavailable",
                "host": socket.gethostname(),
            })
            return
        try:
            result = handler(body)
            payload = dict(result) if isinstance(result, dict) else {
                "ok": bool(result), "accepted": bool(result)}
            status = int(payload.pop(
                "_status", 202 if payload.get("accepted") else 409))
            payload.setdefault("host", socket.gethostname())
            self._send_json(status, payload)
        except ValueError as exc:
            self._send_json(400, {
                "ok": False, "accepted": False,
                "reason": str(exc), "host": socket.gethostname(),
            })
        except Exception as exc:
            self._send_json(500, {
                "ok": False, "accepted": False,
                "reason": f"handler_error:{type(exc).__name__}",
                "host": socket.gethostname(),
            })

    def _post_self_update(self) -> None:
        self._send_not_found()
        return
        if not self._update_client_allowed():
            self._send_json(403, {
                "ok": False,
                "accepted": False,
                "reason": "forbidden",
                "host": socket.gethostname(),
            })
            return
        if self.headers.get("X-RCM-Update") != "v1":
            self._send_json(403, {
                "ok": False,
                "accepted": False,
                "reason": "header_missing",
                "host": socket.gethostname(),
            })
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0 or length > 4096:
            self._send_json(413 if length > 4096 else 400, {
                "ok": False,
                "accepted": False,
                "reason": "invalid_size",
                "host": socket.gethostname(),
            })
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete body")
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {
                "ok": False,
                "accepted": False,
                "reason": "invalid_json",
                "host": socket.gethostname(),
            })
            return
        expect_sha = body.get("expect_sha256") if isinstance(body, dict) else None
        source = body.get("source") if isinstance(body, dict) else None
        if (not isinstance(expect_sha, str)
                or not re.fullmatch(r"[A-Fa-f0-9]{64}", expect_sha)
                or not isinstance(source, str)
                or not source):
            self._send_json(400, {
                "ok": False,
                "accepted": False,
                "reason": "invalid_fields",
                "host": socket.gethostname(),
            })
            return
        handler = getattr(self.server, "self_update_handler", None)
        if not callable(handler):
            self._send_json(503, {
                "ok": False,
                "accepted": False,
                "reason": "handler_unavailable",
                "host": socket.gethostname(),
            })
            return
        try:
            result = handler(expect_sha.upper(), source)
            payload = dict(result) if isinstance(result, dict) else {
                "ok": bool(result),
                "accepted": bool(result),
            }
            status = int(payload.pop(
                "_status", 202 if payload.get("accepted") else 409))
            payload.setdefault("host", socket.gethostname())
            self._send_json(status, payload)
        except Exception as exc:
            self._send_json(500, {
                "ok": False,
                "accepted": False,
                "reason": f"handler_error:{type(exc).__name__}",
                "host": socket.gethostname(),
            })

    def _post_rdp_password(self) -> None:
        self._send_not_found()
        return
        if not self._control_client_allowed():
            self._send_json(403, {
                "ok": False,
                "accepted": False,
                "message": "RDP password control forbidden for this client",
                "host": socket.gethostname(),
            })
            return
        if self.headers.get("X-RCM-Control") != "rdp-password-v1":
            self._send_json(403, {
                "ok": False,
                "accepted": False,
                "message": "RDP password control header missing",
                "host": socket.gethostname(),
            })
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0 or length > 4096:
            self._send_json(413 if length > 4096 else 400, {
                "ok": False,
                "accepted": False,
                "message": "invalid RDP password request size",
                "host": socket.gethostname(),
            })
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete request body")
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {
                "ok": False,
                "accepted": False,
                "message": "invalid RDP password request",
                "host": socket.gethostname(),
            })
            return
        username = body.get("username") if isinstance(body, dict) else None
        old_password = body.get("old_password") if isinstance(body, dict) else None
        new_password = body.get("new_password") if isinstance(body, dict) else None
        request_id = body.get("request_id") if isinstance(body, dict) else None
        if (not isinstance(username, str)
                or not isinstance(old_password, str)
                or not isinstance(new_password, str)
                or not isinstance(request_id, str)):
            self._send_json(400, {
                "ok": False,
                "accepted": False,
                "message": "username, passwords, and request_id must be text",
                "host": socket.gethostname(),
            })
            return
        if (not username or not old_password or not new_password
                or not request_id.strip() or len(request_id) > 128
                or any("\x00" in value for value in (
                    username, old_password, new_password, request_id))):
            self._send_json(400, {
                "ok": False,
                "accepted": False,
                "message": "invalid RDP password request fields",
                "host": socket.gethostname(),
            })
            return
        handler = getattr(self.server, "rdp_password_handler", None)
        if not callable(handler):
            self._send_json(503, {
                "ok": False,
                "accepted": False,
                "message": "RDP password handler unavailable",
                "host": socket.gethostname(),
            })
            return
        try:
            result = handler(username, old_password, new_password, request_id)
            result_payload = dict(result) if isinstance(result, dict) else {
                "ok": bool(result),
                "message": "RDP password changed" if result else "RDP password change failed",
            }
            # Whitelist fields instead of trying to blacklist every possible
            # secret alias or nested value returned by a future handler.
            payload = {
                "ok": bool(result_payload.get("ok")),
                "accepted": bool(result_payload.get("accepted", True)),
                # Do not forward arbitrary handler text: a future native/API
                # error could accidentally embed an account or password.
                "message": ("RDP password changed"
                            if result_payload.get("ok")
                            else "RDP password change failed"),
                "request_id": str(result_payload.get("request_id") or request_id or ""),
                "host": socket.gethostname(),
            }
            self._send_json(200 if payload.get("ok") else 409, payload)
        except Exception as exc:
            self._send_json(500, {
                "ok": False,
                "accepted": False,
                "message": f"RDP password change failed ({type(exc).__name__})",
                "host": socket.gethostname(),
            })

    def do_POST(self):
        self._send_not_found()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST


class TempsServer(threading.Thread):
    """Threaded HTTP server that exposes the local sensor reading."""

    def __init__(self, port: int = DEFAULT_PORT, bind: str = "127.0.0.1",
                 repair_handler: Optional[Callable[[], dict]] = None,
                 repair_status_provider: Optional[Callable[[], dict]] = None,
                 health_provider: Optional[Callable[[], dict]] = None,
                 repair_allowed_hosts: Optional[set[str]] = None,
                 rdp_password_handler: Optional[
                     Callable[[str, str, str, str], dict]] = None,
                 control_allowed_hosts: Optional[set[str]] = None,
                 self_update_handler: Optional[
                     Callable[[str, str], dict]] = None,
                 update_allowed_hosts: Optional[set[str]] = None,
                 cluster_config_handler: Optional[
                     Callable[[dict], dict]] = None,
                 cluster_allowed_hosts: Optional[set[str]] = None):
        if bind != "127.0.0.1":
            raise ValueError("bind must be exact IPv4 loopback 127.0.0.1")
        super().__init__(daemon=True, name="TempsServer")
        self.port = port
        self.bind = bind
        self.repair_handler = repair_handler
        self.repair_status_provider = repair_status_provider
        self.health_provider = health_provider
        self.repair_allowed_hosts = set(repair_allowed_hosts or ())
        self.rdp_password_handler = rdp_password_handler
        # Credential control is a separate privilege boundary.  An omitted
        # allow-list means deny-all, never inherit the repair allow-list.
        self.control_allowed_hosts = set(control_allowed_hosts or ())
        self.self_update_handler = self_update_handler
        # Self-update also fails closed and never inherits another allow-list.
        self.update_allowed_hosts = set(update_allowed_hosts or ())
        self.cluster_config_handler = cluster_config_handler
        # Cluster reconfiguration is a third independent fail-closed boundary.
        self.cluster_allowed_hosts = set(cluster_allowed_hosts or ())
        self._server: Optional[ThreadingHTTPServer] = None
        # Do not shadow threading.Thread._started: Thread.start() sets that
        # internal event before run() creates the HTTP server.
        self._ready = threading.Event()
        self.error: Optional[str] = None

    def run(self):
        try:
            if _HAS_PSUTIL:
                try:
                    psutil.cpu_percent(interval=0.05)
                except Exception:
                    pass
            self._server = ThreadingHTTPServer((self.bind, self.port),
                                               _TempsHandler)
            self._server.health_provider = self.health_provider
            start_background_metrics()
            self._ready.set()
            self._server.serve_forever(poll_interval=0.5)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self._ready.set()
        finally:
            stop_background_metrics()

    def stop(self):
        stop_background_metrics()
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass

    def wait_ready(self, timeout: float = 3.0) -> bool:
        return self._ready.wait(timeout=timeout) and self.error is None


# =========================================================================
# CLI test
# =========================================================================
if __name__ == "__main__":
    import time
    if _HAS_SENSOR_POLLER:
        sensor_poller.start_background_poll(interval_sec=2.0)
    else:
        print(f"sensor_poller unavailable: {_SENSOR_IMPORT_ERROR}")
    srv = TempsServer()
    srv.start()
    if not srv.wait_ready():
        print(f"server failed: {srv.error}")
        raise SystemExit(1)
    print(f"serving locally on http://127.0.0.1:{srv.port}/temps")
    print("ctrl-c to stop. local test: curl http://127.0.0.1:8866/temps")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
        if _HAS_SENSOR_POLLER:
            sensor_poller.stop_background_poll()
