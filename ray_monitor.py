"""
Ray Cluster Manager  --  Win98 classic-text edition

Pure tkinter (no theming).  Plain raised/sunken 3D borders, MS-Sans-Serif/Tahoma
8pt, the canonical #c0c0c0 system gray, and a black diagnostic console.  Looks
like a Win98/2K control panel.

Ray is still launched with CREATE_NO_WINDOW so closing this window never sends
CTRL_CLOSE_EVENT to the daemons.  The head daemonizes and survives the GUI; the
worker is held as a hidden --block child of the GUI.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import csv
import glob
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import uuid

_IS_WIN = os.name == "nt"
_DPI_AWARENESS = "not-windows"


def _enable_dpi_awareness():
    """Opt in before tkinter is imported so Windows does not bitmap-scale Tk."""
    global _DPI_AWARENESS
    if not _IS_WIN:
        return
    try:
        # Prefer Per-Monitor V2. This matters most through RDP and on 4K
        # panels running a lower desktop mode, where system-aware Tk can be
        # bitmap-scaled into an oversized window.
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        ctx = ctypes.c_void_p(-4)  # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        if user32.SetProcessDpiAwarenessContext(ctx):
            _DPI_AWARENESS = "per-monitor-v2"
        else:
            _DPI_AWARENESS = f"pmv2 failed err={ctypes.get_last_error()}"
    except Exception as exc:
        _DPI_AWARENESS = f"pmv2 failed: {type(exc).__name__}"
    try:
        result = ctypes.windll.shcore.SetProcessDpiAwareness(2)
        _DPI_AWARENESS += f"; per-monitor hresult={result}"
    except Exception as exc:
        _DPI_AWARENESS += f"; shcore pm failed: {type(exc).__name__}"
        try:
            result = ctypes.windll.shcore.SetProcessDpiAwareness(1)
            _DPI_AWARENESS += f"; system hresult={result}"
        except Exception as exc2:
            _DPI_AWARENESS += f"; shcore system failed: {type(exc2).__name__}"
            try:
                ctypes.windll.user32.SetProcessDPIAware()
                _DPI_AWARENESS += "; user32-aware"
            except Exception as exc3:
                _DPI_AWARENESS += f"; user32 failed: {type(exc3).__name__}"
    try:
        awareness = ctypes.c_int(-1)
        ctypes.windll.shcore.GetProcessDpiAwareness(
            None, ctypes.byref(awareness))
        _DPI_AWARENESS += f"; current={awareness.value}"
    except Exception:
        pass


_enable_dpi_awareness()

import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from dataclasses import dataclass, field, replace
from datetime import datetime
from tkinter import ttk, filedialog, messagebox   # v1.3: Browse + Firewall dialogs
from typing import Callable, Optional
from src.rcm.legacy_compat import ActionResult, LegacyRayAppMixin, _is_real_sha, _norm_file_path, _replacement_targets_from_processes, bind_legacy_globals, current_binary_path, file_sha256, needs_rcm_control_server, save_config

import requests

from release_info import (
    BUILD_DATE as APP_BUILD_DATE,
    BUILD_TAG as APP_BUILD_TAG,
    DISPLAY_VERSION as APP_VERSION,
)
from windows_credentials import (
    AccountValidationError,
    CredentialValidationError,
    WindowsSecurityError,
    change_local_account_password,
    delete_rdp_credential,
    generate_strong_password,
    rdp_credential_matches,
    rdp_credential_exists,
    write_rdp_credential,
)

try:
    import pystray
    from PIL import Image
    _HAS_TRAY = True
except Exception:
    pystray = None
    Image = None
    _HAS_TRAY = False

# v1.1: temperature monitoring (LHM embedded via pythonnet)
# v1.4: keep OS CPU/RAM metrics independent from the temperature stack.
try:
    import sensor_poller
    _HAS_SENSOR = True
    _sensor_import_error = ""
except Exception as _sensor_exc:
    sensor_poller = None
    _HAS_SENSOR = False
    _sensor_import_error = f"{type(_sensor_exc).__name__}: {_sensor_exc}"

try:
    import temps_server
    _HAS_TEMPS_SERVER = True
    _temps_server_import_error = ""
except Exception as _server_exc:
    temps_server = None
    _HAS_TEMPS_SERVER = False
    _temps_server_import_error = f"{type(_server_exc).__name__}: {_server_exc}"

_HAS_TEMP = _HAS_SENSOR and _HAS_TEMPS_SERVER
_temp_import_error = "; ".join(
    e for e in (_sensor_import_error, _temps_server_import_error) if e
)

try:
    from status_board_content import BoardFeed
    _HAS_STATUS_BOARD_CONTENT = True
    _status_board_content_error = ""
except Exception as _board_exc:
    BoardFeed = None
    _HAS_STATUS_BOARD_CONTENT = False
    _status_board_content_error = f"{type(_board_exc).__name__}: {_board_exc}"

try:
    from process_cleanup import CleanupPolicy
    from process_cleanup_ui import ProcessCleanupDialog
    _HAS_PROCESS_CLEANUP = True
    _process_cleanup_import_error = ""
except Exception as _cleanup_exc:
    CleanupPolicy = None
    ProcessCleanupDialog = None
    _HAS_PROCESS_CLEANUP = False
    _process_cleanup_import_error = (
        f"{type(_cleanup_exc).__name__}: {_cleanup_exc}")


APP_NAME = "Ray Cluster Manager"
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200
_RAY_PROC_NAMES = ["raylet.exe", "gcs_server.exe", "plasma_store_server.exe"]
_mutex_handle = None
AUTO_UI_SCALING_FLOOR = 96.0 / 72.0
AUTO_UI_SCALING_CEILING = 3.0
MAIN_BASE_WIDTH = 1120   # canonical preferred window width at the 96-DPI floor
MAIN_MIN_WIDTH = 620


# ---------------------------------------------------------------------------
# v1.5.33 [fitscreen]: PURE scaling math (no Tk) so the GUI and the regression
# test (test_dpi_scaling.py) cannot drift. The instance methods delegate here.
# These pin the "window stuck small" bug: a 4K screen never resolves below 2.0
# even when a too-low DPI (RDP/96) is reported, because the comfort floor is
# folded in BEFORE the clamp.
# ---------------------------------------------------------------------------
def comfort_floor_for_screen(screen_w, floor=AUTO_UI_SCALING_FLOOR):
    """Readability floor by screen width, so a physically large screen running
    at 100%/RDP-96 is not left at the bare 96-DPI minimum."""
    try:
        sw = int(screen_w)
    except (TypeError, ValueError):
        return floor
    if sw >= 3840:
        tier = 2.00
    elif sw >= 2560:
        tier = 1.67
    elif sw >= 1920:
        tier = 1.50
    else:
        tier = floor
    return max(floor, float(tier))


def clamp_scaling(value, floor=AUTO_UI_SCALING_FLOOR, ceiling=AUTO_UI_SCALING_CEILING):
    """Clamp a UI scale into [floor, ceiling]; bad / NaN / <= 0 -> floor."""
    try:
        v = float(value)
        if v <= 0 or v != v:
            raise ValueError
        return max(floor, min(ceiling, v))
    except (TypeError, ValueError):
        return floor


def fit_scale(dpi, screen_w):
    """Return text scale from effective DPI, not desktop resolution.

    RDP can change resolution without changing effective DPI.  Treating screen
    width as a readability floor made RCM text jump while other applications
    stayed stable.  Width is therefore only a fallback when Windows cannot
    report a usable DPI; window geometry still follows the monitor separately.
    """
    try:
        measured_dpi = float(dpi or 0.0)
    except (TypeError, ValueError):
        measured_dpi = 0.0
    if measured_dpi > 0:
        measured = clamp_scaling(measured_dpi / 72.0)
    else:
        measured = clamp_scaling(comfort_floor_for_screen(screen_w))
    return round(float(measured), 3)


def fit_width(scale, screen_w, base_w=MAIN_BASE_WIDTH, min_w=MAIN_MIN_WIDTH):
    """Preferred window width for a UI scale, clamped to the screen. Divides by
    AUTO_UI_SCALING_FLOOR (NOT a 1.333 literal) so width tracks scale exactly."""
    scaled = int(round(int(base_w) * (float(scale) / AUTO_UI_SCALING_FLOOR)))
    try:
        screen_max = max(int(min_w), int(screen_w) - 40)
    except (TypeError, ValueError):
        screen_max = scaled
    return max(int(min_w), min(scaled, screen_max))


def scaled_px(px, scale):
    """Scale a hardcoded pixel dimension by a UI scale relative to the 96-DPI
    floor (unchanged at the floor, ~1.5x at 2.0). Used for Toplevel dialog
    geometry/minsize/wraplength so dialogs are not cramped at high DPI."""
    try:
        return int(round(int(px) * float(scale) / AUTO_UI_SCALING_FLOOR))
    except (TypeError, ValueError):
        return int(px)


def content_fit_geometry(text_width_px, char_width_px, node_count,
                         row_height_px, chrome_width_px, chrome_height_px,
                         work_area, current_xy=(0, 0), min_size=(620, 430),
                         right_margin_chars=2, spare_rows=1,
                         vertical_scrollbar_width_px=0,
                         horizontal_scrollbar_height_px=0):
    """Return a monitor-clamped geometry for the manual content-fit action.

    ``text_width_px`` is the widest *rstrip'd* header/node row measured with
    its actual Tk font.  Chrome values are everything outside the list text
    viewport.  Keeping this calculation pure makes the important layout
    contract testable without a display server.
    """
    try:
        wx, wy, ww, wh = (int(v) for v in work_area)
    except (TypeError, ValueError):
        wx, wy, ww, wh = 0, 0, 1920, 1080
    ww, wh = max(1, ww), max(1, wh)
    min_w, min_h = (max(1, int(v)) for v in min_size)
    text_w = max(0, int(text_width_px))
    char_w = max(1, int(char_width_px))
    rows = max(0, int(node_count)) + max(0, int(spare_rows))
    base_w = max(min_w, int(chrome_width_px) + text_w
                 + max(0, int(right_margin_chars)) * char_w)
    base_h = max(min_h, int(chrome_height_px)
                 + rows * max(1, int(row_height_px)))
    vbar_w = max(0, int(vertical_scrollbar_width_px))
    hbar_h = max(0, int(horizontal_scrollbar_height_px))

    # Scrollbars affect the opposite axis.  Find the smallest stable layout:
    # a vertical bar consumes width and can require a horizontal bar; that
    # horizontal bar consumes height and can in turn require a vertical bar.
    # The flags only move False->True, so two propagation passes suffice.
    horizontal = base_w > ww
    vertical = base_h > wh
    for _ in range(2):
        horizontal = horizontal or (base_w + (vbar_w if vertical else 0) > ww)
        vertical = vertical or (base_h + (hbar_h if horizontal else 0) > wh)
    desired_w = base_w + (vbar_w if vertical else 0)
    desired_h = base_h + (hbar_h if horizontal else 0)
    width, height = min(desired_w, ww), min(desired_h, wh)
    try:
        cur_x, cur_y = (int(v) for v in current_xy)
    except (TypeError, ValueError):
        cur_x, cur_y = wx, wy
    x = max(wx, min(cur_x, wx + ww - width))
    y = max(wy, min(cur_y, wy + wh - height))
    return {
        "x": x, "y": y, "width": width, "height": height,
        "desired_width": desired_w, "desired_height": desired_h,
        "horizontal_scroll": horizontal,
        "vertical_scroll": vertical,
        "visible_rows": rows,
    }


NODE_COL_WIDTH = 11
NODE_RAY_COL_WIDTH = 6
NODE_RAM_COL_WIDTH = 6
NODE_DISK_COL_WIDTH = 16
NODE_NET_COL_WIDTH = 8
NODE_PING_COL_WIDTH = 4
NODE_CONN_COL_WIDTH = 16
DIAG_FONT_CHOICES = ("Consolas", "Terminal", "Fixedsys", "Courier New")

# Win98 palette
GRAY     = "#c0c0c0"      # face
GRAY_LT  = "#dfdfdf"      # 3D highlight
GRAY_DK  = "#808080"      # 3D shadow
GRAY_DKR = "#404040"      # darkest
BLACK    = "#000000"
WHITE    = "#ffffff"
BLUE98   = "#000080"      # the canonical Win98 progress / selection blue
RED      = "#c00000"
GREEN    = "#008000"


# =========================================================================
#  Paths & config
# =========================================================================
def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", app_dir())
    p = os.path.join(base, rel)
    return p if os.path.exists(p) else os.path.join(app_dir(), rel)






def config_dir() -> str:
    base = os.environ.get("APPDATA") or app_dir()
    d = os.path.join(base, "RayClusterManager")
    os.makedirs(d, exist_ok=True)
    return d


CONFIG_PATH = os.path.join(config_dir(), "config.json")
LOG_PATH = os.path.join(config_dir(), "ray_monitor.log")
TROUBLE_LOG_PATH = os.path.join(config_dir(), "trouble_log.log")
PROCESS_CLEANUP_LOG_PATH = os.path.join(
    config_dir(), "process_cleanup.log")
DEFAULT_OFFICIAL_EXE_PATH = os.environ.get(
    "RCM_OFFICIAL_EXE_PATH",
    "")
DEFAULT_CLUSTER_MANIFEST_PATH = os.environ.get(
    "RCM_CLUSTER_MANIFEST_PATH",
    "")

DEFAULT_CONFIG = {
    "schema_version": 15,
    "head_ip": "",
    "head_port": 6379,
    "dashboard_port": 8265,
    "ray_exe": "auto",
    "this": {
        "role": "auto", "mode": "auto", "ip": "auto", "num_cpus": "auto"},
    "nodes": [],
    # Password-management operators are independent of Ray/controller mode.
    "credential_controller_ips": [],
    "update_controller_ips": [],
    "cluster_controller_ips": [],
    "official_exe_path": DEFAULT_OFFICIAL_EXE_PATH,
    "cluster_manifest_path": DEFAULT_CLUSTER_MANIFEST_PATH,
    "cluster_epoch": 0,
    "poll_interval": 1.5,
    "dashboard_timeout_sec": 6.0,
    "dashboard_unreachable_failures": 3,
    "dashboard_stale_grace_sec": 45.0,
    "theme": "classic",
    "on_close": "tray",   # v1.2: X=트레이로 복원 (백그라운드 8866/sensor/ray 모니터 유지). 진짜 종료는 트레이 Quit (3s hard-kill 보장).
    "stop_on_quit": False,
    "start_on_launch": False,
    "autostart_login": False,
    # v1.1: temperature monitoring
    "temp_enabled": True,
    "temp_warn_c": 80,        # 노란색 표시 임계 (모든 PC 공통)
    "temp_critical_c": 100,   # 빨간색 + auto-pause 임계 (모든 PC 공통)
    "temp_auto_pause": False, # 기본 OFF — critical 도달 시 자동 ray stop
    "temp_port": 8866,
    "temp_poll_sec": 2.0,
    # v1.4: OS CPU/RAM monitoring via the same RCM endpoint
    "metrics_enabled": True,
    "metrics_timeout_sec": 3.0,
    "node_row_mode": "compact",
    "diagnostic_font": "Consolas",
    "process_cleanup": {
        "sample_sec": 8.0,
        "grace_sec": 3.0,
        "result_max_age_sec": 60.0,
        "ignored_fingerprints": [],
    },
    "ui_scale_mode": "stable",
    "ui_scaling": "auto",
    "main_width": 0,
    "os_cpu_warn_pct": 80,
    "os_cpu_critical_pct": 95,
    "ram_warn_pct": 85,
    "ram_critical_pct": 95,
    "disk_warn_pct": 85,
    "disk_critical_pct": 95,
    # v1.4.2: pin Ray worker ports so Tailscale firewall rules can be exact.
    "ray_worker_fixed_ports": True,
    "ray_worker_node_manager_port": 6380,
    "ray_worker_object_manager_port": 6381,
    "ray_worker_runtime_env_agent_port": 6382,
    "ray_worker_dashboard_agent_grpc_port": 6383,
    "ray_worker_dashboard_agent_listen_port": 6384,
    "ray_worker_metrics_export_port": 6385,
    "ray_worker_min_port": 10002,
    "ray_worker_max_port": 10100,
    # v1.1 P-list: §15 함정 회피 — head whoami 와 worker 다르면 --temp-dir 주입
    "head_whoami": "",
    # v1.1 P-list: §B 워치독 활성화 (60초 주기)
    "watchdog_enabled": True,
    "watchdog_interval_sec": 60,
    "watchdog_stale_cycles": 3,
    "head_dashboard_guard_enabled": True,
    "head_dashboard_guard_interval_sec": 20,
    "head_dashboard_guard_cycles": 3,
}

_LEGACY_LABELS = {}

LEGACY_CONTROLLER_IP = "192.0.2.25"


def is_controller_mode(mode) -> bool:
    """Accept every persisted spelling of the outbound-only RCM role."""
    return str(mode or "").strip().lower() in {
        "controller", "rdp-client", "rdp",
    }


def is_controller_node(node) -> bool:
    """Recognize controllers by their configured mode, never by machine IP."""
    if not isinstance(node, dict):
        return False
    return is_controller_mode(node.get("mode"))


def normalize_controller_config(
        cfg: dict, legacy_schema: Optional[int] = None) -> dict:
    """Return a normalized copy of controller mode aliases.

    Schema 12 and older briefly treated one configured node as an outbound-only
    controller. Loading those configs restores that node to a normal Ray worker, keeps the
    first duplicate record, and clears its unset-by-design RDP account.  From
    schema 13 onward every node follows the same editable rules.
    """
    normalized = json.loads(json.dumps(cfg))
    migrate_legacy_controller = (legacy_schema is not None
                                 and int(legacy_schema) < 13)
    this_cfg = normalized.get("this")
    if isinstance(this_cfg, dict):
        this_ip = str(this_cfg.get("ip") or "").strip()
        if migrate_legacy_controller and this_ip == LEGACY_CONTROLLER_IP:
            this_cfg["mode"] = "ray"
            this_cfg["role"] = "worker"
        elif is_controller_mode(this_cfg.get("mode")):
            this_cfg["mode"] = "controller"

    nodes = normalized.get("nodes")
    if not isinstance(nodes, list):
        return normalized
    unique_nodes = []
    seen_legacy_controller = False
    for node in nodes:
        if not isinstance(node, dict):
            unique_nodes.append(node)
            continue
        node_ip = str(node.get("ip") or "").strip()
        if migrate_legacy_controller and node_ip == LEGACY_CONTROLLER_IP:
            if seen_legacy_controller:
                continue
            seen_legacy_controller = True
            node["mode"] = "ray"
            node["role"] = "worker"
            node["rdp_user"] = ""
        elif is_controller_node(node):
            node["mode"] = "controller"
        unique_nodes.append(node)
    normalized["nodes"] = unique_nodes
    return normalized


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    # Keep the schema from the file itself.  Reading it from ``cfg`` after the
    # deep merge would incorrectly make a schema-less legacy file look like
    # the current schema because DEFAULT_CONFIG already carries that value.
    loaded_schema = 0
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            user = json.load(f)
        if isinstance(user, dict):
            try:
                loaded_schema = int(user.get("schema_version") or 0)
            except (TypeError, ValueError):
                loaded_schema = 0
            _deep_update(cfg, user)
    except FileNotFoundError:
        pass
    except Exception as exc:
        print("config read error:", exc)
        _backup_corrupt_config()
    if not isinstance(cfg.get("this"), dict):
        cfg["this"] = json.loads(json.dumps(DEFAULT_CONFIG["this"]))
    for k, v in DEFAULT_CONFIG["this"].items():
        cfg["this"].setdefault(k, v)
    if not isinstance(cfg.get("nodes"), list):
        cfg["nodes"] = json.loads(json.dumps(DEFAULT_CONFIG["nodes"]))
    migrated = False
    normalized = normalize_controller_config(cfg, legacy_schema=loaded_schema)
    if normalized != cfg:
        cfg = normalized
        migrated = True
    for n in cfg["nodes"]:
        if isinstance(n, dict) and n.get("name") in _LEGACY_LABELS:
            n["name"] = _LEGACY_LABELS[n["name"]]
            migrated = True
    seen_ips = {n.get("ip") for n in cfg["nodes"] if isinstance(n, dict)}
    for n in DEFAULT_CONFIG["nodes"]:
        if n.get("ip") not in seen_ips:
            # Generic controller defaults are optional once their schema has
            # been persisted. Ray workers remain part of the default inventory.
            if (is_controller_node(n)
                    and loaded_schema >= DEFAULT_CONFIG["schema_version"]):
                continue
            cfg["nodes"].append(json.loads(json.dumps(n)))
            migrated = True
        else:
            for cur in cfg["nodes"]:
                if not isinstance(cur, dict) or cur.get("ip") != n.get("ip"):
                    continue
                for k in ("name", "mode", "role", "num_cpus"):
                    if k not in cur or cur.get(k) in (None, ""):
                        cur[k] = n.get(k)
                        migrated = True
                if "rdp_user" not in cur and n.get("rdp_user"):
                    cur["rdp_user"] = n.get("rdp_user", "")
                    migrated = True
                break
    if cfg.get("poll_interval") in (3, 5):
        cfg["poll_interval"] = 1.5
        migrated = True
    if cfg.get("on_close") != "tray":
        cfg["on_close"] = "tray"
        migrated = True
    configured_controllers = list(
        cfg.get("credential_controller_ips", []) or [])
    expected_controllers = credential_controller_allowlist(
        cfg.get("head_ip", ""), cfg.get("nodes", []),
        configured_controllers)
    if cfg.get("credential_controller_ips") != expected_controllers:
        cfg["credential_controller_ips"] = expected_controllers
        migrated = True
    schema_version = loaded_schema
    if loaded_schema < 14 and cfg["this"].get("num_cpus") == 0:
        # Schema <=13 used zero as "auto".  From schema 14 onward an integer
        # zero is reserved for a real Ray driver-only node.
        cfg["this"]["num_cpus"] = "auto"
        migrated = True
    if schema_version < 11:
        try:
            if float(cfg.get("metrics_timeout_sec") or 0.0) < 3.0:
                cfg["metrics_timeout_sec"] = 3.0
                migrated = True
        except Exception:
            cfg["metrics_timeout_sec"] = 3.0
            migrated = True
        try:
            if int(cfg.get("temp_port") or 0) == 18871:
                cfg["temp_port"] = DEFAULT_CONFIG["temp_port"]
                migrated = True
        except Exception:
            pass
    if loaded_schema < DEFAULT_CONFIG["schema_version"]:
        cfg["schema_version"] = DEFAULT_CONFIG["schema_version"]
        migrated = True
    try:
        if adopt_cluster_manifest(cfg):
            migrated = True
    except Exception as exc:
        print("cluster manifest read error:", exc)
    if migrated:
        save_config(cfg)
    if os.environ.get("RCM_SKIP_UAC_FOR_TESTS") == "1":
        test_port = os.environ.get("RCM_TEST_TEMP_PORT")
        if test_port:
            try:
                port = int(test_port)
                if 0 < port <= 65535:
                    cfg["_persist_temp_port"] = cfg.get("temp_port")
                    cfg["temp_port"] = port
            except Exception:
                pass
    return cfg




def validate_cluster_manifest(payload: dict) -> dict:
    """Return a normalized cluster definition or raise ValueError."""
    if not isinstance(payload, dict):
        raise ValueError("cluster manifest must be an object")
    epoch = payload.get("epoch")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise ValueError("epoch must be a non-negative integer")
    head_ip = str(payload.get("head_ip") or "").strip()
    try:
        ipaddress.ip_address(head_ip)
    except ValueError as exc:
        raise ValueError("head_ip must be a valid IP address") from exc
    raw_nodes = payload.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise ValueError("nodes must be a non-empty list")
    nodes = []
    seen_ips = set()
    heads = 0
    for raw in raw_nodes:
        if not isinstance(raw, dict):
            raise ValueError("every node must be an object")
        node = dict(raw)
        ip = str(node.get("ip") or "").strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError("node ip must be valid") from exc
        if ip in seen_ips:
            raise ValueError("node IPs must be unique")
        seen_ips.add(ip)
        role = str(node.get("role") or "worker").lower()
        if role not in ("head", "worker"):
            raise ValueError("node role must be head or worker")
        try:
            cpus = int(node.get("num_cpus"))
        except (TypeError, ValueError) as exc:
            raise ValueError("node num_cpus must be an integer") from exc
        if not 0 <= cpus <= 4096:
            raise ValueError("node num_cpus must be 0 to 4096")
        heads += role == "head"
        node.update({
            "name": str(node.get("name") or ip).strip() or ip,
            "ip": ip,
            "role": role,
            "mode": "ray",
            "num_cpus": cpus,
        })
        node.setdefault("rdp_user", "")
        nodes.append(node)
    if heads != 1:
        raise ValueError("manifest must contain exactly one head")
    if not any(node["ip"] == head_ip and node["role"] == "head"
               for node in nodes):
        raise ValueError("head_ip must match the head node")
    return {
        "epoch": epoch,
        "head_ip": head_ip,
        "updated": str(payload.get("updated") or ""),
        "updated_by": str(payload.get("updated_by") or ""),
        "nodes": nodes,
    }


def write_cluster_manifest(path: str, payload: dict) -> dict:
    """Validate and atomically replace the shared cluster manifest."""
    manifest = validate_cluster_manifest(payload)
    target = os.path.normpath(str(path or ""))
    if not target:
        raise ValueError("cluster manifest path is empty")
    parent = os.path.dirname(target)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = (
        target + f".tmp.{os.getpid()}.{threading.get_ident()}."
        + uuid.uuid4().hex)
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
    return manifest


def adopt_cluster_manifest(cfg: dict) -> bool:
    """Adopt a newer shared epoch at startup; offline PCs converge here."""
    path = str(
        cfg.get("cluster_manifest_path")
        or DEFAULT_CLUSTER_MANIFEST_PATH)
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as handle:
        manifest = validate_cluster_manifest(json.load(handle))
    try:
        current_epoch = int(cfg.get("cluster_epoch") or 0)
    except (TypeError, ValueError):
        current_epoch = 0
    if manifest["epoch"] <= current_epoch:
        return False
    cfg["head_ip"] = manifest["head_ip"]
    cfg["nodes"] = manifest["nodes"]
    cfg["cluster_epoch"] = manifest["epoch"]
    return True


def _backup_corrupt_config() -> None:
    try:
        if os.path.exists(CONFIG_PATH):
            os.replace(CONFIG_PATH, CONFIG_PATH + ".bak")
    except Exception:
        pass


def _deep_update(base: dict, extra: dict) -> None:
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v


def _num_or_none(value) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


# =========================================================================
#  Environment detection
# =========================================================================
_ray_exe_cache: dict = {}  # v1.2.1: cache; v1.3.1: TTL on None entries
_RAY_EXE_NONE_TTL = 300.0   # 5 min — short enough so user pip-install is picked up


def _clean_ray_exe_path(path: Optional[str]) -> str:
    return (path or "").strip().strip('"').strip("'")


def _is_valid_ray_exe(path: Optional[str]) -> bool:
    path = _clean_ray_exe_path(path)
    return (bool(path)
            and os.path.isfile(path)
            and os.path.basename(path).lower() == "ray.exe")


def find_ray_exe(configured: str = "auto") -> Optional[str]:
    """v1.2: 강화된 탐색 — Python 3.10~3.13 + where ray + 사용자 home 재귀 fallback.
    v1.3.1: None 캐시 5분 TTL (이전엔 영구 → ray.exe 설치해도 재시작해야 인식).
    v1.5.0: include embedded/manual Python under %USERPROFILE%\\Python3xx."""
    configured = _clean_ray_exe_path(configured or "auto")
    if configured and configured != "auto" and _is_valid_ray_exe(configured):
        return configured
    if configured in _ray_exe_cache:
        cached_path, cached_ts = _ray_exe_cache[configured]
        if cached_path is None:
            # None 캐시는 TTL 짧게
            if (time.time() - cached_ts) < _RAY_EXE_NONE_TTL:
                return None
        elif _is_valid_ray_exe(cached_path):
            return cached_path
    # 1) standard install paths (Python 3.10~3.13, LOCALAPPDATA + APPDATA)
    candidates = []
    for ver in ("313", "312", "311", "310"):
        candidates.append(
            os.path.expandvars(rf"%LOCALAPPDATA%\Programs\Python\Python{ver}\Scripts\ray.exe"))
        candidates.append(
            os.path.expandvars(rf"%APPDATA%\Python\Python{ver}\Scripts\ray.exe"))
        candidates.append(
            os.path.expandvars(rf"%USERPROFILE%\Python{ver}\Scripts\ray.exe"))
    home = os.environ.get("USERPROFILE")
    if home:
        candidates.extend(sorted(
            glob.glob(os.path.join(home, "Python3*", "Scripts", "ray.exe")),
            reverse=True))
    now = time.time()
    for c in candidates:
        if _is_valid_ray_exe(c):
            _ray_exe_cache[configured] = (c, now)
            return c
    # 2) PATH search
    from shutil import which
    w = which("ray")
    if _is_valid_ray_exe(w):
        _ray_exe_cache[configured] = (w, now)
        return w
    # 3) last-resort recursive scan under %USERPROFILE%\AppData (depth-limited).
    # Prune known noise to keep walk fast (v1.2.1).
    noise = ("Microsoft", "Packages", "NuGet", "npm-cache", "Mozilla",
             "Google", "WindowsApps", "Steam", "Discord", "Slack")
    found_other: Optional[str] = None
    if home:
        base = os.path.join(home, "AppData")
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                # depth guard
                depth = root[len(base):].count(os.sep)
                if depth > 6:
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs if d not in noise]
                if "ray.exe" in files:
                    p = os.path.join(root, "ray.exe")
                    if not _is_valid_ray_exe(p):
                        continue
                    if "Scripts" in root:
                        _ray_exe_cache[configured] = (p, now)
                        return p
                    if found_other is None:
                        found_other = p
    if found_other:
        _ray_exe_cache[configured] = (found_other, now)
        return found_other
    _ray_exe_cache[configured] = (None, now)
    return None


def local_ip_towards(head_ip: str) -> str:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect((head_ip, 9))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("100."):
                return ip
    except Exception:
        pass
    return ""


def _tcp_open(host: str, port: int, timeout: float = 0.18) -> bool:
    if not host or not port:
        return False
    s = None
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        return True
    except Exception:
        return False
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass


def _dashboard_alive_ips(cfg: dict, timeout: float = 3.0) -> tuple[set[str], bool]:
    """Return ALIVE Ray node IPs plus whether the dashboard check succeeded."""
    try:
        head_ip = str(cfg.get("head_ip") or "")
        dash_port = int(cfg.get("dashboard_port") or 8265)
        if not head_ip or not dash_port:
            return set(), False
        url = f"http://{head_ip}:{dash_port}/api/v0/nodes"
        r = requests.get(url, timeout=max(0.5, timeout), params={"limit": 200})
        r.raise_for_status()
        payload = r.json() if r.content else {}
        rows = (((payload or {}).get("data") or {}).get("result") or {}).get("result") or []
        ips = set()
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            if row.get("state") != "ALIVE":
                continue
            ip = str(row.get("node_ip") or "").strip()
            if ip:
                ips.add(ip)
        return ips, True
    except Exception:
        return set(), False


def _dashboard_ip_alive(cfg: dict, ip: str, timeout: float = 3.0) -> tuple[bool, bool]:
    ips, checked = _dashboard_alive_ips(cfg, timeout=timeout)
    return (bool(ip and ip in ips), checked)


def _tail_text(path: str, max_bytes: int = 65536) -> str:
    try:
        if not os.path.exists(path):
            return ""
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(-max_bytes, os.SEEK_END)
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


_LOG_WRITE_LOCK = threading.RLock()
_LOG_MAX_BYTES = 256 * 1024
_LEGACY_LOG_STALE_SEC = 60.0


def _append_log_record(
        path: str, text: str, max_bytes: int = _LOG_MAX_BYTES) -> None:
    """Append one complete record, closing the handle before any rotation.

    Opening the destination for every record is deliberate.  If an older RCM
    or a sync/backup tool renames the active file, the next write reopens the
    canonical path instead of following the renamed ``.old`` file.
    """
    with _LOG_WRITE_LOCK:
        if os.path.exists(path) and os.path.getsize(path) > max_bytes:
            try:
                os.replace(path, path + ".old")
            except OSError:
                # A transient reader may hold the file on Windows.  Keep
                # logging to the canonical path and try rotation next time.
                pass
        with open(path, "a", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()


def _newer_legacy_log(
        path: str, now: Optional[float] = None,
        stale_after_sec: float = _LEGACY_LOG_STALE_SEC) -> tuple[str, str]:
    """Select a stranded ``.old`` log and return a user-facing warning."""
    legacy = path + ".old"
    if not os.path.exists(legacy):
        return path, ""
    try:
        legacy_mtime = os.path.getmtime(legacy)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return legacy, (
                "Warning: the active log is missing or empty; "
                "showing the newer legacy .old log.")
        current_mtime = os.path.getmtime(path)
        clock = time.time() if now is None else float(now)
        if (legacy_mtime > current_mtime
                and clock - current_mtime >= max(0.0, stale_after_sec)):
            return legacy, (
                "Warning: the active log is stale; "
                "showing the newer legacy .old log.")
    except OSError:
        pass
    return path, ""


def _current_session_log(text: str) -> str:
    """Keep diagnostic rules from reacting to stale errors from older runs."""
    marker = f"v{APP_VERSION} build "
    idx = (text or "").rfind(marker)
    if idx < 0:
        return text or ""
    line_start = (text or "").rfind("\n", 0, idx)
    return (text or "")[line_start + 1:]


def _process_count(image_name: str) -> int:
    if not _IS_WIN:
        return 0
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}"],
            creationflags=CREATE_NO_WINDOW, timeout=2,
            encoding="utf-8", errors="replace")
        return sum(1 for line in out.splitlines()
                   if line.lower().startswith(image_name.lower()))
    except Exception:
        return 0


def _rcm_process_pids_checked() -> tuple[Optional[list[int]], str]:
    if not _IS_WIN:
        return [], ""
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq RayClusterManager.exe",
             "/FO", "CSV", "/NH"],
            creationflags=CREATE_NO_WINDOW, timeout=3,
            encoding="utf-8", errors="replace")
        pids: list[int] = []
        for row in csv.reader(out.splitlines()):
            if len(row) < 2:
                continue
            if (row[0] or "").strip().lower() != "rayclustermanager.exe":
                continue
            try:
                pids.append(int(str(row[1]).strip()))
            except Exception:
                pass
        return pids, ""
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def normalized_rdp_port(value, default=3389) -> int:
    """Return a valid RDP port without trusting persisted/manual input."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return int(default)
    return port if 1 <= port <= 65535 else int(default)


def rdp_target_address(host: str, port=3389) -> str:
    """Format an mstsc/.rdp target, including bracketed IPv6 when needed."""
    target = str(host or "").strip()
    target_port = normalized_rdp_port(port)
    if ":" in target and not target.startswith("["):
        target = f"[{target}]"
    return f"{target}:{target_port}"


def tcp_probe_state(host: str, port: int, timeout: float = 1.2) -> str:
    """Classify TCP reachability without claiming application-level success."""
    if not host:
        return "error"
    sock = None
    try:
        sock = socket.create_connection(
            (str(host), normalized_rdp_port(port)), timeout=max(0.1, float(timeout)))
        return "open"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        if code in (61, 10061):
            return "refused"
        if code in (60, 10060, 110):
            return "timeout"
        return "error"
    except Exception:
        return "error"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_remote_access(host: str, rdp_port=3389, rcm_port=8866,
                        timeout: float = 1.2) -> dict[str, str]:
    """Probe only the selected RDP port; legacy RCM remote access is retired."""
    del rcm_port
    return {
        "rdp": tcp_probe_state(
            host, normalized_rdp_port(rdp_port), timeout),
        "rcm": "legacy_remote_retired",
    }


def _process_image_path(pid: int) -> tuple[str, str]:
    if not _IS_WIN:
        return "", "not windows"
    handle = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(
            0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return "", f"OpenProcess error {ctypes.get_last_error()}"
        size = wintypes.DWORD(32768)
        buf = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
                handle, 0, buf, ctypes.byref(size)):
            return "", f"QueryFullProcessImageName error {ctypes.get_last_error()}"
        return buf.value, ""
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}"
    finally:
        if handle:
            try:
                ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
            except Exception:
                pass








def _rcm_process_pids() -> list[int]:
    pids, _err = _rcm_process_pids_checked()
    return pids or []


def _kill_orphan_ray_python_processes(
        log: Optional[Callable[[str], None]] = None) -> int:
    """Kill leftover Ray python workers from a prior RCM/Ray session.

    This is intentionally not part of startup/runtime duplicate cleanup because
    an elevation parent or a healthy RCM can coexist with current Ray python
    children. Use it only during explicit Ray Start/Reset cleanup.
    """
    if not _IS_WIN:
        return 0
    killed = 0
    try:
        ps = ("Get-CimInstance Win32_Process | "
              "Where-Object { $_.Name -eq 'python.exe' "
              "-and $_.CommandLine -like '*ray*session_*' } | "
              "ForEach-Object { $_.ProcessId }")
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", ps],
            creationflags=CREATE_NO_WINDOW, timeout=10,
            encoding="utf-8", errors="replace")
        for tok in out.split():
            tok = tok.strip()
            if tok.isdigit():
                subprocess.run(
                    ["taskkill", "/F", "/PID", tok],
                    capture_output=True, creationflags=CREATE_NO_WINDOW,
                    timeout=6)
                killed += 1
    except Exception as exc:
        if callable(log):
            try:
                log(f"  orphan python cleanup skipped: {exc}")
            except Exception:
                pass
    return killed


def _schedule_frozen_temp_cleanup(
        log: Optional[Callable[[str], None]] = None) -> bool:
    if not (_IS_WIN and getattr(sys, "frozen", False)):
        return False
    meipass = str(getattr(sys, "_MEIPASS", "") or "")
    if not meipass:
        return False
    try:
        target = os.path.abspath(meipass)
        temp_root = os.path.abspath(os.environ.get("TEMP", ""))
        if not temp_root or not target.startswith(temp_root + os.sep):
            return False
        if not os.path.basename(target).startswith("_MEI"):
            return False
        quoted = target.replace("'", "''")
        ps = (
            f"$pidToWait={os.getpid()}; $path='{quoted}'; "
            "for($i=0; $i -lt 120; $i++){ "
            "if(-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)){ break }; "
            "Start-Sleep -Milliseconds 250 }; "
            "Start-Sleep -Milliseconds 500; "
            "Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue"
        )
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW)
        if callable(log):
            try:
                log("scheduled frozen temp cleanup")
            except Exception:
                pass
        return True
    except Exception as exc:
        if callable(log):
            try:
                log(f"frozen temp cleanup schedule failed: {exc}")
            except Exception:
                pass
        return False


def _cleanup_duplicate_rcm_processes(
        log: Optional[Callable[[str], None]] = None,
        wait_sec: float = 5.0,
        should_continue: Optional[Callable[[], bool]] = None,
        target_pids: Optional[list[int]] = None) -> tuple[bool, str]:
    """Terminate duplicate RCM processes without ever touching Ray children."""
    if not _IS_WIN:
        return True, "not windows"
    def keep_going() -> bool:
        if callable(should_continue):
            try:
                return bool(should_continue())
            except Exception:
                return False
        return True

    pids, err = _rcm_process_pids_checked()
    if pids is None:
        msg = f"could not list RCM processes: {err}"
        if callable(log):
            try:
                log("duplicate guard: " + msg)
            except Exception:
                pass
        return False, msg
    current = os.getpid()
    target_set = set(int(pid) for pid in target_pids) if target_pids else None
    targets = sorted(
        pid for pid in pids
        if pid != current and (target_set is None or pid in target_set))
    if not targets:
        return True, "no duplicate RCM processes"

    def note(text: str):
        if callable(log):
            try:
                log(text)
            except Exception:
                pass

    note("duplicate guard: found extra RCM pid(s) " +
         ", ".join(str(pid) for pid in targets))
    for pid in targets:
        if not keep_going():
            note("duplicate guard: cancelled")
            return True, "duplicate guard cancelled"
        try:
            proc = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", creationflags=CREATE_NO_WINDOW,
                timeout=6)
            if proc.returncode == 0:
                note(f"duplicate guard: requested stop for pid {pid}")
            else:
                msg = " ".join((proc.stdout or proc.stderr or "").split())
                note(f"duplicate guard: taskkill pid {pid} returned "
                     f"{proc.returncode} {msg[:160]}")
        except Exception as exc:
            note(f"duplicate guard: taskkill pid {pid} failed: "
                 f"{type(exc).__name__}: {exc}")

    deadline = time.monotonic() + max(0.5, wait_sec)
    remaining = []
    while time.monotonic() < deadline:
        if not keep_going():
            note("duplicate guard: cancelled")
            return True, "duplicate guard cancelled"
        pids, err = _rcm_process_pids_checked()
        if pids is None:
            msg = f"could not verify duplicate cleanup: {err}"
            note("duplicate guard: " + msg)
            return False, msg
        remaining = sorted(
            pid for pid in pids
            if pid != current and (target_set is None or pid in target_set))
        if not remaining:
            break
        time.sleep(0.25)
    if remaining:
        msg = "duplicate RCM still running: " + ", ".join(
            str(pid) for pid in remaining)
        note("duplicate guard: " + msg)
        return False, msg
    msg = "closed duplicate RCM pid(s): " + ", ".join(str(pid) for pid in targets)
    note("duplicate guard: " + msg)
    return True, msg


def logical_cpus() -> int:
    return os.cpu_count() or 0


def is_controller_config(cfg: dict, ip: Optional[str] = None) -> bool:
    """Whether this RCM instance is a monitor/RDP client, not a Ray node."""
    this_cfg = cfg.get("this") if isinstance(cfg.get("this"), dict) else {}
    if is_controller_mode(this_cfg.get("mode")):
        return True
    local_ip = str(ip or this_cfg.get("ip") or "").strip()
    if local_ip in ("", "auto"):
        try:
            local_ip = local_ip_towards(str(cfg.get("head_ip") or ""))
        except Exception:
            local_ip = ""
    for node in cfg.get("nodes", []):
        if not isinstance(node, dict) or str(node.get("ip") or "").strip() != local_ip:
            continue
        return is_controller_node(node)
    return False


def rdp_password_targets(nodes) -> list[dict]:
    """Return configured inbound-RDP targets; controllers are never targets."""
    targets = []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        if is_controller_node(node):
            continue
        if not str(node.get("ip") or "").strip():
            continue
        if not str(node.get("rdp_user") or "").strip():
            continue
        targets.append(json.loads(json.dumps(node)))
    return targets




def credential_controller_allowlist(
        head_ip: str, nodes, configured_ips=None) -> list[str]:
    """Normalize persisted legacy operators without deriving authority."""
    del head_ip, nodes
    result = []

    def add_valid(value) -> None:
        candidate = str(value or "").strip()
        try:
            candidate = str(ipaddress.ip_address(candidate))
        except ValueError:
            return
        if candidate not in result:
            result.append(candidate)

    for configured in configured_ips or []:
        add_valid(configured)
    return result


def resolve_identity(cfg: dict) -> tuple[str, str, Optional[int]]:
    head_ip = cfg["head_ip"]
    ip = cfg["this"].get("ip", "auto")
    if ip == "auto" or not ip:
        ip = local_ip_towards(head_ip)
    role = cfg["this"].get("role", "auto")
    if role not in ("head", "worker"):
        role = "head" if (ip and ip == head_ip) else "worker"
    raw_cpus = cfg["this"].get("num_cpus", "auto")
    if isinstance(raw_cpus, str) and raw_cpus.strip().lower() == "auto":
        detected = logical_cpus()
        cpus = detected if detected > 0 else None
    elif raw_cpus in (None, ""):
        cpus = None
    else:
        try:
            cpus = int(raw_cpus)
        except (TypeError, ValueError):
            cpus = None
    return role, ip, cpus


# =========================================================================
#  Ray controller
# =========================================================================


class RayController:
    def __init__(self, cfg: dict, log: Callable[[str], None]):
        self.cfg = cfg
        self.log = log
        self._worker_proc: Optional[subprocess.Popen] = None
        self._worker_lock = threading.Lock()
        self._operation_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        # v1.3.1: set True by auto-pause; watchdog reads to skip rejoin.
        # Cleared on user action (manual Start/Restart) or rearm.
        self.auto_paused = False
        self.repairing = False

    def _flags(self) -> int:
        return CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP if _IS_WIN else 0

    def _env(self) -> dict:
        env = os.environ.copy()
        env["RAY_ENABLE_WINDOWS_OR_OSX_CLUSTER"] = "1"
        return env

    def ray_exe(self) -> Optional[str]:
        return find_ray_exe(self.cfg.get("ray_exe", "auto"))

    def _run(self, args, timeout=60):
        ray = self.ray_exe()
        if not ray:
            return ActionResult(False, "ray.exe not found - set the path in Settings.")
        self.log("> " + " ".join(args))
        try:
            p = subprocess.run(
                [ray] + args, env=self._env(), creationflags=self._flags(),
                capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace",
            )
            out = (p.stdout or "") + (p.stderr or "")
            for line in out.strip().splitlines():
                if line.strip():
                    self.log("  " + line.rstrip())
            return ActionResult(p.returncode == 0, out.strip())
        except subprocess.TimeoutExpired:
            return ActionResult(False, "timed out")
        except Exception as exc:
            return ActionResult(False, str(exc))

    def _force_cleanup(self, verbose: bool = False) -> ActionResult:
        if not _IS_WIN:
            return ActionResult(True, "not windows")
        failures = []
        for name in _RAY_PROC_NAMES:
            try:
                p = subprocess.run(
                    ["taskkill", "/F", "/IM", name],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    creationflags=CREATE_NO_WINDOW, timeout=15)
                if verbose:
                    out = ((p.stdout or "") + (p.stderr or "")).strip()
                    if out:
                        for line in out.splitlines():
                            if line.strip():
                                self.log("  reset cleanup: " + line.strip())
                out_l = ((p.stdout or "") + (p.stderr or "")).lower()
                missing_text = (
                    "not found" in out_l
                    or "not running" in out_l
                    or "no tasks" in out_l
                    or "찾을 수" in out_l
                    or "없습니다" in out_l)
                # Windows taskkill returns 128 when the image does not exist.
                # Treat that as successful cleanup only after tasklist confirms
                # the process is gone, so permission-denied cases still fail.
                missing_ok = _process_count(name) == 0
                if p.returncode != 0 and not missing_ok:
                    failures.append(f"{name}: taskkill returned {p.returncode}")
            except Exception as exc:
                failures.append(f"{name}: {type(exc).__name__}: {exc}")
                if verbose:
                    self.log(f"  reset cleanup {name}: {exc}")
        # v1.5.28: `ray stop` and image-name taskkill miss orphaned Ray python
        # workers, which then collide with the next head's GCS (WrongClusterID ->
        # dashboard 500 -> false "head unreachable"). Clear them here too.
        n = _kill_orphan_ray_python_processes(self.log)
        if n:
            self.log(f"  cleanup: killed {n} orphan Ray python worker(s)")
        if failures:
            return ActionResult(False, "; ".join(failures))
        return ActionResult(True, "leftover Ray process cleanup complete")

    def _kill_orphan_ray_python(self) -> int:
        """Kill leftover Ray python workers that `ray stop` and image-name taskkill
        miss. Matches ONLY python whose command line references a Ray session, so
        unrelated python processes are never touched. Runs only in Start/Reset cleanup."""
        return _kill_orphan_ray_python_processes(self.log)

    def request_shutdown(self):
        self._shutdown_event.set()

    def _shutdown_requested(self) -> bool:
        return self._shutdown_event.is_set()

    def _terminate_worker_wrapper(self):
        with self._worker_lock:
            proc = self._worker_proc
            self._worker_proc = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass
            except Exception:
                pass

    def _cpu_args(self, cpus):
        return (["--num-cpus", str(cpus)]
                if cpus is not None and cpus >= 0 else [])

    def _worker_temp_dir(self) -> str:
        la = os.environ.get("LOCALAPPDATA", "")
        if la:
            return os.path.join(la, "Temp", "ray")
        return os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"), "ray")

    def _worker_port_args(self) -> list[str]:
        if not self.cfg.get("ray_worker_fixed_ports", True):
            return []
        mapping = [
            ("--node-manager-port", "ray_worker_node_manager_port"),
            ("--object-manager-port", "ray_worker_object_manager_port"),
            ("--runtime-env-agent-port", "ray_worker_runtime_env_agent_port"),
            ("--dashboard-agent-grpc-port", "ray_worker_dashboard_agent_grpc_port"),
            ("--dashboard-agent-listen-port", "ray_worker_dashboard_agent_listen_port"),
            ("--metrics-export-port", "ray_worker_metrics_export_port"),
            ("--min-worker-port", "ray_worker_min_port"),
            ("--max-worker-port", "ray_worker_max_port"),
        ]
        args: list[str] = []
        for flag, key in mapping:
            try:
                port = int(self.cfg.get(key) or 0)
            except (TypeError, ValueError):
                port = 0
            if port > 0:
                args += [flag, str(port)]
        return args

    def head_alive(self, timeout=2.5) -> bool:
        url = f"http://{self.cfg['head_ip']}:{self.cfg['dashboard_port']}/api/v0/nodes"
        try:
            r = requests.get(url, timeout=timeout, params={"limit": 200})
            if r.ok:
                rows = (((r.json() or {}).get("data") or {}).get("result") or {}).get("result") or []
                if any(row.get("is_head_node") and row.get("state") == "ALIVE" for row in rows):
                    return True
            # A successful dashboard API response necessarily proves its TCP
            # listener too; an ALIVE head row is the strongest health signal.
        # Dashboard responded but not OK (or its API was flaky). Fall through
        # to direct port checks rather than treating GCS alone as healthy.
        except Exception:
            pass
        # The Windows dashboard State API can intermittently return 500.  TCP
        # openness is sufficient in that case, but BOTH GCS and dashboard must
        # be listening. GCS-only is a half-start that Repair must reset.
        head_ip = str(self.cfg.get("head_ip") or "")
        gcs_open = _tcp_open(
            head_ip, int(self.cfg.get("head_port") or 6379), timeout=0.5)
        dashboard_open = _tcp_open(
            head_ip, int(self.cfg.get("dashboard_port") or 8265), timeout=0.5)
        return gcs_open and dashboard_open

    def start_head(self):
        with self._operation_lock:
            return self._start_head_locked()

    def _start_head_locked(self):
        if self._shutdown_requested():
            return ActionResult(False, "shutdown in progress; start cancelled")
        if self.head_alive():
            return ActionResult(True, "Head already running.")
        role, ip, cpus = resolve_identity(self.cfg)
        self._run(["stop"], timeout=30)
        cleanup = self._force_cleanup()
        if not cleanup.ok:
            return ActionResult(False, "Head cleanup failed: " + cleanup.message)
        if self._shutdown_requested():
            return ActionResult(False, "shutdown in progress; start cancelled")
        head_cpus = cpus if cpus is not None and cpus > 0 else logical_cpus()
        args = ["start", "--head", "--node-ip-address", ip,
                "--port", str(self.cfg["head_port"]),
                "--dashboard-host", "0.0.0.0"] + self._cpu_args(head_cpus)
        res = self._run(args, timeout=90)
        if not res.ok:
            return res
        self.log("  waiting for GCS / dashboard...")
        for _ in range(12):
            time.sleep(1.5)
            if self.head_alive():
                return ActionResult(True, "Head started.")
        return ActionResult(True, "Head started (dashboard not responding yet).")

    def start_worker(self):
        with self._operation_lock:
            return self._start_worker_locked()

    def _start_worker_locked(self):
        if self._shutdown_requested():
            return ActionResult(False, "shutdown in progress; join cancelled")
        role, ip, cpus = resolve_identity(self.cfg)
        if role != "worker":
            return ActionResult(False, "Current role is not worker; refusing worker join.")
        # safety: refuse to join as worker if our IP is the head's IP
        # (would taskkill head daemons in _force_cleanup below) -- P1-fix
        if ip and ip.strip() == str(self.cfg.get("head_ip") or "").strip():
            return ActionResult(False,
                "This PC's IP matches head_ip - cannot join as worker.")
        if cpus is None:
            return ActionResult(False, "Could not determine CPU count; set it in Settings.")
        if cpus < 0:
            return ActionResult(False, "CPU count must be 0 or more.")
        address = f"{self.cfg['head_ip']}:{self.cfg['head_port']}"
        ray = self.ray_exe()
        if not ray:
            return ActionResult(False, "ray.exe not found - set the path in Settings.")
        self._terminate_worker_wrapper()
        self._run(["stop"], timeout=30)
        cleanup = self._force_cleanup()
        if not cleanup.ok:
            return ActionResult(False, "Worker cleanup failed: " + cleanup.message)
        if self._shutdown_requested():
            return ActionResult(False, "shutdown in progress; join cancelled")
        # v1.1 P-list extras
        extra = ["--temp-dir", self._worker_temp_dir()]
        self.log(f"  injecting --temp-dir={extra[1]} (worker local temp)")
        port_args = self._worker_port_args()
        if port_args:
            extra += port_args
            self.log("  fixed Ray worker ports enabled")
        if False:
            # §15: worker whoami ≠ head whoami → temp_dir 권한 에러 방지
            # v1.2.1: LOCALAPPDATA 비어있으면 TEMP는 이미 ...\Temp 경로라
            # 추가 "Temp" join 시 \Temp\Temp 중복. 분기 처리.
            la = os.environ.get("LOCALAPPDATA", "")
            if la:
                local_tmp = os.path.join(la, "Temp", "ray")
            else:
                local_tmp = os.path.join(
                    os.environ.get("TEMP", r"C:\Windows\Temp"), "ray")
            extra += ["--temp-dir", local_tmp]
            self.log(f"  injecting --temp-dir={local_tmp} (whoami mismatch)")
        # always inject --node-name=<hostname> for display consistency
        extra += ["--node-name", socket.gethostname()]
        args = [ray, "start", "--address", address,
                "--node-ip-address", ip] + self._cpu_args(cpus) + extra + ["--block"]
        self.log("> start --address " + address + " (block, no window)")
        try:
            with self._worker_lock:
                self._worker_proc = subprocess.Popen(
                    args, env=self._env(), creationflags=self._flags(),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                )
                proc = self._worker_proc
            threading.Thread(target=self._pump_worker, args=(proc,), daemon=True).start()
            return ActionResult(True, "Worker connecting...")
        except Exception as exc:
            return ActionResult(False, str(exc))

    def _pump_worker(self, p):
        if not p or not p.stdout:
            return
        try:
            for line in p.stdout:
                if line.strip():
                    self.log("  " + line.rstrip())
        except Exception:
            pass
        code = p.poll()
        self.log(f"  (worker process ended, code {code})")

    def worker_running(self):
        with self._worker_lock:
            return self._worker_proc is not None and self._worker_proc.poll() is None

    def stop(self):
        with self._operation_lock:
            return self._stop_locked()

    def _stop_locked(self):
        self._terminate_worker_wrapper()
        res = self._run(["stop"], timeout=45)
        cleanup = self._force_cleanup()
        if not cleanup.ok:
            if res.ok:
                return ActionResult(False, "Ray cleanup failed: " + cleanup.message)
            return ActionResult(
                False,
                f"ray stop failed: {res.message}; cleanup failed: {cleanup.message}")
        return res

    def stop_for_quit(self, lock_timeout: float = 8.0) -> ActionResult:
        """Best-effort shutdown cleanup that cannot block forever behind Start/Repair."""
        self.request_shutdown()
        acquired = self._operation_lock.acquire(timeout=max(0.1, lock_timeout))
        if acquired:
            try:
                return self._stop_locked()
            finally:
                self._operation_lock.release()
        self.log("quit cleanup: Ray operation busy; forcing local cleanup")
        self._terminate_worker_wrapper()
        cleanup = self._force_cleanup(verbose=True)
        if cleanup.ok:
            return ActionResult(
                True,
                "Quit cleanup forced while another Ray operation was busy.")
        return ActionResult(
            False,
            "Quit cleanup forced while another Ray operation was busy: "
            + cleanup.message)

    def clean_reset(self):
        with self._operation_lock:
            return self._clean_reset_locked()

    def reset(self):
        """Compatibility name used by automatic recovery workflows."""
        return self.clean_reset()

    def recover_head_dashboard(self):
        """Serialize the destructive reset/start pair with every UI action."""
        with self._operation_lock:
            reset = self._clean_reset_locked()
            if not reset.ok:
                return reset
            return self._start_head_locked()

    def _clean_reset_locked(self):
        """v1.5: clean local Ray background state without auto-starting it."""
        self._terminate_worker_wrapper()
        self.auto_paused = False
        self.log("reset: ray stop --force")
        res = self._run(["stop", "--force"], timeout=75)
        self.log("reset: killing leftover Ray process names")
        cleanup = self._force_cleanup(verbose=True)
        _ray_exe_cache.clear()
        msg_l = (res.message or "").lower()
        if "accessdenied" in msg_l or "access denied" in msg_l or "permissionerror" in msg_l:
            return ActionResult(
                False,
                "Reset needs admin rights. Quit RCM and run as administrator.")
        if not res.ok:
            return ActionResult(
                False,
                "Reset attempted but ray stop failed. Check Logs, then run as admin if needed.")
        if not cleanup.ok:
            return ActionResult(
                False,
                "Reset cleanup failed. Run RCM as administrator. " + cleanup.message)
        return ActionResult(True, "Clean reset done. Press Start.")


# =========================================================================
#  Cluster monitor
# =========================================================================
@dataclass
class NodeView:
    ip: str
    hostname: str
    alive: bool
    cpu: float
    cpu_used: float
    gpu: float
    mem_gb: float
    is_head: bool
    name: str = ""
    is_this: bool = False
    node_id: str = ""
    rdp_user: str = ""
    rdp_port: int = 3389
    # A Ray dashboard row can exist without a matching local inventory entry.
    # Keep that distinction visible: cluster membership is not RDP setup.
    registered: bool = True
    # v1.1: temperature (None = unavailable)
    temp_cpu_pkg: Optional[float] = None
    temp_cpu_max: Optional[float] = None
    temp_gpu: Optional[float] = None
    temp_error: str = ""
    # v1.4: OS-level metrics from RCM /metrics
    os_cpu_pct: Optional[float] = None
    ram_total_gb: Optional[float] = None
    ram_used_gb: Optional[float] = None
    ram_available_gb: Optional[float] = None
    ram_pct: Optional[float] = None
    disks: list[dict] = field(default_factory=list)
    disk_io_bps: Optional[float] = None
    disk_active: bool = False
    disk_error: str = ""
    net_down_bps: Optional[float] = None
    net_up_bps: Optional[float] = None
    ping_ms: Optional[float] = None
    net_down_total_bytes: Optional[float] = None
    net_up_total_bytes: Optional[float] = None
    metrics_uptime_sec: Optional[float] = None
    metrics_ts: Optional[float] = None
    metrics_age_sec: Optional[float] = None
    conn_label: str = ""
    conn_type: str = ""
    conn_name: str = ""
    conn_category: str = ""
    net_error: str = ""
    metrics_error: str = ""


@dataclass
class ClusterView:
    reachable: bool = False
    # Last direct GCS probe when the dashboard API could not be reached.
    # True distinguishes a dead dashboard from a fully unreachable head.
    gcs_open: Optional[bool] = None
    nodes: list[NodeView] = field(default_factory=list)
    total_cpu: float = 0.0
    used_cpu: float = 0.0
    alive_nodes: int = 0
    error: str = ""
    ts: float = 0.0
    stale: bool = False
    # v1.1: max temp across nodes (for tray title)
    max_temp_c: Optional[float] = None
    max_temp_node: str = ""
    # v1.4: cluster OS metrics summary
    os_cpu_avg_pct: Optional[float] = None
    ram_total_gb: Optional[float] = None
    ram_used_gb: Optional[float] = None
    ram_pct: Optional[float] = None
    g_disk: Optional[dict] = None
    g_disk_node: str = ""
    net_down_bps: Optional[float] = None
    net_up_bps: Optional[float] = None
    net_down_total_bytes: Optional[float] = None
    net_up_total_bytes: Optional[float] = None
    net_uptime_sec: Optional[float] = None


def _node_label_key(value) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "", text)


def _node_view_rank(node: NodeView) -> tuple[int, int, int, float]:
    has_metrics = any(
        value is not None
        for value in (
            node.temp_cpu_pkg, node.temp_cpu_max, node.os_cpu_pct,
            node.ram_pct, node.ping_ms,
        )
    )
    return (
        1 if node.alive else 0,
        1 if has_metrics else 0,
        1 if node.name else 0,
        float(node.cpu or 0.0),
    )


def _dedupe_node_views(nodes: list[NodeView]) -> list[NodeView]:
    winners: list[NodeView] = []
    key_to_index: dict[tuple[str, str], int] = {}

    def keys_for(node: NodeView) -> list[tuple[str, str]]:
        keys: list[tuple[str, str]] = []
        if node.ip:
            keys.append(("ip", node.ip))
        label = _node_label_key(node.name) or _node_label_key(node.hostname)
        if label:
            keys.append(("name", label))
        return keys

    for node in nodes:
        keys = keys_for(node)
        hit = None
        for key in keys:
            if key in key_to_index:
                hit = key_to_index[key]
                break
        if hit is None:
            hit = len(winners)
            winners.append(node)
        elif _node_view_rank(node) > _node_view_rank(winners[hit]):
            winners[hit] = node
        for key in keys:
            key_to_index[key] = hit
    return winners


def complete_ray_display_nodes(nodes, cfg, this_ip="") -> list[NodeView]:
    """Return every configured Ray node, adding missing ones as offline rows.

    Dashboard errors and partial payloads must not shrink the Connected nodes
    pane: Fit Screen promises to expose the whole configured Ray inventory.
    Controller-only machines are deliberately not part of that inventory.
    """
    completed = list(nodes or [])
    existing_ips = {
        str(getattr(node, "ip", "") or "").strip() for node in completed
    }
    existing_names = {
        _node_label_key(getattr(node, "name", "")
                        or getattr(node, "hostname", ""))
        for node in completed
    }
    for item in (cfg or {}).get("nodes", []) or []:
        if not isinstance(item, dict):
            continue
        if is_controller_node(item):
            continue
        ip = str(item.get("ip") or "").strip()
        name = str(item.get("name") or ip).strip()
        if (ip and ip in existing_ips) or (_node_label_key(name) in existing_names):
            continue
        try:
            cpu = float(item.get("num_cpus", 0) or 0)
        except (TypeError, ValueError):
            cpu = 0.0
        completed.append(NodeView(
            ip=ip, hostname=name or ip, alive=False, cpu=cpu,
            cpu_used=0.0, gpu=0.0, mem_gb=0.0,
            is_head=str(item.get("role") or "worker").lower() == "head",
            name=name, is_this=bool(ip and ip == str(this_ip or "").strip()),
            rdp_user=str(item.get("rdp_user") or ""),
            rdp_port=normalized_rdp_port(item.get("rdp_port")), registered=True,
            metrics_error="not in Ray"))
        if ip:
            existing_ips.add(ip)
        if _node_label_key(name):
            existing_names.add(_node_label_key(name))
    return _dedupe_node_views(completed)


def diagnose_cluster_state(
        cfg: dict,
        view: Optional[ClusterView],
        recent_log: str = "",
        ray_path: Optional[str] = None,
        gcs_open: Optional[bool] = None,
        dash_open: Optional[bool] = None,
        metrics_open: Optional[bool] = None,
        rcm_count: Optional[int] = None,
        role: str = "head") -> tuple[str, str, str]:
    """Return (severity, line1, line2) for the v1.5 diagnostic console."""
    head_ip = str(cfg.get("head_ip") or "")
    head_port = int(cfg.get("head_port") or 6379)
    dash_port = int(cfg.get("dashboard_port") or 8265)
    temp_port = int(cfg.get("temp_port") or 8866)
    if gcs_open is None:
        gcs_open = _tcp_open(head_ip, head_port)
    if dash_open is None:
        dash_open = _tcp_open(head_ip, dash_port)
    if metrics_open is None:
        metrics_open = _tcp_open("127.0.0.1", temp_port)
    if rcm_count is None:
        rcm_count = _process_count("RayClusterManager.exe")
    log_l = (recent_log or "").lower()
    is_head_role = role == "head"
    start_label = "Start" if is_head_role else "Join"
    local_reset_next = f"NEXT Press Reset, then {start_label}."
    head_reset_next = (
        "NEXT Press Reset, then Start."
        if is_head_role else
        "NEXT Fix the head PC, then press Join on this worker.")

    if ray_path is None:
        ray_path = find_ray_exe(cfg.get("ray_exe", "auto"))
    if not ray_path:
        return ("ERR",
                "DIAG ERR  ray.exe not found",
                "NEXT Settings -> Cluster -> ray.exe, or install Ray for Python 3.12.")
    if "session name" in log_l and "does not match" in log_l:
        return ("ERR",
                "DIAG ERR  Ray session mismatch",
                f"{local_reset_next} If Reset cannot stop Ray, run RCM as admin.")
    if "accessdenied" in log_l or "access denied" in log_l or "permissionerror" in log_l or "액세스가 거부" in log_l:
        return ("WARN",
                "DIAG WARN cleanup permission denied",
                "NEXT Use Reset from elevated RCM, or quit and run as administrator.")
    if "modulenotfounderror" in log_l and "ray" in log_l:
        return ("ERR",
                "DIAG ERR  Ray import failed or ray.EXE shadow was used",
                "NEXT Pin a real ray.exe in Settings and move any Desktop\\ray.EXE shadow.")
    view_problem = (
        view is None or not view.reachable
        or (getattr(view, "nodes", None) and view.alive_nodes < len(view.nodes)))
    if view_problem and "dashboard_agent" in log_l and ("failed" in log_l or "dead" in log_l):
        return ("WARN",
                "DIAG WARN Ray dashboard agent failed",
                f"{head_reset_next} Check fixed ports/firewall if repeated.")
    if view_problem and "worker" in log_l and "dead" in log_l:
        return ("WARN",
                "DIAG WARN Ray worker went DEAD",
                "NEXT Stop/Start that worker. If it repeats, check ports and Tailscale.")
    if view_problem and ("ray-tailscale-in" in log_l or "firewall" in log_l):
        return ("WARN",
                "DIAG WARN firewall or fixed-port issue suspected",
                "NEXT Check Ray-Tailscale-In rules and fixed worker ports.")
    if "already running" in log_l and gcs_open and not dash_open:
        return ("WARN",
                "DIAG WARN GCS is alive but Dashboard is offline",
                ("NEXT Dashboard died. Auto-recovering..."
                 if is_head_role else
                 "NEXT Head PC dashboard is down. "
                 "It should self-heal; wait ~60s."))
    if "timed out while waiting for gcs" in log_l and not gcs_open:
        return ("WARN",
                "DIAG WARN GCS not ready",
                "NEXT Wait 15-60s, then Start again. If repeated, use Reset.")
    if "ray.exe not found" in log_l:
        return ("ERR",
                "DIAG ERR  ray.exe path invalid",
                "NEXT Check Settings -> Cluster -> ray.exe.")
    if rcm_count and rcm_count > 1:
        ray_summary = ""
        if view is not None and getattr(view, "reachable", False):
            try:
                ray_summary = (
                    f" | Ray {int(round(view.used_cpu))}/"
                    f"{int(round(view.total_cpu))} CPU")
            except Exception:
                ray_summary = ""
        return ("WARN",
                f"DIAG WARN multiple RCM processes ({rcm_count}){ray_summary}",
                "NEXT Keep one window/tray instance; use tray Quit for extras.")

    if view is None or not view.reachable:
        if gcs_open and not dash_open:
            recovery_next = (
                "NEXT Dashboard died. Auto-recovering..."
                if is_head_role else
                "NEXT Head PC dashboard is down. "
                "It should self-heal; wait ~60s.")
            return ("WARN",
                    "DIAG WARN GCS alive, Dashboard offline",
                    recovery_next)
        if not gcs_open and not dash_open:
            return ("STOP",
                    "DIAG STOP Ray head is offline",
                    f"NEXT Press {start_label}." if is_head_role
                    else "NEXT Check head PC/Tailscale, then press Join.")
        if dash_open:
            return ("WARN",
                    "DIAG WARN Dashboard port open, API refresh failed",
                    "NEXT Check Logs; wait for refresh or use Reset if it persists.")
        err = getattr(view, "error", "") if view is not None else ""
        return ("WARN",
                "DIAG WARN Head unreachable",
                f"NEXT {err[:80] or 'Check Tailscale, firewall, and Dashboard 8265.'}")

    used = int(round(view.used_cpu))
    total = int(round(view.total_cpu))
    alive = int(view.alive_nodes)
    total_nodes = len(view.nodes)
    if getattr(view, "stale", False):
        return ("WARN",
                f"DIAG WARN refresh retry | Ray {used}/{total} CPU | Nodes {alive}/{total_nodes}",
                "NEXT Using last good view. If it repeats, check Dashboard or press Reset.")
    wants_metrics_server = (
        bool(cfg.get("metrics_enabled", True))
        or bool(cfg.get("temp_enabled", True)))
    if wants_metrics_server and not metrics_open:
        return ("WARN",
                f"DIAG WARN RCM metrics server offline | Ray {used}/{total} CPU",
                "NEXT Metrics/temp may be blank. Restart RCM if 8866 stays closed.")

    repairable = [
        n.name or n.hostname or n.ip
        for n in view.nodes
        if not n.alive and n.metrics_uptime_sec is not None
    ]
    if repairable:
        names = ", ".join(repairable[:3])
        more = "" if len(repairable) <= 3 else f" +{len(repairable) - 3}"
        return ("WARN",
                f"DIAG WARN RCM alive, Ray missing | Ray {used}/{total} CPU",
                f"NEXT Press Repair for: {names}{more}.")

    offline = [n.name or n.hostname or n.ip for n in view.nodes if not n.alive]
    if offline:
        names = ", ".join(offline[:3])
        more = "" if len(offline) <= 3 else f" +{len(offline) - 3}"
        return ("OK",
                f"DIAG OK   Dashboard online | Ray {used}/{total} CPU | Nodes {alive}/{total_nodes}",
                f"NEXT Cluster usable. Offline: {names}{more}.")
    return ("OK",
            f"DIAG OK   Dashboard online | Ray {used}/{total} CPU | Nodes {alive}/{total_nodes}",
            "NEXT Cluster healthy.")


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_LOG_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\[\d{2}:\d{2}:\d{2}\]\s*")
_RAY_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+\s+[A-Z]+\s+[^-]+--\s*")


def _clean_status_log_line(line: str) -> str:
    line = _ANSI_RE.sub("", str(line or ""))
    line = _LOG_TS_RE.sub("", line).strip()
    if line.startswith("> "):
        return "command " + line[2:].strip()
    line = _RAY_TS_RE.sub("", line).strip()
    line = " ".join(line.replace("\t", " ").split())
    return line


def _log_line_is_noise(text: str) -> bool:
    low = (text or "").lower()
    if not low:
        return True
    noisy = (
        "usage stats collection is enabled",
        "next steps",
        "to add another node",
        "to connect to this ray cluster",
        "ray.init",
        "to submit a ray job",
        "see https://",
        "for more information",
        "to terminate the ray runtime",
        "to view the status",
        "to monitor and debug ray",
        "if connection to the dashboard fails",
        "local node ip",
        "--------------------",
    )
    return any(part in low for part in noisy)


def _log_status_explanation(
        recent_log: str,
        view: Optional[ClusterView],
        severity: str,
        line1: str,
        line2: str,
        gcs_open: bool,
        dash_open: bool,
        metrics_open: bool,
        rcm_count: int) -> str:
    """Build the status-board first line from the freshest useful log fact."""
    lines = [_clean_status_log_line(line)
             for line in (recent_log or "").splitlines()[-80:]]
    lines = [line for line in lines if line and not _log_line_is_noise(line)]
    for text in reversed(lines):
        low = text.lower()
        if "accessdenied" in low or "access denied" in low or "permissionerror" in low:
            return "LOG WARN cleanup blocked by permissions | use elevated RCM"
        if "modulenotfounderror" in low and "ray" in low:
            return "LOG ERR Ray import failed | pin real ray.exe in Settings"
        if "ray.exe not found" in low:
            return "LOG ERR ray.exe not found | Settings -> Cluster -> ray.exe"
        if "session name" in low and "does not match" in low:
            return "LOG ERR Ray session mismatch | Reset then Start/Join"
        if "already running" in low:
            if gcs_open and not dash_open:
                return "LOG WARN Ray half-started | GCS alive, dashboard offline"
            return "LOG WARN Ray reports already running | check dashboard"
        if "timed out while waiting for gcs" in low or "failed to connect to gcs" in low:
            return "LOG WARN GCS connection timed out | check head/Tailscale"
        if "dashboard_agent" in low and ("failed" in low or "dead" in low):
            return "LOG WARN dashboard agent failed | check Ray ports"
        if "worker" in low and "dead" in low:
            return "LOG WARN worker went DEAD | repair or check firewall"
        if "repair" in low and ("failed" in low or "offline" in low or "refused" in low):
            return "LOG WARN repair could not complete | open Trouble log"
        if low.startswith("err:") or " error" in low:
            return "LOG ERR " + text[:120]
        if low.startswith("warn") or " warn " in low:
            return "LOG WARN " + text[:120]
        if low.startswith("ok:"):
            return "LOG OK " + text[3:].strip()[:130]
        if "ray runtime started" in low:
            return "LOG OK Ray runtime started; waiting for workers"
        if low.startswith("watchdog:"):
            return "LOG " + text[:140]
        if low.startswith("duplicate guard"):
            return "LOG " + text[:140]
        if low.startswith("reset:") or low.startswith("command stop") or low.startswith("command start"):
            return "LOG " + text[:140]

    if rcm_count and rcm_count > 1:
        return f"LOG WARN {rcm_count} RCM processes detected | keep one tray/window"
    if view is None or not getattr(view, "reachable", False):
        return (
            "LOG STATE dashboard unavailable | "
            f"GCS={'open' if gcs_open else 'closed'} "
            f"Dash={'open' if dash_open else 'closed'} "
            f"RCM={'open' if metrics_open else 'closed'}")

    used = int(round(view.used_cpu))
    total = int(round(view.total_cpu))
    alive = int(view.alive_nodes)
    total_nodes = len(view.nodes)
    repairable = [
        n.name or n.hostname or n.ip for n in view.nodes
        if not n.alive and n.metrics_uptime_sec is not None
    ]
    if repairable:
        names = ", ".join(repairable[:3])
        more = "" if len(repairable) <= 3 else f" +{len(repairable) - 3}"
        return f"LOG STATE RCM reachable but Ray missing: {names}{more}"
    offline = [n.name or n.hostname or n.ip for n in view.nodes if not n.alive]
    if offline:
        names = ", ".join(offline[:3])
        more = "" if len(offline) <= 3 else f" +{len(offline) - 3}"
        return f"LOG STATE Ray {used}/{total} CPU; offline: {names}{more}"
    if severity in ("WARN", "ERR") and line1:
        return "LOG " + line1.replace("DIAG ", "", 1)[:140]
    if line2 and line2 != "NEXT Cluster healthy.":
        return "LOG NEXT " + line2.replace("NEXT ", "", 1)[:140]
    return f"LOG OK no recent actionable log | Ray {used}/{total} CPU | Nodes {alive}/{total_nodes}"


class WorkerWatchdog(threading.Thread):
    """v1.1 P-list §B: 60초 주기 ESTABLISHED TCP 확인. 끊김 감지 시 자동 재합류.
    PS1 cron 의 역할을 RCM 안으로 흡수.
    v1.2.1: cfg 동적 참조 (Settings 변경 반영) + exponential backoff (60→120→240→...→600).
    """

    def __init__(self, controller, cfg, on_log, interval=60):
        super().__init__(daemon=True, name="WorkerWatchdog")
        self.controller = controller
        self.cfg = cfg  # v1.2.1: 동적 참조 (head_ip 변경 즉시 반영)
        self.on_log = on_log
        self.base_interval = max(20, int(interval))
        self._stop_event = threading.Event()
        self._fail_count = 0  # v1.2.1: backoff counter
        self._stale_worker_count = 0

    def stop(self):
        self._stop_event.set()

    def _current_target(self):
        return self.cfg.get("head_ip", ""), int(self.cfg.get("head_port", 6379))

    def _current_interval(self) -> int:
        # exponential backoff: base * 2^(min(fail_count, 4)), cap at 10x base
        mult = min(2 ** min(self._fail_count, 4), 10)
        return self.base_interval * mult

    def _tcp_established(self) -> bool:
        ip, port = self._current_target()
        if not ip:
            return False
        try:
            out = subprocess.check_output(
                ["netstat", "-an", "-p", "TCP"],
                creationflags=CREATE_NO_WINDOW, timeout=4).decode(
                "utf-8", errors="replace")
            target = f"{ip}:{port}"
            for line in out.splitlines():
                if "ESTABLISHED" in line and target in line:
                    return True
        except Exception:
            pass
        return False

    def _healthy(self) -> bool:
        if not self.controller.worker_running():
            return False
        _, this_ip, _ = resolve_identity(self.cfg)
        alive, checked = _dashboard_ip_alive(self.cfg, this_ip, timeout=3.0)
        if checked:
            return alive
        return self._tcp_established()

    def check_once(self):
        """Run one watchdog decision; split out for deterministic tests."""
        self._cycle_count = getattr(self, "_cycle_count", 0) + 1
        ip, port = self._current_target()
        # v1.3.1: respect auto-pause — don't rejoin a node that auto-pause stopped
        if getattr(self.controller, "auto_paused", False):
            self.on_log("watchdog: auto-pause active — skipping rejoin")
            return
        if getattr(self.controller, "repairing", False):
            self.on_log("watchdog: repair active — skipping rejoin")
            return
        worker_running = self.controller.worker_running()
        healthy = self._healthy()
        if worker_running and not healthy:
            self._stale_worker_count += 1
            limit = max(1, int(self.cfg.get("watchdog_stale_cycles", 3)))
            if self._stale_worker_count < limit:
                self.on_log(
                    "watchdog: local worker alive but not Ray ALIVE yet"
                    f" — waiting ({self._stale_worker_count}/{limit})")
            else:
                self.on_log(
                    "watchdog: local worker stale outside Ray dashboard"
                    f" for {self._stale_worker_count} cycles — restarting")
                try:
                    res = self.controller.start_worker()
                    self._stale_worker_count = 0
                    if res.ok:
                        self._fail_count = 0
                    else:
                        self._fail_count += 1
                    self.on_log(f"watchdog: stale restart → {res.message}")
                except Exception as exc:
                    self._fail_count += 1
                    self.on_log(f"watchdog stale restart error: {exc}")
        elif not healthy:
            # A dead local wrapper is authoritative.  A stale ESTABLISHED
            # socket must never suppress rejoin when the worker process ended.
            self._stale_worker_count = 0
            self.on_log(
                f"watchdog: not Ray ALIVE at {ip}:{port}"
                f" — attempting rejoin (fail #{self._fail_count + 1})")
            try:
                res = self.controller.start_worker()
                if res.ok:
                    self._fail_count = 0
                else:
                    self._fail_count += 1
                self.on_log(f"watchdog: rejoin → {res.message}")
            except Exception as exc:
                self._fail_count += 1
                self.on_log(f"watchdog rejoin error: {exc}")
        else:
            self._fail_count = 0
            self._stale_worker_count = 0
            if self._cycle_count % 10 == 0:
                self.on_log(
                    f"watchdog: healthy at {ip}:{port}; "
                    "local worker running")

    def run(self):
        if self._stop_event.wait(self.base_interval):
            return
        while not self._stop_event.is_set():
            try:
                self.check_once()
            except Exception as exc:
                self.on_log(f"watchdog poll error: {exc}")
            wait_sec = self._current_interval()
            if self._fail_count > 0:
                self.on_log(f"watchdog: backoff → next check in {wait_sec}s")
            if self._stop_event.wait(wait_sec):
                return


class HeadDashboardGuard(threading.Thread):
    """Restart a head only when GCS lives but its dashboard is gone."""

    def __init__(
            self, controller, cfg, on_log, on_trouble=None,
            interval=None, cycles=None, tcp_probe=None):
        super().__init__(daemon=True, name="HeadDashboardGuard")
        self.controller = controller
        self.cfg = cfg
        self.on_log = on_log
        self.on_trouble = on_trouble
        self.base_interval = max(
            1.0, float(
                interval if interval is not None
                else cfg.get("head_dashboard_guard_interval_sec", 20)))
        self.required_cycles = max(
            1, int(
                cycles if cycles is not None
                else cfg.get("head_dashboard_guard_cycles", 3)))
        self.tcp_probe = tcp_probe or _tcp_open
        self._stop_event = threading.Event()
        self._dead_cycles = 0
        self._fail_count = 0

    def stop(self):
        self._stop_event.set()

    def _shutdown_requested(self) -> bool:
        checker = getattr(self.controller, "_shutdown_requested", None)
        return bool(callable(checker) and checker())

    def _current_interval(self) -> float:
        mult = min(2 ** min(self._fail_count, 4), 10)
        return self.base_interval * mult

    def _event(self, message: str):
        self.on_log(message)
        if callable(self.on_trouble):
            try:
                self.on_trouble(message)
            except Exception:
                pass

    def _recover(self):
        atomic_recover = getattr(
            self.controller, "recover_head_dashboard", None)
        if callable(atomic_recover):
            return atomic_recover()
        reset = self.controller.reset()
        if not reset.ok:
            return reset
        return self.controller.start_head()

    def check_once(self):
        if self._shutdown_requested():
            return
        role, _, _ = resolve_identity(self.cfg)
        if role != "head":
            self._dead_cycles = 0
            return
        if (getattr(self.controller, "repairing", False)
                or getattr(self.controller, "auto_paused", False)):
            self._dead_cycles = 0
            return
        head_ip = str(self.cfg.get("head_ip") or "")
        gcs_open = self.tcp_probe(
            head_ip, int(self.cfg.get("head_port") or 6379), timeout=1.0)
        dash_open = self.tcp_probe(
            head_ip, int(self.cfg.get("dashboard_port") or 8265),
            timeout=1.0)
        if not gcs_open or dash_open:
            self._dead_cycles = 0
            if dash_open:
                self._fail_count = 0
            return
        self._dead_cycles += 1
        if self._dead_cycles < self.required_cycles:
            self.on_log(
                "dashboard guard: GCS alive, dashboard offline "
                f"({self._dead_cycles}/{self.required_cycles})")
            return
        self._dead_cycles = 0
        attempt = self._fail_count + 1
        self._event(
            "RCM_DIAG_EVENT dashboard guard recovery "
            f"attempt #{attempt}: restarting the Ray cluster; "
            "workers should rejoin through their watchdogs")
        try:
            result = self._recover()
        except Exception as exc:
            result = ActionResult(False, f"{type(exc).__name__}: {exc}")
        if result.ok:
            self._fail_count = 0
            self._event(
                "RCM_DIAG_EVENT dashboard guard recovery succeeded: "
                + result.message)
        else:
            self._fail_count += 1
            delay = self._current_interval()
            self._event(
                "RCM_DIAG_EVENT dashboard guard recovery failed: "
                f"{result.message}; backoff {delay:g}s")

    def run(self):
        if self._stop_event.wait(self.base_interval):
            return
        while not self._stop_event.is_set():
            try:
                self.check_once()
            except Exception as exc:
                self._event(
                    "RCM_DIAG_EVENT dashboard guard poll error: "
                    f"{type(exc).__name__}: {exc}")
                self._fail_count += 1
            if self._stop_event.wait(self._current_interval()):
                return


class ClusterReconfigurator:
    """Coordinate a monotonic-epoch head change over existing RCM HTTP."""

    def __init__(
            self, cfg, controller=None, on_progress=None, on_event=None,
            http=None, head_alive_probe=None, verify_provider=None):
        self.cfg = cfg
        self.controller = controller
        self.on_progress = on_progress or (
            lambda _stage, _node, _state, _reason="": None)
        self.on_event = on_event or (lambda _message: None)
        self.http = http or requests
        self.head_alive_probe = (
            head_alive_probe or self._default_head_alive)
        self.verify_provider = verify_provider or self._default_verify
        self.port = int(cfg.get("temp_port") or 8866)

    def _nodes(self):
        return [
            dict(node) for node in self.cfg.get("nodes", [])
            if isinstance(node, dict) and not is_controller_node(node)
        ]

    def _node_name(self, node):
        return str(node.get("name") or node.get("ip") or "node")

    def _progress(self, stage, node, state, reason=""):
        self.on_progress(stage, self._node_name(node), state, reason)

    def preflight(self, new_head) -> dict:
        del new_head
        incompatible = []
        for node in self._nodes():
            reason = "legacy_remote_retired"
            incompatible.append({"node": node, "reason": reason})
            self._progress("PREFLIGHT", node, "failed", reason)
        return {
            "health_by_ip": {},
            "unreachable": [],
            "incompatible": incompatible,
            "candidate_ready": False,
            "candidate_firewall_ready": None,
            "reason": "legacy_remote_retired",
        }
        candidate_ip = str(new_head.get("ip") or "").strip()
        health_by_ip = {}
        unreachable = []
        incompatible = []
        for node in self._nodes():
            ip = str(node.get("ip") or "").strip()
            self._progress("PREFLIGHT", node, "running")
            try:
                response = self.http.get(
                    f"http://{ip}:{self.port}/health", timeout=4.0)
                health = response.json() if response.ok else {}
                if not response.ok or not isinstance(health, dict):
                    raise ValueError(f"HTTP {response.status_code}")
                health_by_ip[ip] = health
                reasons = []
                if health.get("version") != APP_VERSION:
                    reasons.append(
                        f"version {health.get('version') or 'unknown'}")
                if not health.get("cluster_config_v1"):
                    reasons.append("cluster_config_v1 missing")
                if reasons:
                    incompatible.append({
                        "node": node, "reason": ", ".join(reasons)})
                    self._progress(
                        "PREFLIGHT", node, "failed", ", ".join(reasons))
                else:
                    self._progress("PREFLIGHT", node, "done")
            except Exception as exc:
                unreachable.append(node)
                self._progress(
                    "PREFLIGHT", node, "unreachable",
                    type(exc).__name__)
        candidate_health = health_by_ip.get(candidate_ip)
        candidate_ready = bool(
            candidate_health
            and candidate_health.get("version") == APP_VERSION
            and candidate_health.get("cluster_config_v1"))
        firewall_ready = (
            candidate_health.get("ray_firewall_ready")
            if candidate_health else None)
        if firewall_ready is False:
            candidate_ready = False
        return {
            "health_by_ip": health_by_ip,
            "unreachable": unreachable,
            "incompatible": incompatible,
            "candidate_ready": candidate_ready,
            "candidate_firewall_ready": firewall_ready,
        }

    def build_manifest(self, new_head, epoch=None) -> dict:
        candidate_ip = str(new_head.get("ip") or "").strip()
        nodes = []
        for node in self._nodes():
            item = dict(node)
            item["role"] = (
                "head" if str(item.get("ip") or "").strip() == candidate_ip
                else "worker")
            nodes.append(item)
        next_epoch = (
            int(self.cfg.get("cluster_epoch") or 0) + 1
            if epoch is None else int(epoch))
        return validate_cluster_manifest({
            "epoch": next_epoch,
            "head_ip": candidate_ip,
            "updated": datetime.now().astimezone().isoformat(
                timespec="seconds"),
            "updated_by": socket.gethostname(),
            "nodes": nodes,
        })

    def _push(self, node, manifest) -> bool:
        del node, manifest
        return False
        ip = str(node.get("ip") or "").strip()
        try:
            response = self.http.post(
                f"http://{ip}:{self.port}/cluster-config",
                headers={"X-RCM-Cluster": "v1"},
                json=manifest, timeout=8.0)
            payload = response.json() if response.content else {}
            return bool(
                response.status_code == 202
                and payload.get("accepted", True))
        except Exception:
            return False

    def _default_head_alive(self, head_ip) -> bool:
        del head_ip
        return False
        try:
            response = self.http.get(
                f"http://{head_ip}:"
                f"{int(self.cfg.get('dashboard_port') or 8265)}"
                "/api/v0/nodes",
                timeout=3.0, params={"limit": 200})
            if not response.ok:
                return False
            rows = ((((response.json() or {}).get("data") or {})
                     .get("result") or {}).get("result") or [])
            return any(
                row.get("is_head_node") and row.get("state") == "ALIVE"
                for row in rows if isinstance(row, dict))
        except Exception:
            return False

    def _default_verify(self, head_ip) -> dict:
        del head_ip
        return {
            "alive_nodes": 0,
            "total_cpu": 0.0,
            "error": "legacy_remote_retired",
        }
        try:
            response = self.http.get(
                f"http://{head_ip}:"
                f"{int(self.cfg.get('dashboard_port') or 8265)}"
                "/api/v0/nodes",
                timeout=5.0, params={"limit": 200})
            response.raise_for_status()
            rows = ((((response.json() or {}).get("data") or {})
                     .get("result") or {}).get("result") or [])
            alive = [
                row for row in rows
                if isinstance(row, dict) and row.get("state") == "ALIVE"]
            return {
                "alive_nodes": len(alive),
                "total_cpu": sum(
                    float((row.get("resources_total") or {}).get("CPU") or 0)
                    for row in alive),
            }
        except Exception as exc:
            return {
                "alive_nodes": 0, "total_cpu": 0.0,
                "error": f"{type(exc).__name__}: {exc}"}

    def _wait_for_head(self, head_ip, timeout=60.0) -> bool:
        del head_ip, timeout
        return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.head_alive_probe(head_ip):
                return True
            time.sleep(2.0)
        return False

    def _rollback(self, previous, reachable_nodes) -> bool:
        del previous, reachable_nodes
        return False
        rollback = dict(previous)
        rollback["epoch"] = int(previous["epoch"]) + 2
        rollback["updated"] = datetime.now().astimezone().isoformat(
            timespec="seconds")
        rollback["updated_by"] = socket.gethostname()
        rollback = validate_cluster_manifest(rollback)
        self.on_event(
            f"ROLLBACK epoch={rollback['epoch']} "
            f"head={rollback['head_ip']}")
        write_cluster_manifest(
            str(self.cfg.get("cluster_manifest_path")
                or DEFAULT_CLUSTER_MANIFEST_PATH),
            rollback)
        old_head = next(
            node for node in rollback["nodes"]
            if node.get("role") == "head")
        ordered = [
            node for node in reachable_nodes
            if str(node.get("ip")) != str(old_head.get("ip"))]
        ordered.append(old_head)
        ok = True
        for node in ordered:
            pushed = self._push(node, rollback)
            self._progress(
                "ROLLBACK", node, "done" if pushed else "failed")
            ok = ok and pushed
        return ok and self._wait_for_head(rollback["head_ip"], timeout=60.0)

    def execute(
            self, new_head, preflight=None,
            cancel_event: Optional[threading.Event] = None) -> ActionResult:
        del new_head, preflight, cancel_event
        return ActionResult(False, "legacy_remote_retired")
        cancel_event = cancel_event or threading.Event()
        info = preflight or self.preflight(new_head)
        if not info.get("candidate_ready"):
            return ActionResult(
                False, "New head candidate failed preflight.")
        manifest = self.build_manifest(new_head)
        old_head = next(
            node for node in self._nodes()
            if node.get("role") == "head")
        previous = validate_cluster_manifest({
            "epoch": int(self.cfg.get("cluster_epoch") or 0),
            "head_ip": str(self.cfg.get("head_ip") or ""),
            "updated": "",
            "updated_by": "",
            "nodes": self._nodes(),
        })
        unreachable_ips = {
            str(node.get("ip") or "")
            for node in info.get("unreachable", [])}
        incompatible_ips = {
            str(item["node"].get("ip") or "")
            for item in info.get("incompatible", [])}
        reachable = [
            node for node in self._nodes()
            if str(node.get("ip") or "") not in (
                unreachable_ips | incompatible_ips)]
        candidate_ip = str(new_head.get("ip") or "")
        ordered = [old_head]
        ordered.extend(
            node for node in reachable
            if str(node.get("ip") or "") not in (
                str(old_head.get("ip") or ""), candidate_ip))
        ordered.extend(
            node for node in reachable
            if str(node.get("ip") or "") == candidate_ip)
        if self.controller is not None:
            self.controller.repairing = True
        try:
            for index, node in enumerate(ordered):
                if cancel_event.is_set():
                    return ActionResult(False, "Head change cancelled.")
                stage = "STOP" if index == 0 else (
                    "START" if str(node.get("ip") or "") == candidate_ip
                    else "PUSH")
                self._progress(stage, node, "running")
                if not self._push(node, manifest):
                    self._progress(stage, node, "failed", "push rejected")
                    if str(node.get("ip") or "") == candidate_ip:
                        self._rollback(previous, reachable)
                        return ActionResult(
                            False,
                            "New head rejected configuration; rolled back.")
                else:
                    self._progress(stage, node, "done")
                if index == 0:
                    write_cluster_manifest(
                        str(self.cfg.get("cluster_manifest_path")
                            or DEFAULT_CLUSTER_MANIFEST_PATH),
                        manifest)
            if not self._wait_for_head(candidate_ip, timeout=60.0):
                rolled_back = self._rollback(previous, reachable)
                return ActionResult(
                    False,
                    "New head did not start; "
                    + ("rollback completed."
                       if rolled_back else "rollback also needs attention."))
            verify = self.verify_provider(candidate_ip)
            expected = len(reachable)
            alive = int(verify.get("alive_nodes") or 0)
            cpu = float(verify.get("total_cpu") or 0.0)
            self.on_event(
                f"VERIFY epoch={manifest['epoch']} "
                f"alive={alive}/{expected} cpu={cpu:g}")
            # Worker failures are reported without rollback: the new head is
            # already healthy and watchdogs can converge them later.
            if alive < expected:
                return ActionResult(
                    True,
                    f"Head changed; VERIFY {alive}/{expected} nodes, "
                    f"{cpu:g} CPU. Some workers need attention.")
            return ActionResult(
                True,
                f"Head changed; VERIFY {alive}/{expected} nodes, {cpu:g} CPU.")
        finally:
            if self.controller is not None:
                self.controller.repairing = False


class ClusterMonitor(threading.Thread):
    _METRIC_SOFT_MISS_LIMIT = 2
    _METRIC_STALE_SEC = 8.0
    _METRIC_CACHE_FIELDS = (
        "temp_cpu_pkg", "temp_cpu_max", "temp_gpu", "temp_error",
        "os_cpu_pct", "ram_total_gb", "ram_used_gb", "ram_available_gb",
        "ram_pct", "disks", "disk_io_bps", "disk_active", "disk_error",
        "net_down_bps", "net_up_bps", "ping_ms", "net_down_total_bytes",
        "net_up_total_bytes", "metrics_uptime_sec", "metrics_ts",
        "metrics_age_sec", "conn_label",
        "conn_type", "conn_name", "conn_category", "net_error",
        "metrics_error",
    )

    def __init__(self, cfg, on_update):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.on_update = on_update
        self._stop_event = threading.Event()
        self._wake = threading.Event()
        self._last_good: Optional[ClusterView] = None
        self._fail_count = 0
        self._metrics_cache: dict[str, dict] = {}
        self._metrics_fail_count: dict[str, int] = {}
        self._metrics_soft_miss_count: dict[str, int] = {}
        self._metrics_skip_until: dict[str, float] = {}
        # Legacy peers do not report producer-side cache age. Remember whether
        # their timestamp advances using this PC's monotonic clock rather than
        # subtracting wall-clock values across different machines.
        self._metrics_remote_progress: dict[str, tuple[float, float]] = {}
        self._metrics_lock = threading.Lock()

    def stop(self):
        self._stop_event.set(); self._wake.set()

    def poke(self):
        self._wake.set()

    def run(self):
        while not self._stop_event.is_set():
            try:
                view = self.fetch()
                self._last_good = view
                self._fail_count = 0
            except Exception as exc:
                self._fail_count += 1
                limit = max(1, int(self.cfg.get("dashboard_unreachable_failures", 3)))
                grace = max(
                    float(self.cfg.get("dashboard_stale_grace_sec", 45.0)),
                    float(self.cfg.get("poll_interval", 1.5)) * limit,
                )
                age = (
                    time.time() - float(getattr(self._last_good, "ts", 0) or 0)
                    if self._last_good is not None else grace + 1.0
                )
                if self._last_good is not None and (self._fail_count < limit or age < grace):
                    view = replace(
                        self._last_good,
                        stale=True,
                        error=f"refresh failed {self._fail_count}: {exc}",
                        ts=time.time(),
                    )
                else:
                    head_ip = str(self.cfg.get("head_ip") or "")
                    head_port = int(self.cfg.get("head_port") or 6379)
                    view = ClusterView(
                        reachable=False,
                        gcs_open=_tcp_open(
                            head_ip, head_port, timeout=1.0),
                        error=str(exc), ts=time.time())
            if self._stop_event.is_set():
                break
            try: self.on_update(view)
            except Exception: pass
            self._wake.clear()
            self._wake.wait(timeout=max(0.5, float(self.cfg.get("poll_interval", 1.5))))

    def _base(self) -> str:
        return f"http://{self.cfg['head_ip']}:{self.cfg['dashboard_port']}"

    def fetch(self) -> ClusterView:
        view = ClusterView(ts=time.time())
        reg: dict[str, dict] = {}
        reg_by_name: dict[str, dict] = {}
        controller_ips: set[str] = set()
        for n in self.cfg.get("nodes", []):
            if not isinstance(n, dict):
                continue
            ip = str(n.get("ip") or "").strip()
            if is_controller_node(n):
                if ip:
                    controller_ips.add(ip)
                continue
            if ip:
                reg[ip] = n
            name_key = _node_label_key(n.get("name"))
            if name_key:
                reg_by_name.setdefault(name_key, n)
        _, this_ip, _ = resolve_identity(self.cfg)

        timeout = max(1.0, float(self.cfg.get("dashboard_timeout_sec", 6.0)))
        r = requests.get(self._base() + "/api/v0/nodes", timeout=timeout, params={"limit": 200})
        r.raise_for_status()
        payload = r.json() if r.content else {}
        rows = (((payload or {}).get("data") or {}).get("result") or {}).get("result") or []
        if not isinstance(rows, list):
            rows = []

        by_ip: dict[str, dict] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = str(row.get("node_ip") or "").strip()
            if not ip:
                continue
            cur = by_ip.get(ip)
            alive = row.get("state") == "ALIVE"
            if cur is None or (alive and cur.get("state") != "ALIVE"):
                by_ip[ip] = row

        usage_by_id: dict = {}
        try:
            cs = requests.get(self._base() + "/api/cluster_status", timeout=timeout).json()
            usage_by_id = (cs.get("data", {}) or {}).get("clusterStatus", {}) \
                .get("loadMetricsReport", {}).get("usageByNode", {}) or {}
        except Exception:
            usage_by_id = {}

        nodes: list[NodeView] = []
        for ip, row in by_ip.items():
            if ip in controller_ips:
                continue
            res = row.get("resources_total") or {}
            alive = row.get("state") == "ALIVE"
            nid = row.get("node_id") or ""
            dash_name = row.get("node_name") or ip
            cfg_info = reg.get(ip) or reg_by_name.get(_node_label_key(dash_name)) or {}
            view_ip = str(cfg_info.get("ip") or ip).strip() or ip
            used_cpu = 0.0
            if alive:
                u = (usage_by_id.get(nid) or {}).get("CPU")
                if isinstance(u, (list, tuple)) and len(u) >= 1:
                    try: used_cpu = float(u[0])
                    except (TypeError, ValueError): pass
            nodes.append(NodeView(
                ip=view_ip,
                hostname=dash_name,
                alive=alive,
                cpu=float(res.get("CPU", 0) or 0),
                cpu_used=used_cpu,
                gpu=float(res.get("GPU", 0) or 0),
                mem_gb=float(res.get("memory", 0) or 0) / (1024 ** 3),
                is_head=bool(row.get("is_head_node")),
                name=cfg_info.get("name", ""),
                is_this=(view_ip == this_ip or ip == this_ip),
                node_id=nid,
                rdp_user=cfg_info.get("rdp_user", ""),
                rdp_port=normalized_rdp_port(cfg_info.get("rdp_port")),
                registered=bool(cfg_info),
            ))
        represented_ips = {n.ip for n in nodes if n.ip}
        represented_names = {
            key for n in nodes
            for key in (_node_label_key(n.name), _node_label_key(n.hostname))
            if key
        }
        for ip, info in reg.items():
            name_key = _node_label_key(info.get("name"))
            if (not ip or ip in represented_ips
                    or (name_key and name_key in represented_names)):
                continue
            try:
                cpu = float(info.get("num_cpus", 0) or 0)
            except (TypeError, ValueError):
                cpu = 0.0
            role = str(info.get("role", "worker")).lower()
            nodes.append(NodeView(
                ip=ip,
                hostname=info.get("name") or ip,
                alive=False,
                cpu=cpu,
                cpu_used=0.0,
                gpu=0.0,
                mem_gb=0.0,
                is_head=(role == "head"),
                name=info.get("name", ""),
                is_this=(ip == this_ip),
                rdp_user=info.get("rdp_user", ""),
                rdp_port=normalized_rdp_port(info.get("rdp_port")), registered=True,
                metrics_error="not in Ray",
            ))
        nodes = _dedupe_node_views(nodes)
        nodes.sort(key=lambda n: (not n.is_head, not n.alive, n.ip))
        view.nodes = nodes
        view.reachable = True
        view.alive_nodes = sum(1 for n in nodes if n.alive)
        view.total_cpu = sum(n.cpu for n in nodes if n.alive)
        view.used_cpu = sum(n.cpu_used for n in nodes if n.alive)
        # v1.4: poll per-node temp + OS metrics (RCM 8866 endpoint)
        metrics_enabled = self.cfg.get("metrics_enabled", True)
        temp_enabled = self.cfg.get("temp_enabled", True)
        if temp_enabled or metrics_enabled:
            self._enrich_metrics(nodes)
            if temp_enabled:
                # compute cluster max (all nodes with temp data)
                max_t = None
                max_n = ""
                for n in nodes:
                    v = n.temp_cpu_max if n.temp_cpu_max is not None else n.temp_cpu_pkg
                    if v is None:
                        continue
                    if max_t is None or v > max_t:
                        max_t = v
                        max_n = n.name or n.hostname or n.ip
                view.max_temp_c = max_t
                view.max_temp_node = max_n
            if metrics_enabled:
                self._compute_os_summary(view)
        return view

    def _compute_os_summary(self, view: ClusterView):
        cpu_weighted = 0.0
        cpu_total = 0.0
        ram_used = 0.0
        ram_total = 0.0
        net_down_bps = 0.0
        net_up_bps = 0.0
        net_down_total = 0.0
        net_up_total = 0.0
        net_count = 0
        net_uptimes = []
        g_first = None
        g_this = None
        for n in view.nodes:
            if n.os_cpu_pct is not None and n.cpu > 0:
                cpu_weighted += n.os_cpu_pct * n.cpu
                cpu_total += n.cpu
            if n.ram_used_gb is not None and n.ram_total_gb:
                ram_used += n.ram_used_gb
                ram_total += n.ram_total_gb
            if n.net_down_bps is not None and n.net_up_bps is not None:
                net_down_bps += n.net_down_bps
                net_up_bps += n.net_up_bps
                if n.net_down_total_bytes is not None:
                    net_down_total += n.net_down_total_bytes
                if n.net_up_total_bytes is not None:
                    net_up_total += n.net_up_total_bytes
                if n.metrics_uptime_sec is not None:
                    net_uptimes.append(n.metrics_uptime_sec)
                net_count += 1
            if n.metrics_uptime_sec is not None or n.alive:
                for d in getattr(n, "disks", []) or []:
                    if not isinstance(d, dict) or not d.get("present"):
                        continue
                    if str(d.get("drive") or "").upper()[:2] != "G:":
                        continue
                    item = (d, n.name or n.hostname or n.ip)
                    if n.is_this:
                        g_this = item
                    elif g_first is None:
                        g_first = item
        if cpu_total > 0:
            view.os_cpu_avg_pct = cpu_weighted / cpu_total
        if ram_total > 0:
            view.ram_used_gb = ram_used
            view.ram_total_gb = ram_total
            view.ram_pct = (ram_used / ram_total) * 100.0
        if net_count > 0:
            view.net_down_bps = net_down_bps
            view.net_up_bps = net_up_bps
            view.net_down_total_bytes = net_down_total
            view.net_up_total_bytes = net_up_total
            if net_uptimes:
                view.net_uptime_sec = min(net_uptimes)
        g_item = g_this or g_first
        if g_item:
            view.g_disk, view.g_disk_node = g_item

    def _enrich_metrics(self, nodes):
        """Poll /metrics on configured nodes. Falls back to /temps for older RCMs."""
        port = int(self.cfg.get("temp_port", 8866))
        timeout = max(0.5, float(self.cfg.get("metrics_timeout_sec", 1.5)))
        # Metrics are independent from Ray membership: a PC can be reachable via
        # RCM :8866 while its Ray worker is missing or stale. Poll every
        # configured node, with per-node backoff for PCs that are truly offline.
        targets = list(nodes)
        if not targets:
            return
        now = time.monotonic()
        ready = []
        for n in targets:
            self._apply_metric_cache(n)
            if not getattr(n, "is_this", False):
                self._clear_metric_values(n)
                n.temp_error = "legacy_remote_retired"
                n.metrics_error = "legacy_remote_retired"
                continue
            with self._metrics_lock:
                skip_until = self._metrics_skip_until.get(n.ip, 0.0)
            if skip_until > now:
                if not n.metrics_error:
                    n.metrics_error = "metrics backoff"
                continue
            ready.append(n)
        targets = ready
        if not targets:
            return
        threads = []
        for n in targets:
            t = threading.Thread(target=self._fetch_one_metrics,
                                 args=(n, port, timeout), daemon=True)
            t.start()
            threads.append(t)
        deadline = time.monotonic() + timeout + 0.3
        for t in threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            t.join(timeout=remaining)

    def _apply_metric_cache(self, node):
        with self._metrics_lock:
            cached = self._metrics_cache.get(node.ip)
            if not cached:
                return
            for key, value in cached.items():
                if key == "disks":
                    value = [dict(d) for d in value if isinstance(d, dict)]
                setattr(node, key, value)

    def _remember_metric_cache(self, node):
        data = {}
        for key in self._METRIC_CACHE_FIELDS:
            value = getattr(node, key, None)
            if key == "disks":
                value = [dict(d) for d in (value or []) if isinstance(d, dict)]
            data[key] = value
        with self._metrics_lock:
            self._metrics_cache[node.ip] = data
            self._metrics_fail_count.pop(node.ip, None)
            self._metrics_soft_miss_count.pop(node.ip, None)
            self._metrics_skip_until.pop(node.ip, None)

    def _clear_metric_values(self, node):
        for key in self._METRIC_CACHE_FIELDS:
            if key == "disks":
                setattr(node, key, [])
            elif key in ("disk_active",):
                setattr(node, key, False)
            elif key in (
                    "temp_error", "disk_error", "net_error", "metrics_error",
                    "conn_label", "conn_type", "conn_name", "conn_category"):
                setattr(node, key, "")
            else:
                setattr(node, key, None)

    def _clear_system_metric_values(self, node):
        for key in (
            "os_cpu_pct", "ram_total_gb", "ram_used_gb", "ram_available_gb",
            "ram_pct", "disk_io_bps", "net_down_bps", "net_up_bps",
            "net_down_total_bytes", "net_up_total_bytes", "metrics_uptime_sec",
            "metrics_age_sec",
        ):
            setattr(node, key, None)
        node.disks = []
        node.disk_active = False
        node.disk_error = ""
        node.conn_label = ""
        node.conn_type = ""
        node.conn_name = ""
        node.conn_category = ""
        node.net_error = ""

    def _metric_payload_age(self, node, payload, metric_ts):
        """Return producer-cache age without trusting cross-PC wall clocks."""
        reported = _num_or_none(payload.get("metrics_age_sec"))
        now = time.monotonic()
        if reported is not None:
            age = max(0.0, reported)
            if metric_ts is not None:
                with self._metrics_lock:
                    self._metrics_remote_progress[node.ip] = (metric_ts, now)
            return age
        if metric_ts is None:
            return None
        with self._metrics_lock:
            previous = self._metrics_remote_progress.get(node.ip)
            if previous is None or abs(metric_ts - previous[0]) > 0.001:
                self._metrics_remote_progress[node.ip] = (metric_ts, now)
                return 0.0
            return max(0.0, now - previous[1])

    def _note_metric_failure(self, node):
        with self._metrics_lock:
            self._metrics_cache.pop(node.ip, None)
            self._metrics_soft_miss_count.pop(node.ip, None)
            count = self._metrics_fail_count.get(node.ip, 0) + 1
            self._metrics_fail_count[node.ip] = count
            backoff = min(30.0, max(5.0, 2.0 * count))
            self._metrics_skip_until[node.ip] = time.monotonic() + backoff

    def _note_metric_soft_miss(self, node, label):
        with self._metrics_lock:
            count = self._metrics_soft_miss_count.get(node.ip, 0) + 1
            self._metrics_soft_miss_count[node.ip] = count
            has_cache = node.ip in self._metrics_cache
        if count < self._METRIC_SOFT_MISS_LIMIT and has_cache:
            node.ping_ms = None
            node.temp_error = f"{label} (stale)"
            node.metrics_error = f"{label} (stale)"
            return
        self._clear_metric_values(node)
        node.temp_error = label
        node.metrics_error = label
        self._note_metric_failure(node)

    def _fetch_one_metrics(self, node, port, timeout):
        if not getattr(node, "is_this", False):
            self._clear_metric_values(node)
            node.temp_error = "legacy_remote_retired"
            node.metrics_error = "legacy_remote_retired"
            return
        try:
            legacy_fallback = False
            host = "127.0.0.1"
            if self.cfg.get("metrics_enabled", True):
                r = requests.get(f"http://{host}:{port}/metrics", timeout=timeout)
            else:
                r = requests.get(f"http://{host}:{port}/temps", timeout=timeout)
            if r.status_code == 404 and self.cfg.get("temp_enabled", True):
                legacy_fallback = True
                r = requests.get(f"http://{host}:{port}/temps", timeout=timeout)
            if not r.ok:
                self._clear_metric_values(node)
                node.temp_error = f"HTTP {r.status_code}"
                node.metrics_error = f"HTTP {r.status_code}"
                self._note_metric_failure(node)
                return
            # Round-trip time of the single successful request (the /temps
            # fallback reassigns r, so r.elapsed never spans both requests).
            try:
                node.ping_ms = round(r.elapsed.total_seconds() * 1000.0, 1)
            except Exception:
                node.ping_ms = None
            d = r.json()
            if self.cfg.get("temp_enabled", True):
                node.temp_cpu_pkg = d.get("cpu_pkg")
                node.temp_cpu_max = d.get("cpu_max")
                node.temp_gpu = d.get("gpu")
                node.temp_error = d.get("error", "")
            else:
                node.temp_cpu_pkg = None
                node.temp_cpu_max = None
                node.temp_gpu = None
                node.temp_error = ""
            if self.cfg.get("metrics_enabled", True):
                metric_ts = _num_or_none(d.get("metrics_ts"))
                node.os_cpu_pct = _num_or_none(d.get("os_cpu_pct"))
                node.ram_total_gb = _num_or_none(d.get("ram_total_gb"))
                node.ram_used_gb = _num_or_none(d.get("ram_used_gb"))
                node.ram_available_gb = _num_or_none(d.get("ram_available_gb"))
                node.ram_pct = _num_or_none(d.get("ram_pct"))
                disks = d.get("disks")
                node.disks = disks if isinstance(disks, list) else []
                node.disk_io_bps = _num_or_none(d.get("disk_io_bps"))
                node.disk_active = bool(d.get("disk_active", False))
                node.disk_error = d.get("disk_error", "")
                node.net_down_bps = _num_or_none(d.get("net_down_bps"))
                node.net_up_bps = _num_or_none(d.get("net_up_bps"))
                node.net_down_total_bytes = _num_or_none(d.get("net_down_total_bytes"))
                node.net_up_total_bytes = _num_or_none(d.get("net_up_total_bytes"))
                node.metrics_uptime_sec = _num_or_none(d.get("metrics_uptime_sec"))
                node.metrics_ts = metric_ts
                node.metrics_age_sec = self._metric_payload_age(
                    node, d, metric_ts)
                node.conn_label = str(d.get("conn_label") or "")
                node.conn_type = str(d.get("conn_type") or "")
                node.conn_name = str(d.get("conn_name") or "")
                node.conn_category = str(d.get("conn_category") or "")
                node.net_error = d.get("net_error", "")
                node.metrics_error = d.get("metrics_error", "")
                if legacy_fallback and not node.metrics_error:
                    node.metrics_error = "legacy /temps fallback"
                if (not legacy_fallback and node.metrics_age_sec is not None
                        and node.metrics_age_sec > self._METRIC_STALE_SEC):
                    age = node.metrics_age_sec
                    self._clear_system_metric_values(node)
                    node.metrics_ts = metric_ts
                    node.metrics_error = f"metrics stale {age:.1f}s"
            self._remember_metric_cache(node)
        except requests.Timeout:
            self._note_metric_soft_miss(node, "timeout")
        except Exception as exc:
            self._note_metric_soft_miss(node, f"{type(exc).__name__}")


# =========================================================================
#  Settings dialog
# =========================================================================
class SettingsDialog(tk.Toplevel):
    """A focused, DPI-safe settings surface in the main window's Win98 theme.

    v1.07.16c [retrofit]: the 1.07.12b redesign gave Settings its own modern
    visual system (white cards, Segoe blue accents) that clashed with the
    Win98-style main window.  The five-section structure, DPI-scaled sizing,
    and Treeview workspace are kept, but every surface now uses the shared
    gray face, groove group boxes, sunken entries, classic raised buttons,
    and the canonical navy selection color so the whole app reads as one
    program.
    """

    _SURFACE = GRAY
    _CARD = GRAY
    _SIDEBAR = GRAY
    _BORDER = GRAY_DK
    _TEXT = BLACK
    _MUTED = GRAY_DKR
    _ACCENT = BLUE98
    _ACCENT_SOFT = GRAY_LT
    _DANGER = RED

    def __init__(
            self, master, cfg, on_save, on_password_action=None,
            on_make_head=None):
        super().__init__(master)
        self.cfg = cfg
        self.on_save = on_save
        self.title("Settings")
        # v1.5.33 [fitscreen]: scale the dialog (and its wraplengths below) by
        # the active UI scale so the Settings window is not cramped at high DPI.
        try:
            self._ui_scale = clamp_scaling(master.tk.call("tk", "scaling"))
        except Exception:
            self._ui_scale = AUTO_UI_SCALING_FLOOR
        self._install_settings_fonts()
        # Geometry is already in window pixels.  Scaling it again with Tk's
        # text factor made Settings near-full-screen at high DPI.
        _dw, _dh = 840, 580
        try:
            _dw = min(_dw, max(420, self.winfo_screenwidth() - 32))
            _dh = min(_dh, max(360, self.winfo_screenheight() - 72))
        except Exception:
            pass
        self.geometry(f"{_dw}x{_dh}")
        # At 200%+ text scaling the Nodes property page needs a few more
        # physical pixels for its heading plus one complete data row.  Grow
        # only the minimum (the normal 840x580 default is unchanged) and keep
        # the result clamped to the available work-area height.
        high_dpi_height = 480 + max(
            0, int(round((self._ui_scale - 2.5) * 120)))
        self.minsize(
            min(720, _dw), min(_dh, high_dpi_height))
        self.configure(bg=self._SURFACE)
        self.resizable(True, True)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.transient(master)
        self.grab_set()
        try: self.iconbitmap(resource_path("assets/icon.ico"))
        except Exception: pass

        self._node_rows: list = []  # compatibility for older integrations
        self._node_records = [json.loads(json.dumps(n)) for n in cfg.get("nodes", [])
                              if isinstance(n, dict)]
        self._node_item_data = {}
        self._password_action_callback = on_password_action
        self._make_head_callback = on_make_head
        self._setup_settings_styles()

        body = tk.Frame(self, bg=self._SURFACE)
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        nav = tk.Frame(body, bg=self._SIDEBAR,
                       bd=2, relief="groove")
        nav.grid(row=0, column=0, sticky="ew")
        tk.Label(
            nav, text="Settings:", bg=self._SIDEBAR, fg=self._TEXT,
            anchor="w", font=self._settings_font("bold")).pack(
                side="left", padx=(scaled_px(8, self._ui_scale),
                                   scaled_px(5, self._ui_scale)))
        nav_items = tk.Frame(nav, bg=self._SIDEBAR)
        nav_items.pack(side="left", pady=scaled_px(4, self._ui_scale))
        self._nav_buttons = []
        for index, (label, hint) in enumerate((
                ("General", "This PC and startup"),
                ("Cluster", "Ray and networking"),
                ("Monitoring", "Health thresholds"),
                ("Nodes & RDP", "Machines and access"),
                ("Cleanup", "Local process safety"),
                ("Help", "Guides in 5 languages"))):
            item = tk.Frame(nav_items, bg=self._SIDEBAR)
            item.pack(side="left", padx=(0, scaled_px(2, self._ui_scale)))
            item.columnconfigure(0, weight=1)
            indicator = tk.Frame(item, bg=self._SIDEBAR,
                                 height=scaled_px(2, self._ui_scale))
            indicator.grid(row=1, column=0, sticky="ew")
            button = tk.Button(
                item, text=label,
                command=lambda i=index: self._show_settings_section(i),
                bg=self._SIDEBAR, fg=self._TEXT, activebackground=self._ACCENT_SOFT,
                activeforeground=self._ACCENT, relief="raised", bd=2,
                highlightthickness=0, anchor="center", cursor="hand2",
                font=self._settings_font("default"),
                padx=scaled_px(4, self._ui_scale),
                pady=scaled_px(1, self._ui_scale))
            button.grid(row=0, column=0, sticky="ew")
            self._nav_buttons.append((item, indicator, button))
        pages = tk.Frame(body, bg=self._SURFACE)
        pages.grid(row=1, column=0, sticky="nsew")
        pages.columnconfigure(0, weight=1)
        pages.rowconfigure(0, weight=1)
        self._settings_pages = []
        self._settings_page_hosts = []
        self._settings_canvases = []
        self._settings_scrollbars = []
        self._settings_canvas_windows = []
        page_specs = (
                ("General", "This PC, startup behavior, and display scaling"),
                ("Cluster", "Ray head connection and Tailscale firewall"),
                ("Monitoring", "Temperature and system usage display"),
                ("Nodes & RDP", "Node list, RDP accounts, and credentials"),
                ("Cleanup", "Local process review and safe termination"),
                ("Help", "Complete operating guide in your language"))
        for page_index, (title, subtitle) in enumerate(page_specs):
            host = tk.Frame(pages, bg=self._SURFACE)
            host.grid(row=0, column=0, sticky="nsew")
            host.columnconfigure(0, weight=1)
            host.rowconfigure(0, weight=1)
            canvas = tk.Canvas(
                host, bg=self._SURFACE, bd=0, relief="flat",
                highlightthickness=0)
            scrollbar = tk.Scrollbar(
                host, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.grid(row=0, column=0, sticky="nsew")
            page = tk.Frame(
                canvas, bg=self._SURFACE,
                padx=scaled_px(14, self._ui_scale),
                pady=scaled_px(10, self._ui_scale))
            canvas_window = canvas.create_window(
                (0, 0), window=page, anchor="nw")
            page.columnconfigure(0, weight=1)
            page_header = tk.Frame(page, bg=self._SURFACE)
            page_header.pack(
                fill="x", pady=(0, scaled_px(8, self._ui_scale)))
            tk.Label(
                page_header, text=title, bg=self._SURFACE, fg=self._TEXT,
                anchor="w", font=self._settings_font("bold")).pack(side="left")
            tk.Label(
                page_header, text=f" - {subtitle}",
                bg=self._SURFACE, fg=self._MUTED, anchor="w",
                font=self._settings_font("small")).pack(
                    side="left", padx=(scaled_px(3, self._ui_scale), 0))
            self._settings_page_hosts.append(host)
            self._settings_canvases.append(canvas)
            self._settings_scrollbars.append(scrollbar)
            self._settings_canvas_windows.append(canvas_window)
            self._settings_pages.append(page)
            page.bind(
                "<Configure>",
                lambda _e, i=page_index: self._sync_settings_page(i))
            canvas.bind(
                "<Configure>",
                lambda _e, i=page_index: self._sync_settings_page(i))

        # General
        general = self._settings_pages[0]
        general_grid = tk.Frame(general, bg=self._SURFACE)
        general_grid.pack(fill="both", expand=True)
        # Prefer the compact two-column arrangement.  A live canvas-width
        # pass stacks cards only when their measured requested widths cannot
        # fit, including after DPI/RDP changes.
        stacked_settings = False
        self._settings_stacked = stacked_settings
        stacked_cluster = False
        for column in (0, 1):
            general_grid.columnconfigure(column, weight=1, uniform="general")
        general_grid.rowconfigure(1, weight=1)
        pc_pos = (0, 0)
        behavior_pos = (1, 0) if stacked_settings else (0, 1)
        pc = self._card(general_grid, "This PC",
                        "How this machine participates in the Ray cluster.",
                        *pc_pos, columnspan=(2 if stacked_settings else 1))
        self.cmb_role = self._optionmenu(pc, "Role:", ["auto", "head", "worker"],
                                         cfg["this"]["role"], 0)
        self.e_this_ip = self._field(pc, "Tailscale IP:", cfg["this"]["ip"], 1)
        self.e_cpus = self._field(
            pc, "Ray CPUs (auto / 0=driver):",
            cfg["this"]["num_cpus"], 2)
        behavior = self._card(general_grid, "Startup & shutdown",
                              "Choose what RCM does automatically.",
                              *behavior_pos,
                              columnspan=(2 if stacked_settings else 1))
        self.cmb_close = tk.StringVar(value="tray")
        self.var_stopquit = tk.BooleanVar(value=cfg["stop_on_quit"])
        self.var_launch = tk.BooleanVar(value=cfg["start_on_launch"])
        self.var_login = tk.BooleanVar(value=cfg["autostart_login"])
        for text_, var_ in (
                ("Start this Ray node when RCM opens", self.var_launch),
                ("Launch RCM at Windows sign-in", self.var_login),
                ("Stop Ray when quitting from the tray", self.var_stopquit)):
            self._checkbutton(behavior, text_, var_).pack(
                anchor="w", pady=(0, scaled_px(7, self._ui_scale)))
        tk.Label(behavior, text="Window X sends RCM to the tray.",
                 bg=self._CARD, fg=self._MUTED, justify="left",
                 font=self._settings_font("small")).pack(
                     anchor="w", pady=(scaled_px(4, self._ui_scale), 0))
        display = self._card(general_grid, "Display scaling",
                             "Control sizing on high-DPI and remote displays.",
                             (2 if stacked_settings else 1), 0,
                             columnspan=2, sticky="new")
        self.var_ui_scale_mode = self._optionmenu(
            display, "DPI mode:", ["stable", "windows"],
            cfg.get("ui_scale_mode", "stable"), 0)
        self.e_ui_scaling = self._field(
            display, "Stable scale:", cfg.get("ui_scaling", "auto"), 1)
        self._general_grid = general_grid
        self._general_pc_card = pc.master
        self._general_behavior_card = behavior.master
        self._general_display_card = display.master
        self._general_page_stacked = False
        tk.Label(display, text="Recommended: stable + auto  ·  Manual range: 1.33-3.00",
                 bg=self._CARD, fg=self._MUTED,
                 font=self._settings_font("small")).grid(
                     row=2, column=0, columnspan=2, sticky="w",
                     pady=(scaled_px(5, self._ui_scale), 0))

        # Cluster
        cluster = self._settings_pages[1]
        cluster_grid = tk.Frame(cluster, bg=self._SURFACE)
        cluster_grid.pack(fill="both", expand=True)
        for column in (0, 1):
            cluster_grid.columnconfigure(column, weight=1, uniform="cluster")
        conn_pos = (0, 0)
        runtime_pos = (1, 0) if stacked_cluster else (0, 1)
        network_pos = (2, 0) if stacked_cluster else (1, 1)
        conn = self._card(cluster_grid, "Head connection",
                          "Shared connection values for every cluster PC.",
                          *conn_pos,
                          columnspan=(2 if stacked_cluster else 1),
                          rowspan=(1 if stacked_cluster else 2))
        self.e_head_ip = self._field(conn, "Head IP:", cfg["head_ip"], 0)
        self.e_head_port = self._field(conn, "Head port:", cfg["head_port"], 1)
        self.e_dash_port = self._field(conn, "Dashboard port:", cfg["dashboard_port"], 2)
        self.e_poll = self._field(conn, "Refresh interval (sec):", cfg["poll_interval"], 3)
        runtime = self._card(cluster_grid, "Ray executable",
                             "Use auto unless Ray is installed in a custom location.",
                             *runtime_pos,
                             columnspan=(2 if stacked_cluster else 1))
        self.e_ray = self._field(runtime, "ray.exe:", cfg["ray_exe"], 0)
        self._button(runtime, "Browse…", self._browse_ray_exe).grid(
            row=0, column=2, padx=(scaled_px(7, self._ui_scale), 0), sticky="e")
        network = self._card(cluster_grid, "Tailscale firewall",
                             "Verify the inbound rules used by Ray and RCM.",
                             *network_pos,
                             columnspan=(2 if stacked_cluster else 1),
                             sticky="new")
        tk.Label(network,
                 text="Ray 6379, 6380-6385, 8265, 10001-10100  ·  "
                      "LHM 8085  ·  RCM 8866",
                 bg=self._CARD, fg=self._MUTED, justify="left",
                 font=self._settings_font("small"),
                 wraplength=310).grid(
                     row=0, column=0, columnspan=2, sticky="w")
        self._button(network, "Check firewall", self._firewall_check).grid(
            row=1, column=0, columnspan=2, sticky="w",
            pady=(scaled_px(10, self._ui_scale), 0))
        guard = self._card(
            cluster_grid, "Head dashboard recovery",
            "Restart the Ray cluster if GCS stays alive but Dashboard dies.",
            (3 if stacked_cluster else 2), 0,
            columnspan=2, sticky="new")
        self.var_head_guard = tk.BooleanVar(
            value=cfg.get("head_dashboard_guard_enabled", True))
        self._checkbutton(
            guard, "Enable automatic head dashboard recovery",
            self.var_head_guard).grid(
                row=0, column=0, columnspan=2, sticky="w")
        self.e_head_guard_interval = self._field(
            guard, "Probe interval (sec):",
            cfg.get("head_dashboard_guard_interval_sec", 20), 1)
        self.e_head_guard_cycles = self._field(
            guard, "Failed probes before recovery:",
            cfg.get("head_dashboard_guard_cycles", 3), 2)
        self._cluster_grid = cluster_grid
        self._cluster_connection_card = conn.master
        self._cluster_runtime_card = runtime.master
        self._cluster_network_card = network.master
        self._cluster_guard_card = guard.master
        self._cluster_page_stacked = False

        # Monitoring
        monitor = self._settings_pages[2]
        monitor_grid = tk.Frame(monitor, bg=self._SURFACE)
        monitor_grid.pack(fill="both", expand=True)
        for column in (0, 1):
            monitor_grid.columnconfigure(column, weight=1, uniform="monitor")
        temp = self._card(monitor_grid, "Temperature",
                          "Sensor endpoint and protection thresholds.", 0, 0,
                          columnspan=(2 if stacked_settings else 1))
        self.var_temp_en = tk.BooleanVar(value=cfg.get("temp_enabled", True))
        self._checkbutton(temp, "Enable temperature monitoring", self.var_temp_en).grid(
                           row=0, column=0, columnspan=2, sticky="w")
        self.e_temp_warn = self._field(temp, "Warning °C:", cfg.get("temp_warn_c", 80), 1)
        self.e_temp_crit = self._field(temp, "Critical °C:", cfg.get("temp_critical_c", 100), 2)
        self.e_temp_port = self._field(temp, "Endpoint port:", cfg.get("temp_port", 8866), 3)
        self.e_temp_poll = self._field(temp, "Poll interval (sec):", cfg.get("temp_poll_sec", 2.0), 4)
        self.var_temp_ap = tk.BooleanVar(value=cfg.get("temp_auto_pause", False))
        self._checkbutton(temp, "Stop Ray at critical temperature", self.var_temp_ap).grid(
            row=5, column=0, columnspan=2, sticky="w",
            pady=(scaled_px(7, self._ui_scale), 0))
        metrics = self._card(monitor_grid, "System metrics",
                             "CPU, memory, disk, and diagnostic display.",
                             (1 if stacked_settings else 0),
                             (0 if stacked_settings else 1),
                             columnspan=(2 if stacked_settings else 1))
        self.var_metrics_en = tk.BooleanVar(value=cfg.get("metrics_enabled", True))
        self._checkbutton(metrics, "Show CPU, RAM, and disk information",
                          self.var_metrics_en).grid(
                              row=0, column=0, columnspan=2, sticky="w")
        self.e_os_cpu_warn = self._field(metrics, "CPU warning %:", cfg.get("os_cpu_warn_pct", 80), 1)
        self.e_os_cpu_crit = self._field(metrics, "CPU critical %:", cfg.get("os_cpu_critical_pct", 95), 2)
        self.e_ram_warn = self._field(metrics, "RAM warning %:", cfg.get("ram_warn_pct", 85), 3)
        self.e_ram_crit = self._field(metrics, "RAM critical %:", cfg.get("ram_critical_pct", 95), 4)
        self.var_diag_font = self._optionmenu(
            metrics, "Diagnostic font:", DIAG_FONT_CHOICES,
            cfg.get("diagnostic_font", "Consolas"), 5)
        self._monitor_grid = monitor_grid
        self._monitor_temperature_card = temp.master
        self._monitor_metrics_card = metrics.master
        self._monitor_page_stacked = False

        # Nodes and RDP
        nodes_page = self._settings_pages[3]
        nodes_body = tk.Frame(nodes_page, bg=self._SURFACE)
        nodes_body.pack(fill="both", expand=True)
        nodes_body.columnconfigure(0, weight=1)
        # Reserve a complete heading plus one complete data row even at
        # 192/216 DPI; otherwise Treeview reported an unusable (0, 0) yview.
        nodes_body.rowconfigure(
            1, weight=1, minsize=scaled_px(42, self._ui_scale))
        self._nodes_body = nodes_body
        notice = tk.Frame(nodes_body, bg=self._ACCENT_SOFT, bd=1,
                          relief="sunken", highlightthickness=0)
        notice.grid(
            row=0, column=0, sticky="ew",
            pady=(0, scaled_px(6, self._ui_scale)))
        tk.Label(notice,
                 text="Controllers connect outward; they are not RDP targets. "
                      "Credentials use Windows Credential Manager.",
                 bg=self._ACCENT_SOFT, fg=self._TEXT, anchor="w", justify="left",
                 font=self._settings_font("small"),
                 wraplength=600).pack(
                     fill="x", padx=scaled_px(8, self._ui_scale),
                     pady=scaled_px(5, self._ui_scale))
        tree_wrap = tk.Frame(nodes_body, bg=self._BORDER,
                             highlightthickness=1, highlightbackground=self._BORDER)
        tree_wrap.grid(row=1, column=0, sticky="nsew")
        tree_wrap.columnconfigure(0, weight=1)
        tree_wrap.rowconfigure(0, weight=1)
        columns = ("name", "ip", "mode", "role", "cpu", "rdp", "port", "credential")
        style = ttk.Style(self)
        style.configure("Settings.Treeview",
                        rowheight=scaled_px(22, self._ui_scale),
                        font=self._settings_font("default"), background=WHITE,
                        fieldbackground=WHITE, foreground=BLACK,
                        borderwidth=0)
        style.map("Settings.Treeview",
                  background=[("selected", self._ACCENT)],
                  foreground=[("selected", WHITE)])
        style.configure("Settings.Treeview.Heading",
                        font=self._settings_font("bold"),
                        background=self._CARD, foreground=self._TEXT,
                        relief="raised", padding=scaled_px(5, self._ui_scale))
        self.nodes_tree = ttk.Treeview(
            tree_wrap, columns=columns, show="headings", selectmode="browse",
            style="Settings.Treeview", height=4)
        headings = {"name": "Name", "ip": "Tailscale IP", "mode": "Mode",
                    "role": "Ray role", "cpu": "CPU", "rdp": "RDP account",
                    "port": "Port", "credential": "Credential"}
        widths = {"name": 105, "ip": 120, "mode": 70, "role": 80,
                  "cpu": 50, "rdp": 155, "port": 55, "credential": 90}
        heading_font = tkfont.Font(
            root=self, font=self._settings_font("bold"))
        for col in columns:
            self.nodes_tree.heading(col, text=headings[col])
            column_width = max(
                scaled_px(widths[col], self._ui_scale),
                heading_font.measure(headings[col])
                + scaled_px(20, self._ui_scale))
            self.nodes_tree.column(col, width=column_width,
                                   minwidth=scaled_px(55, self._ui_scale),
                                   stretch=(col in ("name", "rdp")))
        tree_y = ttk.Scrollbar(tree_wrap, orient="vertical",
                               command=self.nodes_tree.yview)
        tree_x = ttk.Scrollbar(tree_wrap, orient="horizontal",
                               command=self.nodes_tree.xview)
        self.nodes_tree_y = tree_y
        self.nodes_tree_x = tree_x
        self.nodes_tree.configure(
            yscrollcommand=self._nodes_yview_changed,
            xscrollcommand=self._nodes_xview_changed)
        self.nodes_tree.grid(row=0, column=0, sticky="nsew")
        tree_y.grid(row=0, column=1, sticky="ns")
        tree_x.grid(row=1, column=0, sticky="ew")
        tree_y.grid_remove()
        tree_x.grid_remove()
        self.nodes_tree.bind(
            "<Configure>",
            lambda _event: self.after_idle(
                self._refresh_node_scrollbars),
            add="+")
        self.nodes_tree.bind("<Double-1>", lambda _e: self._edit_selected_node())
        self.nodes_tree.bind("<Button-3>", self._show_node_context_menu)
        self.nodes_tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_node_buttons())
        node_actions = tk.Frame(nodes_body, bg=self._SURFACE)
        node_actions.grid(
            row=2, column=0, sticky="ew",
            pady=(scaled_px(6, self._ui_scale), 0))
        node_actions.columnconfigure(0, weight=1)
        local_actions = tk.Frame(node_actions, bg=self._SURFACE)
        local_actions.grid(row=0, column=0, sticky="w")
        self._button(local_actions, "Add node", self._add_node_dialog,
                     primary=True).pack(side="left")
        self._button(local_actions, "Help / Add a PC", self._show_new_pc_guide).pack(
            side="left", padx=(scaled_px(6, self._ui_scale), 0))
        self.btn_node_edit = self._button(local_actions, "Edit", self._edit_selected_node)
        self.btn_node_edit.pack(side="left", padx=(scaled_px(6, self._ui_scale), 0))
        self.btn_node_delete = self._button(local_actions, "Delete", self._delete_selected_node)
        self.btn_node_delete.pack(side="left", padx=(scaled_px(6, self._ui_scale), 0))
        credential_actions = tk.Frame(node_actions, bg=self._SURFACE)
        # Credentials get their own responsive row. Competing left/right pack
        # groups clipped "Change multiple..." at every tested DPI.
        credential_actions.grid(
            row=1, column=0, sticky="e",
            pady=(scaled_px(5, self._ui_scale), 0))
        self._node_local_actions = local_actions
        self._node_credential_actions = credential_actions
        self.btn_password = self._button(
            credential_actions, "Change password…", lambda: self._password_action("change"))
        self.btn_password.pack(side="right")
        self.btn_credential_delete = self._button(
            credential_actions, "Delete credential", lambda: self._password_action("delete"))
        self.btn_credential_delete.pack(side="right", padx=(0, scaled_px(6, self._ui_scale)))
        self.btn_batch_password = self._button(
            credential_actions, "Change multiple…", lambda: self._password_action("batch"))
        self.btn_batch_password.pack(side="right", padx=(0, scaled_px(6, self._ui_scale)))
        self._populate_node_tree()
        self._sync_node_buttons()

        # Cleanup
        cleanup_page = self._settings_pages[4]
        cleanup_grid = tk.Frame(cleanup_page, bg=self._SURFACE)
        cleanup_grid.pack(fill="both", expand=True)
        for column in (0, 1):
            cleanup_grid.columnconfigure(column, weight=1)
        cleanup_cfg = cfg.get("process_cleanup", {})
        if not isinstance(cleanup_cfg, dict):
            cleanup_cfg = {}
        timing = self._card(
            cleanup_grid, "Scan timing",
            "Sampling time and post-end verification wait.",
            0, 0)
        self.e_cleanup_sample = self._field(
            timing, "Scan sample (sec):",
            cleanup_cfg.get("sample_sec", 8.0), 0)
        self.e_cleanup_grace = self._field(
            timing, "End grace period (sec):",
            cleanup_cfg.get("grace_sec", 3.0), 1)
        self.e_cleanup_sample.configure(width=14)
        self.e_cleanup_grace.configure(width=14)
        tk.Label(
            timing,
            text="Defaults: 8s scan · 3s grace",
            bg=self._CARD, fg=self._MUTED, anchor="w", justify="left",
            font=self._settings_font("small")).grid(
                row=2, column=0, columnspan=2, sticky="w",
                pady=(scaled_px(5, self._ui_scale), 0))
        safety = self._card(
            cleanup_grid, "Safety model",
            "Conservative, local-only process review.",
            0, 1)
        tk.Label(
            safety,
            text=(
                "Recommended: selected automatically.\n"
                "Review: requires manual selection.\n"
                "Protected: can never be selected.\n\n"
                "Before ending, RCM rechecks the exact PID, start time, "
                "executable, command identity, and live safety state."
            ),
            bg=self._CARD, fg=self._TEXT, anchor="nw", justify="left",
            font=self._settings_font("default"),
            wraplength=310).grid(
                row=0, column=0, columnspan=2, sticky="new")
        self._cleanup_grid = cleanup_grid
        self._cleanup_timing_card = timing.master
        self._cleanup_safety_card = safety.master
        self._cleanup_page_stacked = False

        # Help. The application chrome stays English; only this page is localized.
        help_page = self._settings_pages[5]
        help_toolbar = tk.Frame(help_page, bg=self._SURFACE)
        help_toolbar.pack(fill="x", pady=(0, scaled_px(10, self._ui_scale)))
        tk.Label(help_toolbar, text="Language:", bg=self._SURFACE,
                 fg=self._TEXT,
                 font=self._settings_font("default")).pack(side="left")
        self.var_help_language = tk.StringVar(value="English")
        help_languages = ("English", "한국어", "日本語", "Español", "中文")
        self.cmb_help_language = tk.OptionMenu(
            help_toolbar, self.var_help_language, *help_languages,
            command=lambda _value: self._refresh_help_text())
        self.cmb_help_language.configure(
            width=14, anchor="w", bg=self._CARD, fg=self._TEXT,
            activebackground=self._ACCENT_SOFT, activeforeground=self._TEXT,
            relief="raised", bd=2, highlightthickness=0,
            font=self._settings_font("default"),
            padx=scaled_px(4, self._ui_scale),
            pady=scaled_px(1, self._ui_scale))
        self.cmb_help_language["menu"].configure(
            font=self._settings_font("default"))
        self.cmb_help_language.pack(
            side="left", padx=(scaled_px(8, self._ui_scale), 0))
        self._button(
            help_toolbar, "Copy help", self._copy_help_text).pack(side="right")
        tk.Label(
            help_page,
            text="Only Help content changes language. The application interface remains English.",
            bg=self._SURFACE, fg=self._MUTED, anchor="w", justify="left",
            font=self._settings_font("small")).pack(
                fill="x", pady=(0, scaled_px(8, self._ui_scale)))
        help_wrap = tk.Frame(
            help_page, bg=self._BORDER, bd=1, relief="sunken")
        help_wrap.pack(fill="both", expand=True)
        help_scroll = tk.Scrollbar(help_wrap, orient="vertical")
        self.help_text = tk.Text(
            help_wrap, wrap="word", relief="flat", bd=0, bg=WHITE, fg=BLACK,
            font=self._settings_font("default"),
            height=10,
            padx=scaled_px(14, self._ui_scale),
            pady=scaled_px(12, self._ui_scale),
            yscrollcommand=help_scroll.set)
        help_scroll.configure(command=self.help_text.yview)
        help_scroll.pack(side="right", fill="y")
        self.help_text.pack(side="left", fill="both", expand=True)
        self._refresh_help_text()

        self._active_settings_section = 0
        self._show_settings_section(0)

        # Persistent action bar: visually attached to the content, not floating.
        bar = tk.Frame(body, bg=self._CARD,
                       highlightthickness=1, highlightbackground=self._BORDER)
        bar.grid(row=2, column=0, sticky="ew")
        self.error_lbl = tk.Label(
            bar, text="", bg=self._CARD, fg=self._DANGER,
            anchor="w", justify="left", height=2,
            wraplength=scaled_px(320, self._ui_scale),
            font=self._settings_font("small"))
        self.error_lbl.pack(side="left", fill="x", expand=True,
                            padx=scaled_px(24, self._ui_scale))
        save_button = self._button(
            bar, "Save changes", self._save, primary=True, default="active")
        save_button.pack(
            side="right", padx=(scaled_px(8, self._ui_scale),
                                scaled_px(24, self._ui_scale)),
            pady=scaled_px(14, self._ui_scale))
        cancel_button = self._button(bar, "Cancel", self.destroy)
        cancel_button.pack(side="right")
        self._settings_action_bar = bar
        self._settings_action_buttons = (save_button, cancel_button)
        self._settings_error_full = ""
        bar.bind("<Configure>", self._fit_settings_error)
        self.error_lbl.bind("<Button-1>", self._show_settings_error)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Control-s>", lambda _e: self._save())
        for index in range(6):
            self.bind(f"<Control-Key-{index + 1}>",
                      lambda _e, i=index: self._show_settings_section(i))

    def _install_settings_fonts(self):
        """Share RayApp's semantic Tahoma fonts; mirror them in test roots."""
        roles = {
            "default": ("RCMDefaultFont", "Tahoma", 8, "normal"),
            "bold": ("RCMBoldFont", "Tahoma", 8, "bold"),
            "value": ("RCMValueFont", "Tahoma", 9, "bold"),
            "small": ("RCMSmallFont", "Tahoma", 7, "normal"),
            "mono": ("RCMMonoFont", "Consolas", 9, "normal"),
        }
        existing = set(tkfont.names(self))
        self._settings_fonts = {}
        for role, (shared, family, size, weight) in roles.items():
            if shared in existing:
                self._settings_fonts[role] = shared
                continue
            fallback = f"RCMSettings{role.title()}Font"
            try:
                font = tkfont.Font(root=self, name=fallback, exists=True)
            except tk.TclError:
                font = tkfont.Font(root=self, name=fallback)
            font.configure(family=family, size=size, weight=weight)
            self._settings_fonts[role] = fallback

    def _settings_font(self, role):
        return self._settings_fonts.get(
            role, self._settings_fonts["default"])

    def _place_settings_card(
            self, card, row, column, columnspan=1, rowspan=1,
            sticky="nsew"):
        """Place a property-sheet card with balanced classic-dialog gutters."""
        gap = scaled_px(6, self._ui_scale)
        card.grid_configure(
            row=row, column=column, columnspan=columnspan, rowspan=rowspan,
            sticky=sticky,
            padx=(0 if column == 0 else gap,
                  0 if column > 0 else gap),
            pady=(0, scaled_px(7, self._ui_scale)))

    def _fit_settings_error(self, _event=None):
        """Keep validation text inside the fixed action bar at every width."""
        try:
            occupied = sum(
                button.winfo_reqwidth()
                for button in self._settings_action_buttons)
            occupied += scaled_px(96, self._ui_scale)
            available = max(
                scaled_px(120, self._ui_scale),
                self._settings_action_bar.winfo_width() - occupied)
            self.error_lbl.configure(wraplength=available)
            self._render_settings_error(available)
        except (AttributeError, tk.TclError):
            pass

    def _render_settings_error(self, available):
        """Render at most two lines while preserving full text for the dialog."""
        full = getattr(self, "_settings_error_full", "")
        compact = " ".join(full.split())
        if not compact:
            self.error_lbl.configure(text="", cursor="")
            return
        font = tkfont.Font(root=self, font=self._settings_font("small"))
        suffix = " ... (click for details)"
        budget = max(1, int(available) * 2 - font.measure(suffix))
        if font.measure(compact) <= int(available) * 2:
            shown = compact
        else:
            lo, hi = 0, len(compact)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if font.measure(compact[:mid]) <= budget:
                    lo = mid
                else:
                    hi = mid - 1
            shown = compact[:lo].rstrip() + suffix
        self.error_lbl.configure(
            text=shown, cursor=("hand2" if shown != compact else ""))

    def _set_settings_error(self, message):
        """Show a bounded summary; retain unusually long details on click."""
        self._settings_error_full = str(message or "")
        self._fit_settings_error()

    def _show_settings_error(self, _event=None):
        full = getattr(self, "_settings_error_full", "")
        if full and " ".join(full.split()) != self.error_lbl.cget("text"):
            messagebox.showerror("Settings validation", full, parent=self)

    def _sync_settings_page(self, index):
        """Fit the property page width and expose vertical scroll only if needed."""
        if not (0 <= int(index) < len(self._settings_pages)):
            return
        page = self._settings_pages[index]
        canvas = self._settings_canvases[index]
        scrollbar = self._settings_scrollbars[index]
        window_id = self._settings_canvas_windows[index]
        try:
            width = max(1, canvas.winfo_width())
            grid_width = max(
                1, width - 2 * scaled_px(14, self._ui_scale))
            gap = 2 * scaled_px(6, self._ui_scale)
            layout_changed = False
            if index == 0 and hasattr(self, "_general_grid"):
                stack = (
                    self._general_pc_card.winfo_reqwidth()
                    + self._general_behavior_card.winfo_reqwidth()
                    + gap > grid_width)
                if stack != self._general_page_stacked:
                    self._general_page_stacked = stack
                    if stack:
                        self._place_settings_card(
                            self._general_pc_card, 0, 0, 2)
                        self._place_settings_card(
                            self._general_behavior_card, 1, 0, 2)
                        self._place_settings_card(
                            self._general_display_card, 2, 0, 2,
                            sticky="new")
                    else:
                        self._place_settings_card(
                            self._general_pc_card, 0, 0)
                        self._place_settings_card(
                            self._general_behavior_card, 0, 1)
                        self._place_settings_card(
                            self._general_display_card, 1, 0, 2,
                            sticky="new")
                    layout_changed = True
            elif index == 1 and hasattr(self, "_cluster_grid"):
                stack = (
                    self._cluster_connection_card.winfo_reqwidth()
                    + max(
                        self._cluster_runtime_card.winfo_reqwidth(),
                        self._cluster_network_card.winfo_reqwidth())
                    + gap > grid_width)
                if stack != self._cluster_page_stacked:
                    self._cluster_page_stacked = stack
                    if stack:
                        self._place_settings_card(
                            self._cluster_connection_card, 0, 0, 2)
                        self._place_settings_card(
                            self._cluster_runtime_card, 1, 0, 2)
                        self._place_settings_card(
                            self._cluster_network_card, 2, 0, 2,
                            sticky="new")
                        self._place_settings_card(
                            self._cluster_guard_card, 3, 0, 2,
                            sticky="new")
                    else:
                        self._place_settings_card(
                            self._cluster_connection_card, 0, 0, 1, 2)
                        self._place_settings_card(
                            self._cluster_runtime_card, 0, 1)
                        self._place_settings_card(
                            self._cluster_network_card, 1, 1,
                            sticky="new")
                        self._place_settings_card(
                            self._cluster_guard_card, 2, 0, 2,
                            sticky="new")
                    layout_changed = True
            elif index == 2 and hasattr(self, "_monitor_grid"):
                stack = (
                    self._monitor_temperature_card.winfo_reqwidth()
                    + self._monitor_metrics_card.winfo_reqwidth()
                    + gap > grid_width)
                if stack != self._monitor_page_stacked:
                    self._monitor_page_stacked = stack
                    if stack:
                        self._place_settings_card(
                            self._monitor_temperature_card, 0, 0, 2)
                        self._place_settings_card(
                            self._monitor_metrics_card, 1, 0, 2)
                    else:
                        self._place_settings_card(
                            self._monitor_temperature_card, 0, 0)
                        self._place_settings_card(
                            self._monitor_metrics_card, 0, 1)
                    layout_changed = True
            if index == 4 and hasattr(self, "_cleanup_grid"):
                side_required = (
                    self._cleanup_timing_card.winfo_reqwidth()
                    + self._cleanup_safety_card.winfo_reqwidth() + gap)
                stack = side_required > grid_width
                if stack != self._cleanup_page_stacked:
                    self._cleanup_page_stacked = stack
                    if stack:
                        self._cleanup_timing_card.grid_configure(
                            row=0, column=0, columnspan=2)
                        self._cleanup_safety_card.grid_configure(
                            row=1, column=0, columnspan=2)
                    else:
                        self._cleanup_timing_card.grid_configure(
                            row=0, column=0, columnspan=1)
                        self._cleanup_safety_card.grid_configure(
                            row=0, column=1, columnspan=1)
                    layout_changed = True
            if layout_changed:
                self.after_idle(
                    lambda i=index: self._sync_settings_page(i))
                return
            viewport_h = max(1, canvas.winfo_height())
            requested_h = max(1, page.winfo_reqheight())
            tolerance = scaled_px(18, self._ui_scale)
            # Nodes owns inner X/Y table scrollbars and Help owns a Text
            # scrollbar. An outer scrollbar on those pages hid their action
            # rows and produced confusing double-scroll UI.
            owns_inner_scroll = index in (3, 5)
            needs_scroll = (
                not owns_inner_scroll
                and requested_h > viewport_h + tolerance)
            content_h = requested_h if needs_scroll else viewport_h
            canvas.itemconfigure(
                window_id, width=width, height=content_h)
            canvas.configure(scrollregion=(0, 0, width, content_h))
            if needs_scroll:
                if not scrollbar.winfo_ismapped():
                    scrollbar.grid(row=0, column=1, sticky="ns")
            else:
                if scrollbar.winfo_ismapped():
                    scrollbar.grid_remove()
                canvas.yview_moveto(0.0)
        except tk.TclError:
            pass

    def _setup_settings_styles(self):
        style = ttk.Style(self)
        style.configure("Settings.TCombobox",
                        font=self._settings_font("default"),
                        padding=0)

    def _card(self, parent, title, description, row, column, columnspan=1,
              rowspan=1, sticky="nsew"):
        # v1.07.16c [retrofit]: cards are classic groove group boxes exactly
        # like the main window's " Cluster " / " Connected nodes " frames.
        card = tk.LabelFrame(parent, text=f" {title} ", bg=self._CARD,
                             fg=self._TEXT, bd=2, relief="groove",
                             font=self._settings_font("default"),
                             padx=scaled_px(8, self._ui_scale),
                             pady=scaled_px(6, self._ui_scale))
        card.grid(row=row, column=column, columnspan=columnspan, rowspan=rowspan,
                  sticky=sticky,
                  padx=(0 if column == 0 else scaled_px(6, self._ui_scale),
                        0 if column > 0 else scaled_px(6, self._ui_scale)),
                  pady=(0, scaled_px(7, self._ui_scale)))
        tk.Label(card, text=description, bg=self._CARD, fg=self._MUTED,
                 anchor="w", justify="left",
                 font=self._settings_font("small"),
                 wraplength=310).pack(
                     fill="x", pady=(0, scaled_px(5, self._ui_scale)))
        form = tk.Frame(card, bg=self._CARD)
        form.pack(fill="both", expand=True)
        # Keep controls at a readable form width.  Expanding text boxes across
        # the whole window was the main cause of the previous empty-canvas feel.
        form.columnconfigure(1, weight=0)
        return form

    def _button(self, parent, text, command, primary=False, **kwargs):
        # v1.07.16c [retrofit]: classic raised Win98 buttons like the main
        # window's Join/Stop/Settings row; primary action is bold only.
        return tk.Button(
            parent, text=text, command=command, bg=self._CARD, fg=self._TEXT,
            activebackground=self._ACCENT_SOFT, activeforeground=self._TEXT,
            relief="raised", bd=2, highlightthickness=0,
            font=(self._settings_font("bold") if primary
                  else self._settings_font("default")),
            padx=scaled_px(6, self._ui_scale),
            pady=scaled_px(1, self._ui_scale), **kwargs)

    def _checkbutton(self, parent, text, variable):
        return tk.Checkbutton(
            parent, text=text, variable=variable, bg=self._CARD, fg=self._TEXT,
            activebackground=self._CARD, activeforeground=self._TEXT,
            selectcolor=WHITE, highlightthickness=0, anchor="w",
            font=self._settings_font("default"))

    def _show_settings_section(self, index=None):
        if not isinstance(index, int):
            index = getattr(self, "_active_settings_section", 0)
        if 0 <= index < len(self._settings_pages):
            self._active_settings_section = index
            self._settings_page_hosts[index].tkraise()
            self.after_idle(lambda i=index: self._sync_settings_page(i))
            for nav_index, (item, indicator, button) in enumerate(self._nav_buttons):
                selected = nav_index == index
                bg = self._ACCENT_SOFT if selected else self._SIDEBAR
                item.configure(bg=bg)
                indicator.configure(bg=self._ACCENT if selected else self._SIDEBAR)
                button.configure(bg=bg,
                                 fg=self._ACCENT if selected else self._TEXT,
                                 relief=("sunken" if selected else "raised"),
                                 font=(self._settings_font("bold") if selected
                                       else self._settings_font("default")))

    def _nodes_xview_changed(self, first, last):
        try:
            self.nodes_tree_x.set(first, last)
            self._set_node_scrollbar(
                self.nodes_tree_x, float(first), float(last), "x")
        except (AttributeError, tk.TclError, TypeError, ValueError):
            pass

    def _nodes_yview_changed(self, first, last):
        try:
            self.nodes_tree_y.set(first, last)
            self._set_node_scrollbar(
                self.nodes_tree_y, float(first), float(last), "y")
        except (AttributeError, tk.TclError, TypeError, ValueError):
            pass

    @staticmethod
    def _scroll_range_overflows(first, last):
        return float(first) > 0.001 or float(last) < 0.999

    def _set_node_scrollbar(self, scrollbar, first, last, axis):
        needs_scroll = self._scroll_range_overflows(first, last)
        if needs_scroll and not scrollbar.winfo_ismapped():
            if axis == "x":
                scrollbar.grid(row=1, column=0, sticky="ew")
            else:
                scrollbar.grid(row=0, column=1, sticky="ns")
        elif not needs_scroll and scrollbar.winfo_ismapped():
            scrollbar.grid_remove()

    def _refresh_node_scrollbars(self):
        try:
            x_first, x_last = self.nodes_tree.xview()
            y_first, y_last = self.nodes_tree.yview()
            self._set_node_scrollbar(
                self.nodes_tree_x, x_first, x_last, "x")
            self._set_node_scrollbar(
                self.nodes_tree_y, y_first, y_last, "y")
        except (AttributeError, tk.TclError):
            pass

    def _populate_node_tree(self, select_index=None):
        self.nodes_tree.delete(*self.nodes_tree.get_children())
        self._node_item_data.clear()
        selected = None
        for index, rec in enumerate(self._node_records):
            mode = ("controller" if is_controller_node(rec)
                    else "ray")
            iid = self.nodes_tree.insert(
                "", "end",
                values=(rec.get("name", ""), rec.get("ip", ""), mode,
                        ("—" if is_controller_mode(mode)
                         else rec.get("role", "worker")),
                        ("—" if is_controller_mode(mode)
                         else (
                             "0 (driver-only)"
                             if rec.get("num_cpus") == 0
                             else rec.get("num_cpus", ""))),
                        ("—" if is_controller_mode(mode)
                         else rec.get("rdp_user", "")),
                        ("—" if is_controller_mode(mode)
                         else normalized_rdp_port(rec.get("rdp_port"))),
                        self._credential_status(rec, mode)))
            self._node_item_data[iid] = rec
            if index == select_index:
                selected = iid
        if selected:
            self.nodes_tree.selection_set(selected)
            self.nodes_tree.focus(selected)
            self.nodes_tree.see(selected)
        self._sync_node_buttons()
        self.after_idle(self._refresh_node_scrollbars)

    def _credential_status(self, record, mode):
        if is_controller_mode(mode):
            return "—"
        ip = str(record.get("ip") or "").strip()
        if not ip:
            return "None"
        try:
            return "Saved" if rdp_credential_exists(ip) else "None"
        except Exception:
            return "Unknown"

    def _selected_node(self):
        selected = self.nodes_tree.selection()
        if not selected:
            return None
        return self._node_item_data.get(selected[0])

    def _show_node_context_menu(self, event):
        iid = self.nodes_tree.identify_row(event.y)
        if not iid:
            return
        self.nodes_tree.selection_set(iid)
        self.nodes_tree.focus(iid)
        record = self._node_item_data.get(iid)
        if not record or is_controller_node(record):
            return
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(
            label="Make this the head",
            state=("disabled" if record.get("role") == "head" else "normal"),
            command=lambda: self._request_make_head(record))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _request_make_head(self, record):
        callback = self._make_head_callback
        if callable(callback):
            callback(json.loads(json.dumps(record)), self)

    def _sync_node_buttons(self):
        selected = self._selected_node()
        edit_state = "normal" if selected is not None else "disabled"
        is_target = bool(selected and rdp_password_targets([selected]))
        credential_state = "normal" if is_target else "disabled"
        for button in (self.btn_node_edit, self.btn_node_delete):
            button.configure(state=edit_state)
        for button in (self.btn_password, self.btn_credential_delete):
            button.configure(state=credential_state)
        self.btn_batch_password.configure(
            state=("normal" if len(rdp_password_targets(self._node_records)) >= 2
                   else "disabled"))

    def _node_editor(self, record=None):
        """Edit only visible node fields while retaining all hidden keys."""
        original = record or {}
        win = tk.Toplevel(self)
        editor_title = "Edit node" if record is not None else "Add node"
        win.title(editor_title)
        win.configure(bg=self._SURFACE)
        win.transient(self)
        win.grab_set()
        win.resizable(False, False)
        shell = tk.Frame(win, bg=self._SURFACE,
                         padx=scaled_px(22, self._ui_scale),
                         pady=scaled_px(20, self._ui_scale))
        shell.pack(fill="both", expand=True)
        tk.Label(shell, text=editor_title, bg=self._SURFACE, fg=self._TEXT,
                 anchor="w", font=("Segoe UI", 11, "bold")).pack(fill="x")
        tk.Label(shell, text="Configure how this machine appears and connects.",
                 bg=self._SURFACE, fg=self._MUTED, anchor="w",
                 font=("Segoe UI", 9)).pack(
                     fill="x", pady=(scaled_px(3, self._ui_scale),
                                     scaled_px(14, self._ui_scale)))
        card_edge = tk.LabelFrame(shell, text=" Node ", bg=self._CARD,
                                  fg=self._TEXT, bd=2, relief="groove")
        card_edge.pack(fill="x")
        form = tk.Frame(card_edge, bg=self._CARD,
                        padx=scaled_px(12, self._ui_scale),
                        pady=scaled_px(10, self._ui_scale))
        form.pack(fill="both", expand=True)
        form.columnconfigure(1, weight=1)

        def entry(label, value, row):
            tk.Label(form, text=label, bg=self._CARD, fg=self._TEXT, anchor="w",
                     font=("Segoe UI", 9)).grid(
                row=row, column=0, sticky="w", pady=scaled_px(5, self._ui_scale))
            widget = tk.Entry(
                form, width=30, bg=WHITE, fg=self._TEXT, relief="sunken", bd=1,
                highlightthickness=0, font=("Segoe UI", 9))
            widget.insert(0, value or "")
            widget.grid(row=row, column=1, sticky="ew",
                        padx=(scaled_px(10, self._ui_scale), 0),
                        pady=scaled_px(5, self._ui_scale),
                        ipady=scaled_px(4, self._ui_scale))
            return widget

        e_name = entry("Name:", original.get("name", ""), 0)
        e_ip = entry("Tailscale IP:", original.get("ip", ""), 1)
        original_mode = ("controller" if is_controller_node(original)
                         else "ray")
        mode = tk.StringVar(value=(original_mode
                                   if original_mode in ("ray", "controller")
                                   else "ray"))
        role = tk.StringVar(value=(original.get("role", "worker")
                                   if original.get("role", "worker") in ("head", "worker")
                                   else "worker"))
        role_menu = None
        for row, label, variable, values in (
                (2, "Mode:", mode, ("ray", "controller")),
                (3, "Ray role:", role, ("head", "worker"))):
            tk.Label(form, text=label, bg=self._CARD, fg=self._TEXT, anchor="w",
                     font=("Segoe UI", 9)).grid(
                row=row, column=0, sticky="w", pady=scaled_px(5, self._ui_scale))
            menu = ttk.Combobox(form, textvariable=variable, values=values,
                                state="readonly", width=28,
                                style="Settings.TCombobox")
            menu.grid(row=row, column=1, sticky="ew",
                      padx=(scaled_px(10, self._ui_scale), 0),
                      pady=scaled_px(5, self._ui_scale))
            if variable is role:
                role_menu = menu
        e_cpus = entry("Ray CPUs:", original.get("num_cpus", ""), 4)
        e_rdp = entry("RDP account:", original.get("rdp_user", ""), 5)
        e_rdp_port = entry("RDP port:", original.get("rdp_port", 3389), 6)
        tk.Label(form, text="Example: NODE\\USER  ·  RDP port defaults to 3389",
                 bg=self._CARD, fg=self._MUTED, font=("Segoe UI", 8)).grid(
                     row=7, column=0, columnspan=2, sticky="w",
                     pady=(scaled_px(4, self._ui_scale), 0))
        result = {"value": None}

        def sync_mode_fields(*_args):
            controller = mode.get() == "controller"
            if controller:
                role.set("worker")  # retained only for schema compatibility
                e_rdp.delete(0, "end")
            if role_menu is not None:
                role_menu.configure(state=("disabled" if controller else "readonly"))
            e_cpus.configure(state=("disabled" if controller else "normal"))
            e_rdp.configure(state=("disabled" if controller else "normal"))
            e_rdp_port.configure(state=("disabled" if controller else "normal"))

        mode.trace_add("write", sync_mode_fields)
        sync_mode_fields()

        def accept():
            ip = e_ip.get().strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                messagebox.showerror("Node", "Enter a valid IP address.", parent=win)
                return
            controller = mode.get() == "controller"
            try:
                cpus = 0 if controller else int(e_cpus.get().strip())
                if not controller and not 0 <= cpus <= 4096:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Node",
                    "Ray CPUs must be 0 to 4096 (0 = driver-only).",
                    parent=win)
                return
            try:
                rdp_port = 3389 if controller else int(e_rdp_port.get().strip())
                if not controller and not 1 <= rdp_port <= 65535:
                    raise ValueError
            except ValueError:
                messagebox.showerror(
                    "Node", "RDP port must be an integer from 1 to 65535.", parent=win)
                return
            updated = dict(original)
            updated.update({
                "name": e_name.get().strip() or ip,
                "ip": ip,
                "mode": mode.get(),
                "role": role.get(),
                "num_cpus": cpus,
                "rdp_user": ("" if mode.get() == "controller"
                             else e_rdp.get().strip()),
                "rdp_port": rdp_port,
            })
            result["value"] = updated
            win.destroy()

        actions = tk.Frame(shell, bg=self._SURFACE)
        actions.pack(fill="x", pady=(scaled_px(14, self._ui_scale), 0))
        self._button(actions, "Save node", accept, primary=True).pack(side="right")
        self._button(actions, "Cancel", win.destroy).pack(
            side="right", padx=(0, scaled_px(8, self._ui_scale)))
        win.bind("<Escape>", lambda _e: win.destroy())
        win.bind("<Return>", lambda _e: accept())
        e_name.focus_set()
        self.wait_window(win)
        return result["value"]

    def _add_node_dialog(self):
        record = self._node_editor()
        if record is None:
            return
        self._node_records.append(record)
        self._populate_node_tree(len(self._node_records) - 1)

    def _edit_selected_node(self):
        record = self._selected_node()
        if record is None:
            return
        index = self._node_records.index(record)
        updated = self._node_editor(record)
        if updated is not None:
            self._node_records[index] = updated
            self._populate_node_tree(index)

    def _delete_selected_node(self):
        record = self._selected_node()
        if record is None:
            return
        if not messagebox.askyesno(
                "Delete node", f"Delete {record.get('name') or record.get('ip')}?",
                parent=self):
            return
        index = self._node_records.index(record)
        self._node_records.remove(record)
        self._populate_node_tree(min(index, len(self._node_records) - 1))

    def _password_action(self, action):
        if action == "batch":
            targets = rdp_password_targets(self._node_records)
            callback = getattr(self, "_password_action_callback", None)
            if callable(callback):
                callback(action, targets, self)
            return
        record = self._selected_node()
        if record is None:
            return
        callback = getattr(self, "_password_action_callback", None)
        if callable(callback):
            callback(action, json.loads(json.dumps(record)), self)
            return
        messagebox.showinfo(
            "RDP credentials",
            "The password management module is not connected.\n"
            "You can still save node and RDP account settings.",
            parent=self)

    def _new_pc_guide_text(self) -> str:
        """Compatibility entry point; the complete guide now lives on Help."""
        return self._settings_help_text("English")

    def _show_new_pc_guide(self):
        self._show_settings_section(5)
        try:
            self.help_text.yview_moveto(0.0)
            self.cmb_help_language.focus_set()
        except Exception:
            pass

    @staticmethod
    def _help_font(language: str) -> str:
        return {
            "한국어": "Malgun Gothic",
            "日本語": "Yu Gothic UI",
            "中文": "Microsoft YaHei UI",
        }.get(language, "Segoe UI")

    def _refresh_help_text(self):
        language = self.var_help_language.get() or "English"
        content = self._settings_help_text(language)
        self.help_text.configure(
            state="normal", font=(self._help_font(language), 9))
        self.help_text.delete("1.0", "end")
        self.help_text.insert("1.0", content)
        self.help_text.configure(state="disabled")
        self.help_text.yview_moveto(0.0)

    def _copy_help_text(self):
        language = self.var_help_language.get() or "English"
        self.clipboard_clear()
        self.clipboard_append(self._settings_help_text(language))

    def _settings_help_text(self, language: str = "English") -> str:
        cfg = getattr(self, "cfg", None) or {}
        head_ip = str(cfg.get("head_ip") or "<head Tailscale IP>")
        head_port = int(cfg.get("head_port") or 6379)
        dash_port = int(cfg.get("dashboard_port") or 8265)
        rcm_port = int(cfg.get("temp_port") or 8866)
        documents = {
            "English": f"""
                RAY CLUSTER MANAGER HELP
                ========================

                Current connection
                Head: {head_ip}  |  GCS: {head_port}  |  Dashboard: {dash_port}  |  Local RCM: 127.0.0.1:{rcm_port}

                1. Quick start
                - Connect every PC to the same trusted Tailscale tailnet.
                - Run RCM as administrator on Ray PCs so firewall, process cleanup, and sensors work.
                - A cluster has one head and any number of workers. A controller manages other PCs but does not join Ray.
                - Start the head first. Use Join on workers. Confirm ALIVE nodes and CPU totals in the main window.

                2. Main window controls
                - Start / Join: start this PC in its configured Ray role.
                - Stop: stop Ray on this PC only.
                - Restart: restart this PC's Ray runtime.
                - Reset: remove stale local Ray state, then leave the PC ready to Start or Join.
                - Repair: diagnose and repair Ray on this PC only.
                - Dashboard: open the configured Ray Dashboard.
                - RDP: probe the selected PC's RDP port, then open Windows Remote Desktop.
                - Logs: open current RCM, Ray, Trouble, and diagnostic logs.
                - Fit Screen: refit text and window geometry to the current monitor or RDP session.
                - Update Fleet: unavailable (legacy_remote_retired).

                3. Update Fleet
                - Legacy remote update is retired: legacy_remote_retired.
                - RCM does not expose a remote update, password, repair, or cluster-config route.

                4. Head, worker, and driver
                - The head runs the Ray control plane, Dashboard, and metadata services, so it may use more RAM than a worker.
                - A driver is the Python program that submits work. It does not have to run on the head.
                - A joined worker can submit jobs with ray.init(address="auto").
                - Commands that hard-code an old head, localhost, Dashboard URL, Ray Client URL, or GCS address must use the configured head above.
                - Make this the head is unavailable (legacy_remote_retired).

                5. Settings
                - General: this PC's role, Tailscale IP, Ray CPUs, startup, shutdown, and display scaling.
                - Cluster: head address, Ray executable, firewall check, and head Dashboard recovery.
                - Monitoring: temperature, CPU, RAM, disk, polling, and alert thresholds.
                - Nodes & RDP: names, addresses, roles, CPU counts, RDP accounts, ports, and saved-credential status.
                - CPU value auto uses detected logical CPUs. CPU 0 creates a driver-only worker. A head cannot use 0.

                6. Add a PC
                - Install the same Python patch version and Ray version used by the cluster.
                - Join the same tailnet and record the PC's 100.x Tailscale IPv4 address.
                - Add the node under Settings > Nodes & RDP and choose worker, CPU count, local Windows RDP account, and RDP port.
                - Run Check firewall for Ray only. Local RCM uses 127.0.0.1:{rcm_port}.
                - Press Join and confirm the node appears as ALIVE. A * suffix means Ray discovered a PC that is not registered in this local inventory.
                - RDP is independent of Ray. The target Windows edition, Remote Desktop service, firewall, account permission, and port must also be ready.

                7. RDP and credentials
                - Configure an explicit local account such as HOST\\user. Windows Hello PIN is not an RDP password.
                - A saved TERMSRV credential is reused only when its username matches the configured RDP account.
                - Microsoft-account password changes and Windows Hello PIN changes are not supported.
                - Current passwords are used for one request and are never stored in settings or logs.
                - A new password is stored in Windows Credential Manager only when you select that option after a successful change.
                - Remote password change is unavailable (legacy_remote_retired); local password change remains.

                8. Monitoring and recovery
                - GCS open plus Dashboard closed is a partial head failure, not a network outage.
                - Head Dashboard recovery waits for repeated failures, serializes recovery, and backs off after errors.
                - Worker watchdog checks the Ray wrapper and Dashboard ALIVE membership before rejoining.
                - Offline history may remain as DEAD in Ray. Use the node state, not the raw row count.
                - Use Copy Diag and Trouble logs before Reset when a failure repeats.

                9. Safety
                - RCM {rcm_port} is loopback-only. Limit Ray ports to the trusted tailnet.
                - Do not count offline nodes as updated or ALIVE.
                - Do not run ray start --head on a worker.
                - Before changing the head, finish or intentionally stop important Ray jobs.

                10. Process Cleanup
                - Cleanup scans this PC only. Keep the Recommended timing defaults unless diagnosing a special case.
                - Review candidates manually. RCM revalidates the exact process identity before ending it; ignored identities stay excluded.
            """,
            "한국어": f"""
                RAY CLUSTER MANAGER 도움말
                ==========================

                현재 연결
                HEAD: {head_ip}  |  GCS: {head_port}  |  Dashboard: {dash_port}  |  Local RCM: 127.0.0.1:{rcm_port}

                1. 빠른 시작
                - 모든 PC를 신뢰하는 동일 Tailscale tailnet에 연결합니다.
                - Ray PC에서는 방화벽·프로세스 정리·센서가 작동하도록 RCM을 관리자 권한으로 실행합니다.
                - 클러스터에는 HEAD 한 대와 여러 Worker가 있습니다. Controller는 다른 PC를 관리하지만 Ray에는 참가하지 않습니다.
                - HEAD를 먼저 시작하고 Worker에서 Join을 누른 뒤 메인 화면의 ALIVE 수와 CPU 합계를 확인합니다.

                2. 메인 화면 버튼
                - Start / Join: 이 PC를 설정된 Ray 역할로 시작합니다.
                - Stop: 이 PC의 Ray만 중지합니다.
                - Restart: 이 PC의 Ray runtime을 재시작합니다.
                - Reset: 이 PC의 오래된 Ray 상태를 정리하고 Start/Join 가능한 상태로 둡니다.
                - Repair: HEAD와 도달 가능한 Worker를 진단하고 확인된 장애만 복구합니다.
                - Dashboard: 설정된 Ray Dashboard를 엽니다.
                - RDP: 선택한 PC의 RDP 포트를 확인한 뒤 Windows 원격 데스크톱을 엽니다.
                - Logs: 현재 RCM·Ray·Trouble·진단 로그를 엽니다.
                - Fit Screen: 현재 모니터나 RDP 화면에 맞춰 글꼴과 창 크기를 다시 맞춥니다.
                - Update Fleet: 사용할 수 없습니다 (legacy_remote_retired).

                3. Update Fleet
                - 기존 원격 업데이트는 폐기되었습니다: legacy_remote_retired.
                - RCM은 원격 update·password·repair·cluster-config route를 제공하지 않습니다.

                4. HEAD, Worker, Driver
                - HEAD는 Ray control plane, Dashboard, metadata 서비스를 실행하므로 Worker보다 RAM을 더 쓸 수 있습니다.
                - Driver는 작업을 제출하는 Python 프로그램이며 HEAD에서 실행할 필요가 없습니다.
                - 클러스터에 합류한 Worker도 ray.init(address="auto")로 작업을 제출할 수 있습니다.
                - 옛 HEAD, localhost, Dashboard URL, Ray Client URL, GCS 주소를 직접 적은 명령은 위의 현재 HEAD로 바꿉니다.
                - Make this the head는 사용할 수 없습니다 (legacy_remote_retired).

                5. Settings
                - General: 이 PC 역할, Tailscale IP, Ray CPU, 시작·종료, 화면 배율.
                - Cluster: HEAD 주소, ray.exe, 방화벽 점검, HEAD Dashboard 자동 복구.
                - Monitoring: 온도, CPU, RAM, 디스크, polling, 경고 임계값.
                - Nodes & RDP: 이름, 주소, 역할, CPU 수, RDP 계정·포트, 저장 자격 상태.
                - CPU auto는 감지된 논리 CPU를 사용합니다. CPU 0은 driver-only Worker이며 HEAD에는 0을 사용할 수 없습니다.

                6. 새 PC 추가
                - 클러스터와 동일한 Python patch 버전과 Ray 버전을 설치합니다.
                - 같은 tailnet에 연결하고 PC의 100.x Tailscale IPv4 주소를 확인합니다.
                - Settings > Nodes & RDP에서 노드를 추가하고 worker, CPU 수, 로컬 Windows RDP 계정, RDP 포트를 입력합니다.
                - Ray 전용 Check firewall을 실행합니다. 로컬 RCM은 127.0.0.1:{rcm_port}를 사용합니다.
                - Join을 누르고 ALIVE로 표시되는지 확인합니다. * 표시는 Ray가 발견했지만 이 PC의 로컬 목록에는 등록되지 않은 노드입니다.
                - RDP는 Ray와 별개입니다. 대상 Windows 에디션, Remote Desktop 서비스, 방화벽, 계정 권한, 포트도 준비되어야 합니다.

                7. RDP와 자격 증명
                - HOST\\user 같은 명시적인 로컬 계정을 설정합니다. Windows Hello PIN은 RDP 비밀번호가 아닙니다.
                - 저장된 TERMSRV 자격 증명의 사용자명이 설정된 RDP 계정과 일치할 때만 재사용합니다.
                - Microsoft 계정 비밀번호와 Windows Hello PIN 변경은 지원하지 않습니다.
                - 현재 비밀번호는 한 요청에만 사용하며 Settings나 로그에 저장하지 않습니다.
                - 새 비밀번호는 변경 성공 후 저장 옵션을 선택했을 때만 Windows 자격 증명 관리자에 저장합니다.
                - 원격 비밀번호 변경은 사용할 수 없고(legacy_remote_retired), 로컬 변경만 유지됩니다.

                8. 모니터링과 복구
                - GCS는 열렸지만 Dashboard가 닫힌 상태는 네트워크 장애가 아니라 HEAD 부분 장애입니다.
                - HEAD Dashboard 복구는 반복 실패를 확인하고 작업을 직렬화하며 실패 시 backoff합니다.
                - Worker watchdog은 Ray wrapper와 Dashboard ALIVE 등록을 확인한 뒤 재합류합니다.
                - 종료된 노드는 Ray에 DEAD 이력으로 남을 수 있습니다. 단순 행 수가 아니라 state를 확인합니다.
                - 장애가 반복되면 Reset 전에 Copy Diag와 Trouble 로그를 확인합니다.

                9. 안전 수칙
                - RCM {rcm_port}는 loopback 전용입니다. Ray 포트만 신뢰하는 tailnet으로 제한합니다.
                - offline 노드를 업데이트 완료나 ALIVE로 세지 않습니다.
                - Worker에서 ray start --head를 실행하지 않습니다.
                - HEAD 변경 전 중요한 Ray job을 완료하거나 의도적으로 중지합니다.

                10. 프로세스 정리
                - Cleanup은 이 PC만 검사합니다. 특별한 진단이 아니라면 권장 시간 기본값을 유지합니다.
                - 후보를 직접 검토합니다. 종료 직전 RCM이 정확한 프로세스 신원을 다시 확인하며 무시한 신원은 계속 제외됩니다.
            """,
            "日本語": f"""
                RAY CLUSTER MANAGER ヘルプ
                =========================

                現在の接続
                HEAD: {head_ip}  |  GCS: {head_port}  |  Dashboard: {dash_port}  |  Local RCM: 127.0.0.1:{rcm_port}

                1. クイックスタート
                - すべてのPCを、信頼できる同じTailscale tailnetに接続します。
                - Ray PCでは、ファイアウォール、プロセス整理、センサーを利用できるようRCMを管理者として実行します。
                - クラスターには1台のHeadと複数のWorkerがあります。Controllerは他のPCを管理しますがRayには参加しません。
                - Headを先に起動し、WorkerでJoinを押して、メイン画面のALIVE数とCPU合計を確認します。

                2. メイン画面
                - Start / Join: このPCを設定されたRayロールで起動します。
                - Stop: このPC上のRayだけを停止します。
                - Restart: このPCのRay runtimeを再起動します。
                - Reset: 古いローカルRay状態を削除し、StartまたはJoin可能な状態にします。
                - Repair: Headと到達可能なWorkerを診断し、確認された障害だけを修復します。
                - Dashboard: 設定済みのRay Dashboardを開きます。
                - RDP: 選択したPCのRDPポートを確認してWindows Remote Desktopを開きます。
                - Logs: 現在のRCM、Ray、Trouble、診断ログを開きます。
                - Fit Screen: 現在のモニターまたはRDPセッションに文字とウィンドウを合わせます。
                - Update Fleet: 利用できません (legacy_remote_retired)。

                3. Update Fleet
                - Legacy remote updateは廃止されました: legacy_remote_retired。
                - RCMはremote update・password・repair・cluster-config routeを公開しません。

                4. Head、Worker、Driver
                - HeadはRay control plane、Dashboard、metadata serviceを動かすため、WorkerよりRAMを多く使うことがあります。
                - Driverは処理を投入するPythonプログラムで、Head上で動かす必要はありません。
                - クラスターに参加したWorkerでもray.init(address="auto")でjobを投入できます。
                - 古いHead、localhost、Dashboard URL、Ray Client URL、GCS addressを固定したコマンドは上記のHeadに変更します。
                - Make this the headは利用できません (legacy_remote_retired)。

                5. Settings
                - General: このPCのロール、Tailscale IP、Ray CPU、起動・終了、表示倍率。
                - Cluster: Head address、ray.exe、firewall check、Head Dashboard recovery。
                - Monitoring: 温度、CPU、RAM、disk、polling、警告しきい値。
                - Nodes & RDP: 名前、address、role、CPU数、RDP account・port、保存credential。
                - CPU autoは検出したlogical CPUを使います。CPU 0はdriver-only Workerで、Headには設定できません。

                6. PCを追加
                - クラスターと同じPython patch versionとRay versionをインストールします。
                - 同じtailnetへ接続し、100.xのTailscale IPv4 addressを確認します。
                - Settings > Nodes & RDPでnodeを追加し、worker、CPU数、local Windows RDP account、RDP portを設定します。
                - Ray専用のCheck firewallを実行します。Local RCMは127.0.0.1:{rcm_port}を使います。
                - Joinを押してALIVE表示を確認します。* はRayが検出したものの、このPCのlocal inventoryには未登録であることを示します。
                - RDPはRayとは独立しています。対象Windows edition、Remote Desktop service、firewall、account permission、portも必要です。

                7. RDPとcredential
                - HOST\\userのような明示的なlocal accountを設定します。Windows Hello PINはRDP passwordではありません。
                - 保存済みTERMSRV credentialは、usernameが設定済みRDP accountと一致する場合だけ再利用します。
                - Microsoft account passwordとWindows Hello PINの変更は対応していません。
                - Current passwordは1回のrequestだけで使い、Settingsやlogには保存しません。
                - New passwordは変更成功後に保存を選んだ場合だけWindows Credential Managerへ保存します。
                - Remote password変更は利用できず(legacy_remote_retired)、local変更だけを維持します。

                8. Monitoringとrecovery
                - GCSがopenでDashboardがclosedなら、network outageではなくHeadの部分障害です。
                - Head Dashboard recoveryは連続失敗を確認し、処理を直列化し、失敗後はbackoffします。
                - Worker watchdogはRay wrapperとDashboardのALIVE登録を確認してから再参加します。
                - 停止したnodeがRayにDEAD履歴として残ることがあります。行数ではなくstateを確認してください。
                - 障害が繰り返す場合はReset前にCopy DiagとTrouble logを確認します。

                9. 安全
                - RCM {rcm_port}はloopback専用です。Ray portだけを信頼できるtailnetに制限します。
                - Offline nodeを更新済みまたはALIVEとして数えません。
                - Workerでray start --headを実行しません。
                - Head変更前に重要なRay jobを完了または意図的に停止します。

                10. Process Cleanup
                - CleanupはこのPCだけをscanします。特別な診断でなければ推奨の時間設定を維持します。
                - 候補は手動で確認します。終了直前にRCMが正確なprocess identityを再確認し、無視したidentityは除外を維持します。
            """,
            "Español": f"""
                AYUDA DE RAY CLUSTER MANAGER
                ============================

                Conexión actual
                HEAD: {head_ip}  |  GCS: {head_port}  |  Dashboard: {dash_port}  |  Local RCM: 127.0.0.1:{rcm_port}

                1. Inicio rápido
                - Conecte todos los equipos a la misma red privada y confiable de Tailscale.
                - En los equipos Ray, ejecute RCM como administrador para habilitar firewall, limpieza de procesos y sensores.
                - Un clúster tiene un Head y varios Workers. Un Controller administra otros equipos, pero no participa en Ray.
                - Inicie primero el Head. Pulse Join en los Workers y compruebe los nodos ALIVE y el total de CPU.

                2. Controles principales
                - Start / Join: inicia este equipo con el rol Ray configurado.
                - Stop: detiene Ray solo en este equipo.
                - Restart: reinicia el runtime Ray de este equipo.
                - Reset: elimina el estado Ray local obsoleto y deja el equipo listo para Start o Join.
                - Repair: diagnostica el Head y los Workers accesibles y repara solo fallos confirmados.
                - Dashboard: abre el Ray Dashboard configurado.
                - RDP: comprueba el puerto RDP del equipo seleccionado y abre Windows Remote Desktop.
                - Logs: abre los registros actuales de RCM, Ray, Trouble y diagnóstico.
                - Fit Screen: ajusta texto y ventana al monitor o sesión RDP actual.
                - Update Fleet: no disponible (legacy_remote_retired).

                3. Update Fleet
                - La actualización remota heredada está retirada: legacy_remote_retired.
                - RCM no expone rutas remotas de update, password, repair o cluster-config.

                4. Head, Worker y Driver
                - El Head ejecuta el control plane, Dashboard y servicios de metadata de Ray, por lo que puede usar más RAM que un Worker.
                - Un Driver es el programa Python que envía trabajo y no necesita ejecutarse en el Head.
                - Un Worker unido al clúster puede enviar jobs con ray.init(address="auto").
                - Los comandos con el Head antiguo, localhost, Dashboard URL, Ray Client URL o GCS fijados deben usar el Head configurado arriba.
                - Make this the head no está disponible (legacy_remote_retired).

                5. Settings
                - General: rol de este equipo, Tailscale IP, Ray CPU, inicio, cierre y escala de pantalla.
                - Cluster: dirección del Head, ray.exe, comprobación de firewall y recuperación del Dashboard.
                - Monitoring: temperatura, CPU, RAM, disco, polling y umbrales de alerta.
                - Nodes & RDP: nombres, direcciones, roles, CPU, cuentas y puertos RDP, y credenciales guardadas.
                - CPU auto usa las CPU lógicas detectadas. CPU 0 crea un Worker solo para Driver; un Head no puede usar 0.

                6. Añadir un equipo
                - Instale la misma versión patch de Python y la misma versión de Ray que usa el clúster.
                - Únase al mismo tailnet y anote la dirección IPv4 100.x de Tailscale.
                - En Settings > Nodes & RDP, añada el nodo y configure worker, CPU, cuenta local de Windows para RDP y puerto RDP.
                - Ejecute Check firewall solo para Ray. RCM local usa 127.0.0.1:{rcm_port}.
                - Pulse Join y confirme que aparece como ALIVE. El sufijo * indica que Ray detectó un equipo no registrado en este inventario local.
                - RDP es independiente de Ray. También deben estar preparados Windows edition, Remote Desktop service, firewall, permisos de cuenta y puerto.

                7. RDP y credenciales
                - Configure una cuenta local explícita como HOST\\usuario. El PIN de Windows Hello no es una contraseña RDP.
                - Una credencial TERMSRV guardada solo se reutiliza si su username coincide con la cuenta RDP configurada.
                - No se admiten cambios de contraseña de Microsoft account ni de PIN de Windows Hello.
                - La contraseña actual se usa para una petición y nunca se guarda en Settings ni en logs.
                - La contraseña nueva solo se guarda en Windows Credential Manager si el cambio tuvo éxito y usted elige guardarla.
                - El cambio remoto está retirado (legacy_remote_retired); se mantiene solo el cambio local.

                8. Monitoring y recuperación
                - GCS abierto con Dashboard cerrado es un fallo parcial del Head, no una caída de red.
                - La recuperación del Dashboard espera fallos repetidos, serializa la operación y aplica backoff tras errores.
                - El watchdog del Worker comprueba el wrapper Ray y la pertenencia ALIVE antes de volver a unirlo.
                - Ray puede conservar un nodo detenido como historial DEAD. Revise state, no el número bruto de filas.
                - Si el fallo se repite, revise Copy Diag y Trouble antes de usar Reset.

                9. Seguridad
                - RCM {rcm_port} usa solo loopback. Limite los puertos Ray al tailnet confiable.
                - No cuente nodos offline como actualizados ni ALIVE.
                - No ejecute ray start --head en un Worker.
                - Antes de cambiar el Head, termine o detenga de forma intencionada los jobs importantes.

                10. Limpieza de procesos
                - Cleanup analiza solo este PC. Mantenga los tiempos recomendados salvo que investigue un caso especial.
                - Revise los candidatos manualmente. RCM vuelve a validar la identidad exacta antes de finalizar; las identidades ignoradas siguen excluidas.
            """,
            "中文": f"""
                RAY CLUSTER MANAGER 帮助
                =======================

                当前连接
                HEAD: {head_ip}  |  GCS: {head_port}  |  Dashboard: {dash_port}  |  Local RCM: 127.0.0.1:{rcm_port}

                1. 快速开始
                - 将所有电脑连接到同一个可信的 Tailscale tailnet。
                - 在 Ray 电脑上以管理员身份运行 RCM，以便使用防火墙配置、进程清理和传感器。
                - 一个集群只有一个 Head，可以有多个 Worker。Controller 可以管理其他电脑，但不加入 Ray。
                - 先启动 Head，再在 Worker 上点击 Join，然后确认主窗口中的 ALIVE 节点数和 CPU 总数。

                2. 主窗口控制
                - Start / Join：按已配置的 Ray 角色启动本机。
                - Stop：只停止本机的 Ray。
                - Restart：重新启动本机的 Ray runtime。
                - Reset：清除本机过期的 Ray 状态，使其可以再次 Start 或 Join。
                - Repair：诊断 Head 和可访问的 Worker，只修复已确认的故障。
                - Dashboard：打开已配置的 Ray Dashboard。
                - RDP：检查所选电脑的 RDP 端口，然后打开 Windows Remote Desktop。
                - Logs：打开当前的 RCM、Ray、Trouble 和诊断日志。
                - Fit Screen：根据当前显示器或 RDP 会话重新调整文字和窗口大小。
                - Update Fleet：不可用（legacy_remote_retired）。

                3. Update Fleet
                - 旧版远程更新已停用：legacy_remote_retired。
                - RCM 不公开远程 update、password、repair 或 cluster-config 路由。

                4. Head、Worker 与 Driver
                - Head 运行 Ray control plane、Dashboard 和 metadata service，因此可能比 Worker 使用更多 RAM。
                - Driver 是提交任务的 Python 程序，不必运行在 Head 上。
                - 已加入集群的 Worker 也可以通过 ray.init(address="auto") 提交 job。
                - 如果命令固定写入了旧 Head、localhost、Dashboard URL、Ray Client URL 或 GCS 地址，请改为上面显示的当前 Head。
                - Make this the head 不可用（legacy_remote_retired）。

                5. Settings
                - General：本机角色、Tailscale IP、Ray CPU、启动、退出和显示缩放。
                - Cluster：Head 地址、ray.exe、防火墙检查和 Head Dashboard 自动恢复。
                - Monitoring：温度、CPU、RAM、磁盘、polling 和告警阈值。
                - Nodes & RDP：名称、地址、角色、CPU 数、RDP 账户和端口、已保存凭据状态。
                - CPU auto 使用检测到的逻辑 CPU。CPU 0 表示仅用于 Driver 的 Worker，Head 不能使用 0。

                6. 添加电脑
                - 安装与集群相同的 Python patch 版本和 Ray 版本。
                - 加入同一个 tailnet，并记录该电脑的 100.x Tailscale IPv4 地址。
                - 在 Settings > Nodes & RDP 中添加节点，设置 worker、CPU 数、本地 Windows RDP 账户和 RDP 端口。
                - 仅对 Ray 运行 Check firewall。本机 RCM 使用 127.0.0.1:{rcm_port}。
                - 点击 Join 并确认节点显示为 ALIVE。* 表示 Ray 已发现该电脑，但它尚未注册到本机的 local inventory。
                - RDP 与 Ray 相互独立。目标 Windows edition、Remote Desktop service、防火墙、账户权限和端口也必须准备好。

                7. RDP 与凭据
                - 配置明确的本地账户，例如 HOST\\user。Windows Hello PIN 不是 RDP 密码。
                - 只有已保存 TERMSRV 凭据的 username 与配置的 RDP 账户一致时，才会复用该凭据。
                - 不支持修改 Microsoft account 密码或 Windows Hello PIN。
                - 当前密码只用于一次请求，绝不会保存到 Settings 或日志中。
                - 只有密码修改成功且您选择保存时，新密码才会写入 Windows Credential Manager。
                - 远程密码修改已停用（legacy_remote_retired），仅保留本机修改。

                8. 监控与恢复
                - GCS 开放但 Dashboard 关闭表示 Head 部分故障，不是网络中断。
                - Head Dashboard 恢复会等待连续失败，串行执行恢复，并在错误后 backoff。
                - Worker watchdog 会检查 Ray wrapper 和 Dashboard 中的 ALIVE 状态后再重新加入。
                - 已停止的节点可能作为 DEAD 历史保留在 Ray 中。请检查 state，不要只看行数。
                - 如果故障反复出现，请在 Reset 前查看 Copy Diag 和 Trouble 日志。

                9. 安全
                - RCM {rcm_port} 仅监听 loopback；只向可信 tailnet 开放 Ray 端口。
                - 不要把 offline 节点计为已更新或 ALIVE。
                - 不要在 Worker 上运行 ray start --head。
                - 更换 Head 前，请先完成或有意停止重要的 Ray job。

                10. 进程清理
                - Cleanup 只扫描本机。除非进行特殊诊断，否则请保留建议的时间默认值。
                - 请手动检查候选项。终止前 RCM 会重新验证准确的进程身份；已忽略的身份会继续排除。
            """,
        }
        selected = language if language in documents else "English"
        return textwrap.dedent(documents[selected]).strip() + "\n"

    def _field(self, parent, label, value, row):
        tk.Label(parent, text=label, bg=self._CARD, fg=self._TEXT, anchor="w",
                 font=self._settings_font("default")).grid(
            row=row, column=0, sticky="w",
            pady=scaled_px(3, self._ui_scale))
        e = tk.Entry(parent, width=22, relief="sunken", bd=1, bg=WHITE,
                     fg=self._TEXT, insertbackground=self._TEXT,
                     highlightthickness=0,
                     font=self._settings_font("default"))
        e.insert(0, str(value))
        e.grid(row=row, column=1, sticky="ew",
               ipady=scaled_px(2, self._ui_scale),
               pady=scaled_px(3, self._ui_scale),
               padx=(scaled_px(7, self._ui_scale), 0))
        return e

    def _optionmenu(self, parent, label, values, current, row):
        tk.Label(parent, text=label, bg=self._CARD, fg=self._TEXT, anchor="w",
                 font=self._settings_font("default")).grid(
            row=row, column=0, sticky="w",
            pady=scaled_px(3, self._ui_scale))
        var = tk.StringVar(value=current)
        om = tk.OptionMenu(parent, var, *tuple(values))
        om.configure(
            width=18, anchor="w", bg=self._CARD, fg=self._TEXT,
            activebackground=self._ACCENT_SOFT, activeforeground=self._TEXT,
            relief="raised", bd=2, highlightthickness=0,
            font=self._settings_font("default"),
            padx=scaled_px(4, self._ui_scale),
            pady=scaled_px(1, self._ui_scale))
        om["menu"].configure(font=self._settings_font("default"))
        om.grid(row=row, column=1, sticky="ew",
                pady=scaled_px(3, self._ui_scale),
                padx=(scaled_px(7, self._ui_scale), 0))
        return var

    def _add_node_row(self, name, ip, role, rdp_user=""):
        row = tk.Frame(self.nodes_box, bg=GRAY)
        row.pack(fill="x", pady=2)
        e_name = tk.Entry(row, width=13, relief="sunken", bd=1, bg=WHITE)
        e_name.insert(0, name); e_name.pack(side="left", padx=(0, 4))
        e_ip = tk.Entry(row, width=16, relief="sunken", bd=1, bg=WHITE)
        e_ip.insert(0, ip); e_ip.pack(side="left", padx=4)
        var = tk.StringVar(value=(role if role in ("head", "worker") else "worker"))
        om = tk.OptionMenu(row, var, "head", "worker")
        om.configure(bg=GRAY, activebackground=GRAY, relief="raised", bd=1,
                     highlightthickness=0)
        om.pack(side="left", padx=4)
        e_rdp = tk.Entry(row, width=22, relief="sunken", bd=1, bg=WHITE)
        e_rdp.insert(0, rdp_user); e_rdp.pack(side="left", padx=4)
        rec = [row, e_name, e_ip, var, e_rdp]
        tk.Button(row, text="X", width=2,
                  command=lambda: self._del_node_row(rec)).pack(side="left")
        self._node_rows.append(rec)

    def _del_node_row(self, rec):
        rec[0].destroy()
        if rec in self._node_rows:
            self._node_rows.remove(rec)

    def _browse_ray_exe(self):
        """v1.3.1: 파일 다이얼로그 + 파일명 검증 + 경로 정규화."""
        initial = self.e_ray.get().strip()
        initialdir = ""
        if initial and initial != "auto":
            d = os.path.dirname(initial)
            if d and os.path.isdir(d):
                initialdir = d
        if not initialdir:
            for cand in (r"%APPDATA%\Python", r"%LOCALAPPDATA%\Programs\Python",
                         r"%USERPROFILE%"):
                d = os.path.expandvars(cand)
                if os.path.isdir(d):
                    initialdir = d
                    break
        path = filedialog.askopenfilename(
            parent=self, title="Select ray.exe",
            initialdir=initialdir or os.path.expanduser("~"),
            filetypes=[("ray.exe", "ray.exe"), ("All exe", "*.exe")])
        if not path:
            return
        path = os.path.normpath(path)
        if os.path.basename(path).lower() != "ray.exe":
            if not messagebox.askyesno(
                    "Browse",
                    f"The selected file is not 'ray.exe':\n{path}\n\nUse it anyway?",
                    parent=self):
                return
        self.e_ray.delete(0, "end")
        self.e_ray.insert(0, path)

    def _firewall_check(self):
        """v1.3.1: 3개 Tailscale inbound 룰 확인.
        - Enabled 상태도 검증 (단순 존재 X)
        - Tailscale 인터페이스 사전 검증 (없으면 add 거부)
        - exact match (substring 'True' 매칭 함정 회피)
        - admin PowerShell 창은 5초 대기 (사용자가 결과 보게)"""
        rules = {
            "Ray-Tailscale-In": "6379,6380-6385,8265,10001-10100",
            "LHM-Tailscale-In-8085": "8085",
            "RCM-Tailscale-In-8866": "8866",
        }
        # 사전: Tailscale 인터페이스 존재?
        ts_present = False
        try:
            p = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetAdapter -Name 'Tailscale' -ErrorAction SilentlyContinue) -ne $null"],
                capture_output=True, text=True, timeout=5,
                creationflags=CREATE_NO_WINDOW)
            ts_present = (p.stdout or "").strip() == "True"
        except Exception:
            pass
        # 각 룰 검사 — Enabled 도 확인
        results = []
        for name in rules:
            present, enabled = False, False
            try:
                ps = ("$r = Get-NetFirewallRule -Name '" + name +
                      "' -ErrorAction SilentlyContinue; "
                      "if (-not $r) { $r = Get-NetFirewallRule -DisplayName '" + name +
                      "' -ErrorAction SilentlyContinue }; "
                      "if ($r) { Write-Host 'present'; "
                      "if ($r.Enabled -eq 'True') { Write-Host 'enabled' } }")
                p = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps],
                    capture_output=True, text=True, timeout=6,
                    creationflags=CREATE_NO_WINDOW)
                out = (p.stdout or "")
                present = "present" in out
                enabled = "enabled" in out
            except Exception:
                pass
            results.append((name, present, enabled))
        body = "\n".join(
            f"  {'✓' if (ok and en) else '⚠' if ok else '✗'}  {n}"
            f"{' (disabled)' if (ok and not en) else ''}"
            for n, ok, en in results)
        ts_line = ("Tailscale interface: " +
                   ("✓ present" if ts_present else "✗ NOT FOUND"))
        missing = [n for n, ok, en in results if not (ok and en)]
        try:
            self.master._firewall_ready_cache = (
                "Ray-Tailscale-In" not in missing)
            self.master._firewall_ready_ts = time.time()
        except Exception:
            pass
        if not missing:
            messagebox.showinfo("Firewall",
                                f"All rules present ✓\n\n{ts_line}\n\n{body}",
                                parent=self)
            return
        if not ts_present:
            messagebox.showerror(
                "Firewall — Tailscale not found",
                f"Firewall rules cannot be added without the Tailscale adapter.\n"
                f"Start Tailscale and try again.\n\n{body}",
                parent=self)
            return
        msg = (f"{ts_line}\n\nFirewall rules:\n\n{body}\n\n"
               "Add/enable missing rules with admin elevation?")
        if not messagebox.askyesno("Firewall — missing rules", msg, parent=self):
            return
        cmd_parts = []
        for r in missing:
            port = rules[r]
            # 기존에 있으면 enable, 없으면 신규
            cmd_parts.append(
                f"$r = Get-NetFirewallRule -Name '{r}' -EA SilentlyContinue; "
                f"if (-not $r) {{ $r = Get-NetFirewallRule -DisplayName '{r}' -EA SilentlyContinue }}; "
                f"if ($r) "
                f"{{ $r | Enable-NetFirewallRule -EA SilentlyContinue }} "
                f"else {{ New-NetFirewallRule -Name '{r}' -DisplayName '{r}' -Direction Inbound "
                f"-Protocol TCP -LocalPort {port} -InterfaceAlias 'Tailscale' "
                "-Action Allow -EA SilentlyContinue | Out-Null }")
        ps_cmd = ("; ".join(cmd_parts) +
                  "; Write-Host ''; Write-Host '=== done ==='; "
                  "Write-Host 'press Enter to close'; Read-Host")
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe",
                f'-NoProfile -ExecutionPolicy Bypass -Command "{ps_cmd}"',
                None, 1)
            messagebox.showinfo(
                "Firewall",
                "Admin PowerShell launched. After it shows 'done', "
                "press Enter in that window, then click Firewall Check again to verify.",
                parent=self)
        except Exception as exc:
            messagebox.showerror("Firewall", f"Failed: {exc}", parent=self)

    def _save(self):
        errors = []

        def as_int(entry, label, default=None, min_value=None, max_value=None):
            raw = entry.get().strip()
            if not raw and default is not None:
                raw = str(default)
            try:
                value = int(raw)
            except ValueError:
                errors.append(f"{label} must be an integer.")
                return int(default or 0)
            if min_value is not None and value < min_value:
                errors.append(f"{label} must be >= {min_value}.")
            if max_value is not None and value > max_value:
                errors.append(f"{label} must be <= {max_value}.")
            return value

        def as_float(entry, label, default=None, min_value=None, max_value=None):
            raw = entry.get().strip()
            if not raw and default is not None:
                raw = str(default)
            try:
                value = float(raw)
            except ValueError:
                errors.append(f"{label} must be a number.")
                return float(default or 0)
            if min_value is not None and value < min_value:
                errors.append(f"{label} must be >= {min_value}.")
            if max_value is not None and value > max_value:
                errors.append(f"{label} must be <= {max_value}.")
            return value

        def check_ip(value, label, allow_auto=False):
            if allow_auto and value == "auto":
                return
            try:
                ipaddress.ip_address(value)
            except ValueError:
                errors.append(f"{label} must be a valid IP address.")

        c = json.loads(json.dumps(self.cfg))
        c["head_ip"] = self.e_head_ip.get().strip()
        check_ip(c["head_ip"], "Head IP")
        c["head_port"] = as_int(self.e_head_port, "Head port", 6379, 1, 65535)
        c["dashboard_port"] = as_int(self.e_dash_port, "Dashboard port", 8265, 1, 65535)
        c["this"]["role"] = self.cmb_role.get()
        c["this"]["ip"] = self.e_this_ip.get().strip() or "auto"
        check_ip(c["this"]["ip"], "This IP", allow_auto=True)
        this_cpus = self.e_cpus.get().strip().lower()
        if this_cpus == "auto":
            c["this"]["num_cpus"] = "auto"
        else:
            c["this"]["num_cpus"] = as_int(
                self.e_cpus, "CPUs", 0, 0, 4096)
        c["ray_exe"] = self.e_ray.get().strip() or "auto"
        if c["ray_exe"] != "auto" and not _is_valid_ray_exe(c["ray_exe"]):
            errors.append("ray.exe path must point to a real ray.exe, or use auto.")
        c["poll_interval"] = as_float(self.e_poll, "Refresh sec", 1.5, 0.5, 3600)
        c["head_dashboard_guard_enabled"] = bool(
            self.var_head_guard.get())
        c["head_dashboard_guard_interval_sec"] = as_int(
            self.e_head_guard_interval, "Dashboard guard interval",
            20, 1, 3600)
        c["head_dashboard_guard_cycles"] = as_int(
            self.e_head_guard_cycles, "Dashboard guard cycles",
            3, 1, 100)
        c["on_close"] = "tray"
        c["stop_on_quit"] = bool(self.var_stopquit.get())
        c["start_on_launch"] = bool(self.var_launch.get())
        c["autostart_login"] = bool(self.var_login.get())
        c["temp_enabled"] = bool(self.var_temp_en.get())
        c["temp_warn_c"] = as_float(self.e_temp_warn, "Temp warn", 80, 0, 140)
        c["temp_critical_c"] = as_float(self.e_temp_crit, "Temp critical", 100, 0, 140)
        if c["temp_warn_c"] >= c["temp_critical_c"]:
            errors.append("Temp warn must be lower than temp critical.")
        c["temp_port"] = as_int(self.e_temp_port, "Temp endpoint port", 8866, 1, 65535)
        c["temp_poll_sec"] = as_float(self.e_temp_poll, "Temp poll sec", 2.0, 0.5, 3600)
        c["temp_auto_pause"] = bool(self.var_temp_ap.get())
        c["metrics_enabled"] = bool(self.var_metrics_en.get())
        c["os_cpu_warn_pct"] = as_float(self.e_os_cpu_warn, "CPU warn", 80, 0, 100)
        c["os_cpu_critical_pct"] = as_float(self.e_os_cpu_crit, "CPU critical", 95, 0, 100)
        if c["os_cpu_warn_pct"] >= c["os_cpu_critical_pct"]:
            errors.append("CPU warn must be lower than CPU critical.")
        c["ram_warn_pct"] = as_float(self.e_ram_warn, "RAM warn", 85, 0, 100)
        c["ram_critical_pct"] = as_float(self.e_ram_crit, "RAM critical", 95, 0, 100)
        if c["ram_warn_pct"] >= c["ram_critical_pct"]:
            errors.append("RAM warn must be lower than RAM critical.")
        cleanup_cfg = c.get("process_cleanup")
        if not isinstance(cleanup_cfg, dict):
            cleanup_cfg = json.loads(json.dumps(
                DEFAULT_CONFIG["process_cleanup"]))
        cleanup_cfg["sample_sec"] = as_float(
            self.e_cleanup_sample, "Cleanup scan sample", 8.0, 1.0, 60.0)
        cleanup_cfg["grace_sec"] = as_float(
            self.e_cleanup_grace, "Cleanup grace period", 3.0, 0.5, 30.0)
        cleanup_cfg.setdefault("result_max_age_sec", 60.0)
        cleanup_cfg.setdefault("ignored_fingerprints", [])
        c["process_cleanup"] = cleanup_cfg
        diag_font = str(self.var_diag_font.get() or "Consolas")
        c["diagnostic_font"] = (
            diag_font if diag_font in DIAG_FONT_CHOICES else "Consolas")
        c["ui_scale_mode"] = (
            self.var_ui_scale_mode.get()
            if self.var_ui_scale_mode.get() in ("stable", "windows")
            else "stable")
        ui_scaling = self.e_ui_scaling.get().strip() or "auto"
        if ui_scaling.lower() != "auto":
            try:
                v = float(ui_scaling)
                if not AUTO_UI_SCALING_FLOOR <= v <= AUTO_UI_SCALING_CEILING:
                    errors.append("Stable scaling must be auto or 1.33-3.00.")
            except ValueError:
                errors.append("Stable scaling must be auto or a number.")
        c["ui_scaling"] = ui_scaling

        controller_normalized = normalize_controller_config({
            "this": c.get("this", {}),
            "nodes": self._node_records,
        })
        c["this"] = controller_normalized.get("this", c.get("this", {}))
        nodes = []
        seen_ips = set()
        seen_names = set()
        for source in controller_normalized.get("nodes", []):
            rec = json.loads(json.dumps(source))
            ip = str(rec.get("ip") or "").strip()
            if not ip:
                continue
            check_ip(ip, f"Node IP {ip}")
            if ip in seen_ips:
                errors.append(f"Duplicate node IP: {ip}")
            seen_ips.add(ip)
            rec["name"] = str(rec.get("name") or ip).strip() or ip
            name_key = _node_label_key(rec["name"])
            if name_key and name_key in seen_names:
                errors.append(f"Duplicate node name: {rec['name']}")
            if name_key:
                seen_names.add(name_key)
            rec["ip"] = ip
            rec["role"] = (rec.get("role") if rec.get("role") in ("head", "worker")
                           else "worker")
            rec["mode"] = ("controller" if is_controller_node(rec) else "ray")
            if is_controller_node(rec):
                rec["num_cpus"] = 0
                rec["rdp_user"] = ""
                rec["rdp_port"] = 3389
            else:
                try:
                    rec["num_cpus"] = int(rec.get("num_cpus"))
                    if not 0 <= rec["num_cpus"] <= 4096:
                        raise ValueError
                except (TypeError, ValueError):
                    errors.append(
                        f"Node CPUs must be 0-4096: {rec['name']}")
                    rec["num_cpus"] = 1
                try:
                    port = int(rec.get("rdp_port", 3389))
                    if not 1 <= port <= 65535:
                        raise ValueError
                    rec["rdp_port"] = port
                except (TypeError, ValueError):
                    errors.append(f"Invalid RDP port: {rec['name']}")
                    rec["rdp_port"] = 3389
                rec["rdp_user"] = str(rec.get("rdp_user") or "").strip()
            nodes.append(rec)
        c["nodes"] = nodes
        c["credential_controller_ips"] = credential_controller_allowlist(
            c.get("head_ip", ""), nodes,
            c.get("credential_controller_ips", []))
        if not nodes:
            errors.append("At least one node is required.")
        ray_heads = [
            node for node in nodes
            if not is_controller_node(node) and node.get("role") == "head"
        ]
        if len(ray_heads) != 1:
            errors.append("Exactly one Ray head node is required.")
        elif str(ray_heads[0].get("ip") or "") != c.get("head_ip"):
            errors.append("Head IP must match the head node in Nodes & RDP.")
        if errors:
            msg = " ".join(errors[:3])
            if len(errors) > 3:
                msg += f" (+{len(errors) - 3} more)"
            self._set_settings_error(msg)
            return
        try:
            saved = self.on_save(c)
        except Exception as exc:
            self._set_settings_error(
                f"Could not save settings: {type(exc).__name__}: {exc}")
            return
        if saved is False:
            self._set_settings_error("Could not save settings. Try again.")
            return
        self.destroy()


class RdpPasswordDialog(tk.Toplevel):
    """Immediate password-change workflow; secrets live only in this dialog."""

    def __init__(self, master, node: dict, executor: Callable):
        super().__init__(master)
        self.node = dict(node)
        self.executor = executor
        self.operation_id = uuid.uuid4().hex
        self.title("Change RDP password")
        self.configure(bg=GRAY)
        self.transient(master)
        self.grab_set()
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        body = tk.Frame(self, bg=GRAY, padx=14, pady=12)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        name = self.node.get("name") or self.node.get("ip") or "node"
        account = self.node.get("rdp_user") or ""
        tk.Label(body, text=f"{name}  ·  {account}", bg=GRAY,
                 font=("Tahoma", 9, "bold"), anchor="w").grid(
                     row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        tk.Label(
            body,
            text="Changes a local Windows account using its current password. "
                 "Microsoft-account passwords and Windows Hello PINs are not "
                 "supported, and RCM never force-resets an account.",
            bg=GRAY, fg=GRAY_DKR, justify="left", wraplength=480).grid(
                row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        def secret_entry(label, row):
            tk.Label(body, text=label, bg=GRAY, anchor="w").grid(
                row=row, column=0, sticky="w", pady=4)
            entry = tk.Entry(body, width=38, show="●", bg=WHITE,
                             relief="sunken", bd=1)
            entry.grid(row=row, column=1, columnspan=2, sticky="ew",
                       padx=(8, 0), pady=4)
            return entry

        self.old_entry = secret_entry("Current password:", 2)
        self.new_entry = secret_entry("New password:", 3)
        self.confirm_entry = secret_entry("Confirm new password:", 4)
        self.save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            body, text="Save in Windows Credential Manager on this PC",
            variable=self.save_var, bg=GRAY, activebackground=GRAY).grid(
                row=5, column=0, columnspan=2, sticky="w", pady=(7, 4))
        tk.Button(body, text="Generate strong password", command=self._generate).grid(
            row=5, column=2, sticky="e", pady=(7, 4))
        self.status = tk.Label(body, text="", bg=GRAY, fg=RED,
                               anchor="w", justify="left", wraplength=480)
        self.status.grid(row=6, column=0, columnspan=3, sticky="ew", pady=(5, 2))
        actions = tk.Frame(body, bg=GRAY)
        actions.grid(row=7, column=0, columnspan=3, sticky="e", pady=(8, 0))
        tk.Button(actions, text="Cancel", width=10,
                  command=self.destroy).pack(side="right")
        self.apply_button = tk.Button(actions, text="Change", width=10,
                                      command=self._submit, default="active")
        self.apply_button.pack(side="right", padx=(0, 6))
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Return>", lambda _e: self._submit())
        self.old_entry.focus_set()

    def _generate(self):
        value = generate_strong_password()
        for entry in (self.new_entry, self.confirm_entry):
            entry.delete(0, "end")
            entry.insert(0, value)
        self.status.configure(
            text="A new password was generated. Copy it safely before applying if needed.",
            fg=BLUE98)

    def _submit(self):
        if str(self.apply_button.cget("state")) == "disabled":
            return
        old_password = self.old_entry.get()
        new_password = self.new_entry.get()
        if not old_password or not new_password:
            self.status.configure(
                text="Enter the current password and a new password.", fg=RED)
            return
        if new_password != self.confirm_entry.get():
            self.status.configure(
                text="The new-password confirmation does not match.", fg=RED)
            return
        self.apply_button.configure(state="disabled")
        self.status.configure(text="Changing password...", fg=BLUE98)
        operation_id = self.operation_id
        save_credential = bool(self.save_var.get())

        def work():
            try:
                outcome = self.executor(
                    self.node, old_password, new_password,
                    save_credential, operation_id)
            except Exception as exc:
                outcome = ("failure", f"Password change failed ({type(exc).__name__})")
            app = getattr(self.master, "master", None)
            post = getattr(app, "_post", None)
            if callable(post):
                post(lambda: self._finish(outcome))
            else:
                self.after(0, lambda: self._finish(outcome))

        threading.Thread(target=work, daemon=True,
                         name="RdpPasswordChange").start()

    def _finish(self, outcome):
        if not self.winfo_exists():
            return
        state, message = outcome
        if state == "success":
            self.status.configure(text=message, fg=GREEN)
            refresh = getattr(self.master, "_populate_node_tree", None)
            if callable(refresh):
                refresh()
            messagebox.showinfo("RDP password", message, parent=self)
            self.destroy()
            return
        if state == "failure":
            self.operation_id = uuid.uuid4().hex
        self.status.configure(
            text=message,
            fg=("#a06000" if state == "partial" else RED))
        self.apply_button.configure(state="normal")


class BatchRdpPasswordDialog(tk.Toplevel):
    """Sequential multi-target change with one old-password field per PC."""

    def __init__(self, master, nodes: list[dict], executor: Callable):
        super().__init__(master)
        self.nodes = rdp_password_targets(nodes)
        self.executor = executor
        self.old_entries = []
        self.result_items = []
        self.operation_ids = [uuid.uuid4().hex for _ in self.nodes]
        self.result_states = ["pending" for _ in self.nodes]
        self.title("Change RDP passwords on multiple PCs")
        self.configure(bg=GRAY)
        self.transient(master)
        self.grab_set()
        self.geometry("760x620")
        self.minsize(680, 520)

        body = tk.Frame(self, bg=GRAY, padx=12, pady=10)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Change passwords on multiple PCs", bg=GRAY,
                 font=("Tahoma", 10, "bold"), anchor="w").pack(fill="x")
        tk.Label(
            body,
            text="Local Windows accounts only. Enter each target's current "
                 "password and one shared new password; targets are processed "
                 "sequentially. Controllers, Microsoft accounts, and PINs are excluded.",
            bg=GRAY, fg=GRAY_DKR, justify="left", anchor="w",
            wraplength=720).pack(fill="x", pady=(2, 8))

        current_box = tk.LabelFrame(
            body, text=" Current password for each target ", bg=GRAY, padx=6, pady=5)
        current_box.pack(fill="x")
        for index, node in enumerate(self.nodes):
            name = node.get("name") or node.get("ip")
            account = node.get("rdp_user") or ""
            row = tk.Frame(current_box, bg=GRAY)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{name}  ·  {account}", width=32,
                     bg=GRAY, anchor="w").pack(side="left")
            entry = tk.Entry(row, show="●", bg=WHITE, relief="sunken", bd=1)
            entry.pack(side="left", fill="x", expand=True, padx=(8, 0))
            self.old_entries.append(entry)

        new_box = tk.LabelFrame(
            body, text=" Shared new password ", bg=GRAY, padx=6, pady=5)
        new_box.pack(fill="x", pady=(8, 0))
        new_box.columnconfigure(1, weight=1)
        tk.Label(new_box, text="New password:", bg=GRAY).grid(
            row=0, column=0, sticky="w", pady=3)
        self.new_entry = tk.Entry(new_box, show="●", bg=WHITE,
                                  relief="sunken", bd=1)
        self.new_entry.grid(row=0, column=1, sticky="ew", padx=(8, 5), pady=3)
        tk.Label(new_box, text="Confirm:", bg=GRAY).grid(
            row=1, column=0, sticky="w", pady=3)
        self.confirm_entry = tk.Entry(new_box, show="●", bg=WHITE,
                                      relief="sunken", bd=1)
        self.confirm_entry.grid(row=1, column=1, sticky="ew", padx=(8, 5), pady=3)
        tk.Button(new_box, text="Generate", width=8, command=self._generate).grid(
            row=0, column=2, rowspan=2, sticky="ns")
        self.save_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            new_box, text="Save successful targets in Windows Credential Manager on this PC",
            variable=self.save_var, bg=GRAY, activebackground=GRAY).grid(
                row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

        result_box = tk.LabelFrame(body, text=" Sequential results ", bg=GRAY,
                                   padx=4, pady=4)
        result_box.pack(fill="both", expand=True, pady=(8, 0))
        self.results = ttk.Treeview(
            result_box, columns=("node", "account", "result"),
            show="headings", height=max(3, len(self.nodes)))
        for col, text_, width in (("node", "PC", 130),
                                  ("account", "Account", 190),
                                  ("result", "Result", 330)):
            self.results.heading(col, text=text_)
            self.results.column(col, width=width, stretch=(col == "result"))
        self.results.pack(fill="both", expand=True)
        for node in self.nodes:
            iid = self.results.insert(
                "", "end", values=(node.get("name") or node.get("ip"),
                                   node.get("rdp_user"), "Pending"))
            self.result_items.append(iid)

        self.status = tk.Label(body, text="", bg=GRAY, fg=GRAY_DKR,
                               anchor="w")
        self.status.pack(fill="x", pady=(5, 0))
        actions = tk.Frame(body, bg=GRAY)
        actions.pack(fill="x", pady=(6, 0))
        tk.Button(actions, text="Close", width=10,
                  command=self.destroy).pack(side="right")
        self.apply_button = tk.Button(actions, text="Change sequentially", width=18,
                                      command=self._submit)
        self.apply_button.pack(side="right", padx=(0, 6))
        self.bind("<Escape>", lambda _e: self.destroy())
        if self.old_entries:
            self.old_entries[0].focus_set()

    def _generate(self):
        value = generate_strong_password()
        for entry in (self.new_entry, self.confirm_entry):
            entry.delete(0, "end")
            entry.insert(0, value)
        self.status.configure(
            text="A shared new password was generated. Store it safely before applying.",
            fg=BLUE98)

    def _post_ui(self, callback):
        app = getattr(self.master, "master", None)
        post = getattr(app, "_post", None)
        if callable(post):
            post(callback)
        else:
            self.after(0, callback)

    def _set_result(self, index, state, message):
        if not self.winfo_exists():
            return
        labels = {"success": "Complete", "partial": "Check required",
                  "failure": "Failed", "running": "Changing"}
        self.results.set(
            self.result_items[index], "result",
            f"{labels.get(state, state)} · {message}" if message
            else labels.get(state, state))
        self.results.see(self.result_items[index])

    def _submit(self):
        if str(self.apply_button.cget("state")) == "disabled":
            return
        old_passwords = [entry.get() for entry in self.old_entries]
        new_password = self.new_entry.get()
        if (not self.nodes
                or any(not value for index, value in enumerate(old_passwords)
                       if self.result_states[index] != "success")):
            self.status.configure(
                text="Enter the current password for every unfinished target.", fg=RED)
            return
        if not new_password or new_password != self.confirm_entry.get():
            self.status.configure(
                text="Check the shared new password and confirmation.", fg=RED)
            return
        save_credential = bool(self.save_var.get())
        self.apply_button.configure(state="disabled")
        self.status.configure(
            text="Changing sequentially... Do not close this window.", fg=BLUE98)

        def work():
            for index, (node, old_password) in enumerate(
                    zip(self.nodes, old_passwords)):
                if self.result_states[index] == "success":
                    continue
                self._post_ui(lambda i=index: self._set_result(i, "running", ""))
                try:
                    state, message = self.executor(
                        node, old_password, new_password, save_credential,
                        self.operation_ids[index])
                except Exception as exc:
                    state, message = (
                        "failure",
                        f"Password change failed ({type(exc).__name__})")
                if state not in ("success", "partial", "failure"):
                    state = "failure"
                self.result_states[index] = state
                # A timeout/partial reuses the same ID so the target can return
                # its cached result. A definite failure gets a fresh attempt.
                if state == "failure":
                    self.operation_ids[index] = uuid.uuid4().hex
                self._post_ui(
                    lambda i=index, s=state, m=message:
                    self._set_result(i, s, m))
            summary = {
                key: sum(1 for state in self.result_states if state == key)
                for key in ("success", "partial", "failure")
            }
            self._post_ui(lambda: self._finish(summary))

        threading.Thread(target=work, daemon=True,
                         name="BatchRdpPasswordChange").start()

    def _finish(self, summary):
        if not self.winfo_exists():
            return
        self.status.configure(
            text=(f"Complete {summary['success']} · "
                  f"Check required {summary['partial']} · "
                  f"Failed {summary['failure']}"),
            fg=(GREEN if not summary["partial"] and not summary["failure"]
                else "#a06000"))
        self.apply_button.configure(state="normal")
        refresh = getattr(self.master, "_populate_node_tree", None)
        if callable(refresh):
            refresh()


class OperationProgressDialog(tk.Toplevel):
    """Small reusable progress window for fleet-wide control operations."""

    def __init__(self, master, title):
        super().__init__(master)
        self.title(title)
        self.configure(bg=GRAY)
        self.transient(master)
        self.geometry("720x430")
        self.minsize(560, 320)
        self.cancel_event = threading.Event()
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.status = tk.Label(
            self, text="Preparing...", bg=GRAY, fg=BLUE98, anchor="w")
        self.status.pack(fill="x", padx=10, pady=(10, 4))
        self.text = tk.Text(
            self, wrap="word", bg=WHITE, fg=BLACK,
            font=("Consolas", 9), relief="sunken", bd=2)
        self.text.pack(fill="both", expand=True, padx=10, pady=4)
        buttons = tk.Frame(self, bg=GRAY)
        buttons.pack(fill="x", padx=10, pady=(4, 10))
        self.cancel_btn = tk.Button(
            buttons, text="Cancel", width=10, command=self.cancel)
        self.cancel_btn.pack(side="right")

    def append(self, line):
        try:
            self.text.insert("end", str(line).rstrip() + "\n")
            self.text.see("end")
        except tk.TclError:
            pass

    def cancel(self):
        if self.cancel_btn.cget("text") == "Close":
            self.destroy()
            return
        self.cancel_event.set()
        self.status.configure(text="Cancellation requested...", fg="#a06000")
        self.cancel_btn.configure(state="disabled")

    def finish(self, summary, ok=True):
        try:
            self.status.configure(
                text=summary, fg=GREEN if ok else "#a06000")
            self.cancel_btn.configure(
                text="Close", state="normal", command=self.destroy)
            self.protocol("WM_DELETE_WINDOW", self.destroy)
        except tk.TclError:
            pass


class LogViewerDialog(tk.Toplevel):
    def __init__(self, master, path):
        super().__init__(master)
        self.ray_log_path = path
        self.trouble_log_path = TROUBLE_LOG_PATH
        self.cleanup_log_path = PROCESS_CLEANUP_LOG_PATH
        self.path = self.ray_log_path
        self.title("RCM Logs")
        # v1.5.33 [fitscreen]: scale the log viewer by the active UI scale too.
        try:
            _ls = clamp_scaling(master.tk.call("tk", "scaling"))
        except Exception:
            _ls = AUTO_UI_SCALING_FLOOR
        _lw = scaled_px(760, _ls)
        _lh = scaled_px(460, _ls)
        try:
            _lw = min(_lw, self.winfo_screenwidth() - 40)
            _lh = min(_lh, self.winfo_screenheight() - 80)
        except Exception:
            pass
        self.geometry(f"{_lw}x{_lh}")
        self.minsize(min(scaled_px(560, _ls), _lw), min(scaled_px(320, _ls), _lh))
        self.configure(bg=GRAY)
        self.transient(master)
        try: self.iconbitmap(resource_path("assets/icon.ico"))
        except Exception: pass

        self.warning_lbl = tk.Label(
            self, text="", bg="#fff4ce", fg="#7a3e00",
            anchor="w", justify="left", padx=8, pady=4)

        self.log_body = tk.Frame(self, bg=GRAY, bd=2, relief="sunken")
        self.log_body.pack(fill="both", expand=True, padx=8, pady=(8, 4))
        self.txt = tk.Text(self.log_body, wrap="none", bg=WHITE, fg=BLACK,
                           font=("Consolas", 9), relief="flat",
                           bd=0, padx=4, pady=4)
        ysb = tk.Scrollbar(
            self.log_body, orient="vertical", command=self.txt.yview)
        xsb = tk.Scrollbar(
            self.log_body, orient="horizontal", command=self.txt.xview)
        self.txt.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        ysb.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")
        self.txt.pack(side="left", fill="both", expand=True)

        bar = tk.Frame(self, bg=GRAY)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        self.btn_ray_log = tk.Button(bar, text="Ray Log", width=9,
                                     command=self.show_ray_log)
        self.btn_ray_log.pack(side="left")
        self.btn_trouble_log = tk.Button(bar, text="Trouble", width=9,
                                         command=self.show_trouble_log)
        self.btn_trouble_log.pack(side="left", padx=(4, 0))
        self.btn_cleanup_log = tk.Button(
            bar, text="Cleanup", width=9,
            command=self.show_cleanup_log)
        self.btn_cleanup_log.pack(side="left", padx=(4, 0))
        self.status_lbl = tk.Label(bar, text="", bg=GRAY, fg=GRAY_DKR,
                                   anchor="w", width=1)
        self.status_lbl.pack(side="left", fill="x", expand=True, padx=(8, 0))
        tk.Button(bar, text="Refresh", width=9,
                  command=self.reload).pack(side="right", padx=(4, 0))
        tk.Button(bar, text="Copy", width=8,
                  command=self.copy_all).pack(side="right", padx=(4, 0))
        tk.Button(bar, text="Copy Diag", width=9,
                  command=self.copy_diagnostics).pack(side="right", padx=(4, 0))
        tk.Button(bar, text="Close", width=8,
                  command=self.destroy).pack(side="right", padx=(4, 0))

        self.reload()

    def _update_mode_buttons(self):
        try:
            self.btn_ray_log.configure(
                relief=("sunken" if self.path == self.ray_log_path else "raised"))
            self.btn_trouble_log.configure(
                relief=("sunken" if self.path == self.trouble_log_path else "raised"))
            self.btn_cleanup_log.configure(
                relief=("sunken" if self.path == self.cleanup_log_path else "raised"))
        except tk.TclError:
            pass

    def show_ray_log(self):
        self.path = self.ray_log_path
        self.reload()

    def show_trouble_log(self):
        self.path = self.trouble_log_path
        self.reload()

    def show_cleanup_log(self):
        self.path = self.cleanup_log_path
        self.reload()

    def _set_text(self, text):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", text)
        self.txt.configure(state="disabled")
        self.txt.see("end")

    def reload(self):
        self._update_mode_buttons()
        try:
            display_path, warning = _newer_legacy_log(self.path)
            if warning:
                self.warning_lbl.configure(text=warning)
                if not self.warning_lbl.winfo_manager():
                    self.warning_lbl.pack(
                        fill="x", padx=8, pady=(8, 0),
                        before=self.log_body)
            elif self.warning_lbl.winfo_manager():
                self.warning_lbl.pack_forget()
            if not os.path.exists(display_path):
                if self.path == self.trouble_log_path:
                    self._set_text(
                        "No trouble events recorded yet.\n\n"
                        "WARN/ERR diagnostic states will appear here with "
                        "ports, process counts, cluster view, node snapshots, "
                        "and the recent ray_monitor.log tail.")
                elif self.path == self.cleanup_log_path:
                    self._set_text(
                        "No process cleanup activity recorded yet.\n\n"
                        "Scans and confirmed termination summaries will "
                        "appear here. Commands and secrets are never logged.")
                else:
                    self._set_text(f"Log file not found:\n{self.path}")
                self.status_lbl.configure(text="missing")
                return
            size = os.path.getsize(display_path)
            with open(display_path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            self._set_text(text)
            suffix = "  [legacy recovery]" if warning else ""
            self.status_lbl.configure(
                text=f"{display_path}  ({size} bytes){suffix}")
        except Exception as exc:
            self._set_text(f"Could not read log:\n{self.path}\n\n{exc}")
            self.status_lbl.configure(text="read error")

    def copy_all(self):
        try:
            text = self.txt.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_lbl.configure(text="copied log text")
        except Exception as exc:
            self.status_lbl.configure(text=f"copy failed: {exc}")

    def copy_diagnostics(self):
        try:
            maker = getattr(self.master, "diagnostic_snapshot_text", None)
            if callable(maker):
                text = maker()
            else:
                text = self.txt.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_lbl.configure(text="copied diagnostic snapshot")
        except Exception as exc:
            self.status_lbl.configure(text=f"copy diag failed: {exc}")


# =========================================================================
#  Main application
# =========================================================================
class RayApp(LegacyRayAppMixin, tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self._ui_scaling_target = None
        self._ui_scaling_guard_job = None
        self._duplicate_guard_job = None
        self._duplicate_guard_running = False
        self._apply_ui_scaling_from_config(initial=True)
        self.role, self.ip, self.cpus = resolve_identity(self.cfg)
        self.controller_only = is_controller_config(self.cfg, self.ip)
        self.controller = RayController(self.cfg, self._log)
        self.monitor: Optional[ClusterMonitor] = None
        self.tray = None
        self._last_view: Optional[ClusterView] = None
        self._busy = False
        self._repair_lock = threading.Lock()
        self._password_change_lock = threading.Lock()
        self._self_update_lock = threading.Lock()
        self._self_update_pending = False
        self._cluster_config_lock = threading.Lock()
        self._rdp_probe_generation = 0
        self._rdp_probe_running = False
        self._password_request_cache: dict[str, dict] = {}
        # Per-process only: binds an idempotency key to the exact secret
        # payload without retaining a reversible copy of either password.
        self._password_request_hmac_key = os.urandom(32)
        self._password_completed_operations: list[str] = []
        self._repair_status = {
            "ok": True,
            "state": "idle",
            "message": "",
            "ts": 0.0,
        }
        self._closing = False
        self._mon_gen = 0
        self._settings_win: Optional[SettingsDialog] = None
        self._logs_win: Optional[LogViewerDialog] = None
        self._cleanup_win = None
        self._ui_q: "queue.Queue[Callable]" = queue.Queue()
        self._displayed_nodes: list[NodeView] = []
        # v1.07.16d [flexcols]: responsive node-table column widths,
        # recomputed per render and monotonic within the session.
        self._node_cols: dict = {}
        self._diag_raw = ("STOP", "DIAG WAIT starting monitor...", "NEXT Please wait.")
        self._diag_log_line = "LOG WAIT starting monitor; reading ray_monitor.log"
        self._diag_font = None
        self._diag_ticker_offset = 0
        self._diag_ticker_key = None
        self._diag_tick_job = None
        self._board_feed = (
            BoardFeed(seed=f"{APP_VERSION}-{APP_BUILD_TAG}-{socket.gethostname()}")
            if _HAS_STATUS_BOARD_CONTENT and BoardFeed is not None else None)
        self._board_line = ""
        self._board_line_ts = 0.0
        self._board_scene = None
        self._board_prev_scene = None
        self._board_scene_ts = 0.0
        self._board_scene_transition_start = 0.0
        self._board_scene_hold_sec = 24.0
        self._board_scene_transition_sec = 2.8
        self._radio_segments: list[str] = []
        self._radio_recent_heads: list[str] = []
        self._radio_scroll_px = 0
        self._radio_separator = "     |     "
        self._radio_notice_last = ""
        self._radio_notice_ts = 0.0
        self._radio_notice_cooldown_sec = 60.0
        self._last_trouble_key = None
        self._last_trouble_ts = 0.0
        self._diag_probe_ts = 0.0
        self._diag_probe = (False, False, False, 0)
        self._layout_fit_done = False
        self._last_fit_geometry = None
        self._last_screen_size = None
        self._last_monitor_dpi = None
        self._last_display_signature = None
        self._firewall_ready_cache = None
        self._firewall_ready_ts = 0.0

        # Shared named fonts are deliberately reconfigured after a live
        # tk-scaling change. Anonymous font tuples retain stale pixel metrics
        # across some RDP DPI transitions until the process is restarted.
        self._init_ui_fonts()
        self.option_add("*Font", "RCMDefaultFont")
        self.option_add("*Background", GRAY)
        self.option_add("*Foreground", BLACK)
        self.option_add("*highlightThickness", 0)

        self.title(f"Ray Cluster Manager {APP_VERSION} [{APP_BUILD_TAG}]")
        # v1.5.0: progress bar replaced by the diagnostic status board.
        w, h, min_w, min_h, self._layout_mode = self._choose_main_geometry()
        self._main_width = w
        self._base_main_width = w  # v1.5.33: canonical base for Fit Screen width scaling
        self._main_min_width = min_w
        self._main_min_height = min_h
        # v1.5.33 [fitscreen]: a width chosen by the Fit Screen button persists
        # across runs. It is re-clamped to the live screen by _fit_main_geometry
        # on every refit, so a stale/oversized value can never overflow.
        try:
            saved_w = int(self.cfg.get("main_width") or 0)
        except (TypeError, ValueError):
            saved_w = 0
        if saved_w > 0:
            self._main_width = saved_w
        self.geometry(f"{w}x{h}")
        self.minsize(min_w, min_h)
        self.maxsize(max(min_w, self.winfo_screenwidth() - 40),
                     max(min_h, self.winfo_screenheight() - 60))
        self.resizable(True, True)
        self.configure(bg=GRAY)
        try: self.iconbitmap(resource_path("assets/icon.ico"))
        except Exception: pass

        self._build_ui()
        self._apply_diag_font()
        w, h, min_w, min_h = self._fit_main_geometry(force=True)
        # v1.5.33 [fitscreen]: once the window is actually mapped on its real
        # monitor, auto-fit scale+width to THAT monitor so a user who never
        # clicks Fit Screen is never left stuck-small. _fit_to_monitor honours
        # an explicit/windows scale and only re-measures DPI in auto mode.
        self.after(160, self._auto_fit_startup)
        self.protocol("WM_DELETE_WINDOW", self._on_close_button)
        self.apply_login_autostart(self.cfg.get("autostart_login", False))
        self._log(f"monitoring {self.cfg['head_ip']}:{self.cfg['dashboard_port']}")
        self._log(
            f"layout: {self._layout_mode} "
            f"geometry={w}x{h} min={min_w}x{min_h} "
            f"screen={self.winfo_screenwidth()}x{self.winfo_screenheight()}")

        self.after(25, self._drain_ui_q)
        self._start_monitor()
        if _HAS_TRAY:
            self._build_tray()
        # v1.1: start temperature poller + HTTP endpoint
        self._temp_srv = None
        self._metrics_retry_job = None
        self._auto_pause_fired = False
        self._cool_streak = 0  # v1.3.1: K-cycle rearm debounce
        self._watchdog = None
        self._head_guard = None
        # Capture the bytes that created this process. The shared official
        # path may be overwritten later by Google Drive; re-hashing that path
        # would then confuse an old in-memory process with the new artifact
        # and make /self-update incorrectly return already_current.
        self._startup_binary_sha = file_sha256(current_binary_path())
        # v1.1 debug: report temp module status loudly
        self._log(f"v{APP_VERSION} build {APP_BUILD_DATE}  PID={os.getpid()}")
        startup_dup = os.environ.pop("RCM_STARTUP_DUP_CLEANUP", "")
        if startup_dup:
            self._log("duplicate guard startup: " + startup_dup)
        self._log(f"binary: {current_binary_path()}")
        self._log(f"binary sha256: {self._startup_binary_sha}")
        try:
            self._log(
                f"dpi: {_DPI_AWARENESS} "
                f"tk_scaling={self.tk.call('tk', 'scaling')} "
                f"fpixels_1i={self.winfo_fpixels('1i')} "
                f"screen={self.winfo_screenwidth()}x{self.winfo_screenheight()}")
        except Exception:
            self._log(f"dpi: {_DPI_AWARENESS}")
        self._log(
            "ui scale: "
            f"mode={self.cfg.get('ui_scale_mode', 'stable')} "
            f"setting={self.cfg.get('ui_scaling', 'auto')} "
            f"target={self._ui_scaling_target or 'windows'} "
            f"actual={self._current_tk_scaling()}")
        self._schedule_ui_scaling_guard()
        self._schedule_duplicate_guard()
        self._log(
            "resolved ray.exe: "
            f"{find_ray_exe(self.cfg.get('ray_exe', 'auto')) or '<not found>'}")
        if _HAS_TEMPS_SERVER:
            self._log("metrics server module: OK (temps_server imported)")
        else:
            self._log(f"metrics server module: UNAVAILABLE - {_temps_server_import_error}")
        if _HAS_SENSOR and not self.controller_only:
            self._log("sensor_poller module: OK")
            # try opening LHM right now so errors hit the log
            if self.cfg.get("temp_enabled", True):
                try:
                    err = sensor_poller.get_poller().open()
                    if err:
                        self._log(f"sensor_poller.open() FAILED: {err}")
                    else:
                        test = sensor_poller.get_poller().read()
                        self._log(f"sensor_poller test read: pkg={test.cpu_pkg} "
                                  f"max={test.cpu_max} err={test.error or 'none'}")
                except Exception as exc:
                    self._log(f"sensor_poller open exception: "
                              f"{type(exc).__name__}: {exc}")
            else:
                self._log("sensor_poller: skipped (temperature monitoring disabled)")
        elif self.controller_only:
            # A controller only launches outbound RDP sessions.  Do not even
            # instantiate the LHM singleton here: opening/reading it is wasted
            # work on low-power nodes and can leave native sensor handles resident.
            self._log("sensor_poller: skipped (controller mode)")
        else:
            self._log(f"sensor_poller: UNAVAILABLE - {_sensor_import_error}")
        self._temp_srv_port = None
        self._temp_polling = False
        self._sync_metrics_runtime()
        self._sync_watchdog_runtime()
        # v1.2: warn loudly if ray.exe missing
        self._check_ray_exe()
        # v1.3.1: non-admin banner on dedicated admin_lbl (no race with ray_lbl)
        if os.environ.get("RCM_NON_ADMIN") == "1":
            self._log("WARNING: non-admin mode — CPU temps unavailable")
            try:
                self.admin_lbl.configure(
                    text="⚠ Not running as administrator — CPU temperatures "
                         "are unavailable. Quit, then right-click and run as administrator.")
                self.admin_lbl.pack_forget()
                self.admin_lbl.pack(fill="x", side="top",
                                    before=self._head_frame)
            except Exception: pass
        test_quit_after = os.environ.get("RCM_TEST_QUIT_AFTER_MS")
        if test_quit_after and _skip_uac_for_tests():
            try:
                delay_ms = max(500, int(float(test_quit_after)))
                test_stop_ray = (
                    os.environ.get("RCM_TEST_QUIT_STOP_RAY", "1") != "0")
                self.after(
                    delay_ms,
                    lambda: self._quit(
                        stop_ray=test_stop_ray, source="test-auto"))
                self._log(
                    f"test auto quit scheduled in {delay_ms}ms "
                    f"(stop_ray={test_stop_ray})")
            except Exception as exc:
                self._log(f"test auto quit ignored: {exc}")
        if self.cfg.get("start_on_launch") and not self.controller_only:
            self.after(800, self._do_start)

    def _choose_main_geometry(self):
        """Use a compact width and let Tk report the required content height.

        The regression after v1.5.1 was making the whole window wider to fit a
        longer node row. Keep the row text compact and fit both width and
        height to the actual DPI/font metrics on each PC so low-DPI workers do
        not get large empty gray areas around the content.
        """
        return 1120, 470, 620, 430, "quitguard"

    def _fit_main_geometry(self, force=False):
        """Shrink or grow the fixed-width window to the actual packed content."""
        preferred_w = int(getattr(self, "_main_width", 880) or 880)
        min_w = int(getattr(self, "_main_min_width", 520) or 520)
        min_h = int(getattr(self, "_main_min_height", 340) or 340)
        try:
            self.update_idletasks()
            screen_w = int(self.winfo_screenwidth())
            screen_max_w = max(min_w, screen_w - 40)
            cur_w = int(self.winfo_width())
            desired_w = max(min_w, min(preferred_w, screen_max_w))
            if force:
                width = desired_w
            else:
                width = cur_w if cur_w >= min_w else desired_w
                width = max(min_w, min(width, screen_max_w))
            req_h = int(self.winfo_reqheight())
            screen_h = int(self.winfo_screenheight())
            max_h = max(min_h, screen_h - 80)
            height = max(min_h, min(req_h + 4, max_h))
            target = (width, height)
            if force or target != self._last_fit_geometry:
                cur = (int(self.winfo_width()), int(self.winfo_height()))
                if force or cur != target:
                    self.geometry(f"{width}x{height}")
                self.minsize(min_w, min_h)
                self.maxsize(screen_max_w, max(height, int(self.winfo_screenheight()) - 60))
                self.resizable(True, True)
                self._last_fit_geometry = target
            self._last_screen_size = (screen_w, screen_h)
            return width, height, min_w, min_h
        except Exception:
            self.geometry(f"{preferred_w}x430")
            self.minsize(min_w, min_h)
            screen_w = int(self.winfo_screenwidth())
            screen_h = int(self.winfo_screenheight())
            self.maxsize(max(min_w, screen_w - 40),
                         max(min_h, screen_h - 60))
            self.resizable(True, True)
            self._last_screen_size = (screen_w, screen_h)
            return preferred_w, 430, min_w, min_h

    def _check_ray_exe(self):
        # v1.3.1: uses dedicated ray_lbl (no longer clobbers admin_lbl).
        # Also: clear cached None on each re-check (cache-invalidation hole).
        if self.controller_only:
            try:
                self.ray_lbl.configure(text="Controller mode — local Ray not required")
            except Exception:
                pass
            return
        configured = self.cfg.get("ray_exe", "auto")
        _ray_exe_cache.pop(configured, None)  # force fresh scan
        def scan():
            path = find_ray_exe(configured)
            def apply():
                if path:
                    try: self.ray_lbl.pack_forget()
                    except Exception: pass
                    self._log(f"ray.exe found: {path}")
                else:
                    try:
                        self.ray_lbl.configure(
                            text="⚠ ray.exe NOT FOUND — open Settings → Cluster → ray.exe")
                        self.ray_lbl.pack_forget()
                        self.ray_lbl.pack(fill="x", side="top",
                                          before=self._head_frame)
                    except Exception as exc:
                        self._log(f"ray_lbl pack error: {exc}")
                    self._log("ray.exe NOT FOUND in any standard path")
            self._post(apply)
        threading.Thread(target=scan, daemon=True, name="RayExeScan").start()

    def _monitor_dpi_for_window(self):
        """v1.5.33 [fitscreen]: real per-monitor DPI of the monitor the live
        window currently sits on. Returns a float DPI (96.0/144.0/192.0...) or
        None if unavailable. This is the query the app never had, and its
        absence was the root of the 'stuck small' behaviour."""
        if not _IS_WIN:
            return None
        try:
            user32 = ctypes.windll.user32
            # HWND is pointer-sized; wrap in c_void_p so it is not truncated
            # to 32 bits on 64-bit Windows.
            hwnd = ctypes.c_void_p(int(self.winfo_id()))
            # Walk up to the real top-level HWND so we read the window's
            # monitor, not a child widget's.
            try:
                user32.GetAncestor.restype = ctypes.c_void_p
                user32.GetAncestor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                top = user32.GetAncestor(hwnd, 2)  # GA_ROOT
                if top:
                    hwnd = ctypes.c_void_p(top)
            except Exception:
                pass
            # Win10 1607+: GetDpiForWindow returns the effective per-monitor DPI
            # because the process is Per-Monitor-V2 aware.
            try:
                user32.GetDpiForWindow.restype = ctypes.c_uint
                user32.GetDpiForWindow.argtypes = [ctypes.c_void_p]
                dpi = int(user32.GetDpiForWindow(hwnd))
                if dpi > 0:
                    return float(dpi)
            except Exception:
                pass
            # Fallback: MonitorFromWindow + GetDpiForMonitor (MDT_EFFECTIVE=0).
            try:
                user32.MonitorFromWindow.restype = ctypes.c_void_p
                user32.MonitorFromWindow.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                hmon = user32.MonitorFromWindow(hwnd, 2)  # NEAREST
                dx = ctypes.c_uint(0)
                dy = ctypes.c_uint(0)
                shcore = ctypes.windll.shcore
                shcore.GetDpiForMonitor.argtypes = [
                    ctypes.c_void_p, ctypes.c_int,
                    ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
                if (shcore.GetDpiForMonitor(
                        ctypes.c_void_p(hmon), 0,
                        ctypes.byref(dx), ctypes.byref(dy)) == 0
                        and dx.value > 0):
                    return float(dx.value)
            except Exception:
                pass
        except Exception:
            return None
        return None

    def _comfort_floor_scaling(self, screen_w=None):
        """v1.5.33 [fitscreen]: delegate to the pure comfort_floor_for_screen so
        the GUI and test_dpi_scaling.py cannot drift. screen_w defaults to the
        width of the monitor the window is actually on."""
        if screen_w is None:
            screen_w = self._monitor_width_for_window() or self._safe_screen_w()
        return comfort_floor_for_screen(screen_w)

    def _current_tk_scaling(self):
        try:
            return float(self.tk.call("tk", "scaling"))
        except Exception:
            return None

    def _clamped_ui_scaling(self, value):
        return clamp_scaling(value)

    def _configured_ui_scaling_target(self, current=None, live=False):
        mode = str(self.cfg.get("ui_scale_mode") or "stable").lower()
        if mode == "windows":
            return None
        if current is None:
            current = self._current_tk_scaling()
        raw = str(self.cfg.get("ui_scaling", "auto")).strip().lower()
        if raw in ("", "auto"):
            if live:
                dpi = self._monitor_dpi_for_window()
                mon_w = self._monitor_width_for_window() or self._safe_screen_w()
                return fit_scale(dpi, mon_w)
            return self._clamped_ui_scaling(current)
        return self._clamped_ui_scaling(raw)

    def _apply_ui_scaling_from_config(self, initial=False):
        current = self._current_tk_scaling()
        target = self._configured_ui_scaling_target(current, live=not initial)
        self._ui_scaling_target = target
        if current is None:
            return target
        if target is None:
            if not initial:
                self._refresh_ui_fonts()
            return target
        try:
            if abs(float(current) - float(target)) > 0.01:
                self.tk.call("tk", "scaling", float(target))
            if not initial:
                self._refresh_ui_fonts()
        except Exception:
            pass
        return target

    def _schedule_ui_scaling_guard(self):
        if self._closing:
            return
        try:
            self._guard_ui_scaling()
        except Exception:
            pass

    def _guard_ui_scaling(self):
        if self._closing:
            return
        try:
            mode = str(self.cfg.get("ui_scale_mode") or "stable").lower()
            raw = str(self.cfg.get("ui_scaling", "auto")).strip().lower()
            auto = (mode != "windows" and raw in ("", "auto"))
            dpi = self._monitor_dpi_for_window()
            mon_w = self._monitor_width_for_window() or self._safe_screen_w()
            work = self._monitor_work_area_for_window()
            signature = (
                round(float(dpi), 1) if dpi else None,
                int(mon_w), tuple(int(v) for v in work))
            previous = getattr(self, "_last_display_signature", None)
            display_changed = previous is not None and signature != previous
            self._last_display_signature = signature
            self._last_monitor_dpi = dpi
            current = self._current_tk_scaling()
            target = self._configured_ui_scaling_target(current, live=True)
            scale_drift = (
                target is not None and current is not None
                and abs(float(current) - float(target)) > 0.02)

            if auto and (display_changed or scale_drift):
                self._log(
                    "display: auto resync "
                    f"signature={previous}->{signature} scale={current}->{target}")
                self._fit_to_monitor(persist=False, reason="display-change")
                self.update_idletasks()
                self._fit_to_content(persist=False)
            elif mode == "windows" and display_changed:
                self._refresh_ui_fonts()
                self.update_idletasks()
                self._fit_to_content(persist=False)
            elif target is not None and scale_drift:
                self.tk.call("tk", "scaling", float(target))
                self._refresh_ui_fonts()
                self._log(
                    "ui scale: restored explicit setting "
                    f"{current:.3f}->{target:.3f}")
                self.update_idletasks()
                self._fit_to_content(persist=False)
        finally:
            if not self._closing:
                self._ui_scaling_guard_job = self.after(
                    2500, self._guard_ui_scaling)

    def _safe_screen_w(self):
        try:
            return int(self.winfo_screenwidth())
        except Exception:
            return 1920

    def _monitor_width_for_window(self):
        """v1.5.33 [fitscreen]: pixel width of the monitor the window sits on.
        In a Per-Monitor-V2 process winfo_screenwidth() returns the PRIMARY
        monitor, so use GetMonitorInfo on the window's own HMONITOR instead."""
        if not _IS_WIN:
            return None
        try:
            user32 = ctypes.windll.user32
            hwnd = ctypes.c_void_p(int(self.winfo_id()))
            try:
                user32.GetAncestor.restype = ctypes.c_void_p
                user32.GetAncestor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                top = user32.GetAncestor(hwnd, 2)  # GA_ROOT
                if top:
                    hwnd = ctypes.c_void_p(top)
            except Exception:
                pass
            user32.MonitorFromWindow.restype = ctypes.c_void_p
            user32.MonitorFromWindow.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            hmon = user32.MonitorFromWindow(hwnd, 2)  # NEAREST
            if not hmon:
                return None

            class _RECT(ctypes.Structure):
                _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                            ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

            class _MONITORINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_ulong), ("rcMonitor", _RECT),
                            ("rcWork", _RECT), ("dwFlags", ctypes.c_ulong)]

            mi = _MONITORINFO()
            mi.cbSize = ctypes.sizeof(_MONITORINFO)
            user32.GetMonitorInfoW.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(_MONITORINFO)]
            if user32.GetMonitorInfoW(ctypes.c_void_p(hmon), ctypes.byref(mi)):
                w = int(mi.rcMonitor.right - mi.rcMonitor.left)
                if w > 0:
                    return w
        except Exception:
            return None
        return None

    def _monitor_work_area_for_window(self):
        """Return (x, y, width, height) for this window's monitor work area."""
        if _IS_WIN:
            try:
                user32 = ctypes.windll.user32
                hwnd = ctypes.c_void_p(int(self.winfo_id()))
                user32.MonitorFromWindow.restype = ctypes.c_void_p
                user32.MonitorFromWindow.argtypes = [ctypes.c_void_p, ctypes.c_uint]
                hmon = user32.MonitorFromWindow(hwnd, 2)  # MONITOR_DEFAULTTONEAREST

                class _RECT(ctypes.Structure):
                    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long),
                                ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

                class _MONITORINFO(ctypes.Structure):
                    _fields_ = [("cbSize", ctypes.c_ulong), ("rcMonitor", _RECT),
                                ("rcWork", _RECT), ("dwFlags", ctypes.c_ulong)]

                mi = _MONITORINFO()
                mi.cbSize = ctypes.sizeof(_MONITORINFO)
                if user32.GetMonitorInfoW(ctypes.c_void_p(hmon), ctypes.byref(mi)):
                    rc = mi.rcWork
                    return (int(rc.left), int(rc.top),
                            max(1, int(rc.right - rc.left)),
                            max(1, int(rc.bottom - rc.top)))
            except Exception:
                pass
        return (0, 0, max(1, int(self.winfo_screenwidth())),
                max(1, int(self.winfo_screenheight())))

    def _set_node_scrollbars(self, horizontal=False, vertical=False):
        """Show only scrollbars that the current content-fit genuinely needs."""
        for widget in (self.nodes_hscroll, self.nodes_vscroll):
            try:
                widget.pack_forget()
            except Exception:
                pass
        if vertical:
            self.nodes_vscroll.pack(side="right", fill="y", before=self.nodes_list)
        if horizontal:
            self.nodes_hscroll.pack(side="bottom", fill="x", before=self.nodes_list)

    def _fit_to_content(self, persist=True):
        """Fit the manual button to visible header/rows without changing DPI.

        Width follows the actual rstrip'd font measurements plus two character
        cells. Height follows connected nodes plus one intentionally blank row.
        Automatic monitor/DPI fitting remains in ``_fit_to_monitor``.
        """
        try:
            # Measure chrome in the no-scrollbar state that we are trying to
            # produce.  Otherwise a currently visible vertical/horizontal bar
            # is counted as permanent chrome and leaves a bar-sized excess.
            self._set_node_scrollbars(horizontal=False, vertical=False)
            self.update_idletasks()
            header_text = str(self.nodes_header.cget("text") or "").rstrip()
            rows = [str(v).rstrip() for v in self.nodes_list.get(0, "end")]
            header_font = tkfont.Font(root=self, font=self.nodes_header.cget("font"))
            row_font = tkfont.Font(root=self, font=self.nodes_list.cget("font"))
            text_width = header_font.measure(header_text)
            if rows:
                text_width = max(text_width, max(row_font.measure(v) for v in rows))
            char_width = max(1, header_font.measure("0"), row_font.measure("0"))
            row_height = max(1, int(row_font.metrics("linespace")) + 2)

            current_w = max(1, int(self.winfo_width()))
            current_h = max(1, int(self.winfo_height()))
            viewport_w = max(1, int(self.nodes_list.winfo_width()))
            viewport_h = max(1, int(self.nodes_list.winfo_height()))
            chrome_w = max(0, current_w - viewport_w)
            chrome_h = max(0, current_h - viewport_h)
            vbar_w = max(0, int(self.nodes_vscroll.winfo_reqwidth()))
            hbar_h = max(0, int(self.nodes_hscroll.winfo_reqheight()))
            work = self._monitor_work_area_for_window()
            # A metrics-disabled table can be much narrower than the fixed
            # action row.  Content fitting must never shrink the root until
            # right-packed Fit Screen / Logs controls disappear.  Tk reports
            # the full requested row width even while the live row is clipped.
            action_row_min_w = int(self._main_min_width)
            btnrow = getattr(self, "btnrow", None)
            if btnrow is not None:
                action_row_min_w = max(
                    action_row_min_w,
                    int(btnrow.winfo_reqwidth())
                    + 2 * int(getattr(self, "_btnrow_outer_pad_x", 0)))
            fit_min_w = min(action_row_min_w, max(1, int(work[2])))
            # v1.07.16c [retrofit]: the fixed manual-resize minimum height
            # (430px regardless of UI scale) forced blank filler rows under
            # small clusters.  Every fixed control is already measured inside
            # chrome_h, so the content fit may go below that minimum while
            # keeping all controls visible; manual resizing keeps the floor
            # via minsize below.
            content_min_h = chrome_h + (len(rows) + 1) * row_height
            fit_min_h = min(int(self._main_min_height), int(content_min_h))
            layout = content_fit_geometry(
                text_width, char_width, len(rows), row_height,
                chrome_w, chrome_h, work,
                current_xy=(self.winfo_x(), self.winfo_y()),
                min_size=(fit_min_w, fit_min_h),
                right_margin_chars=2, spare_rows=1,
                vertical_scrollbar_width_px=vbar_w,
                horizontal_scrollbar_height_px=hbar_h)

            # A Tk Listbox height is measured in rows. This is the direct UI
            # expression of the node_count + 1 requirement.
            self.nodes_list.configure(height=max(1, layout["visible_rows"]))
            self._set_node_scrollbars(
                horizontal=layout["horizontal_scroll"],
                vertical=layout["vertical_scroll"])
            self.geometry(
                f"{layout['width']}x{layout['height']}+{layout['x']}+{layout['y']}")
            self.minsize(fit_min_w,
                         min(int(self._main_min_height), int(layout["height"])))
            self.maxsize(work[2], work[3])
            self._main_width = int(layout["width"])
            self._last_fit_geometry = (layout["width"], layout["height"])
            self._layout_fit_done = True
            if persist:
                self.cfg["main_width"] = int(layout["width"])
                save_config(self.cfg)
            self._log(
                "fit-to-content: "
                f"rows={len(rows)}+1 text={text_width}px char={char_width}px "
                f"min_w={fit_min_w}px "
                f"geometry={layout['width']}x{layout['height']} "
                f"scroll={layout['horizontal_scroll']}/{layout['vertical_scroll']}")
            return layout
        except Exception as exc:
            self._log(f"fit-to-content failed: {type(exc).__name__}: {exc}")
            return None

    def _fit_to_monitor(self, persist=False, reason="manual",
                        apply_geometry=True):
        """v1.5.33 [fitscreen]: measure the monitor the window is CURRENTLY on
        and size the UI (scale + width) to it, live and without a restart.
        Shared by the Fit Screen button (persist=True), the post-map auto-fit,
        and the per-monitor-DPI guard. Reads the REAL per-monitor DPI/width
        (GetDpiForWindow / GetMonitorInfo -- NOT winfo_screenwidth(), which is
        the primary monitor). In 'auto' mode the scale is re-measured from DPI;
        an explicit user scale is honoured; 'windows' mode is left to Tk. All
        scaling math delegates to the pure fit_scale/fit_width functions."""
        try:
            self.update_idletasks()
            before = self._current_tk_scaling()
            dpi = self._monitor_dpi_for_window()
            mon_w = self._monitor_width_for_window() or self._safe_screen_w()
            mode = str(self.cfg.get("ui_scale_mode") or "stable").lower()
            raw = str(self.cfg.get("ui_scaling", "auto")).strip().lower()
            if mode == "windows":
                target = self._current_tk_scaling() or AUTO_UI_SCALING_FLOOR
                apply_scale = False
            elif raw in ("", "auto"):
                target = fit_scale(dpi, mon_w)
                apply_scale = True
            else:
                target = clamp_scaling(raw)
                apply_scale = True
            target = round(float(target), 3)
            self._ui_scaling_target = target
            self._last_monitor_dpi = dpi
            base_w = int(getattr(self, "_base_main_width", None) or MAIN_BASE_WIDTH)
            self._main_width = fit_width(target, mon_w, base_w=base_w,
                                         min_w=self._main_min_width)
            # Apply the scale UNCONDITIONALLY for this explicit re-fit, so tk
            # scaling and the new width can never derive from different values
            # (the 0.01-gated _apply_ui_scaling_from_config could skip it).
            if apply_scale:
                try:
                    self.tk.call("tk", "scaling", float(target))
                except Exception:
                    pass
            # Reconfiguring named fonts is required even when target==current:
            # Fit Screen is the manual recovery path for stale RDP pixel metrics.
            self._refresh_ui_fonts()
            if persist:
                # Remember the width hint (avoids a resize flash next launch);
                # ui_scaling is left as-is so 'auto' stays self-correcting and a
                # later monitor/RDP change is still auto-fitted.
                self.cfg["main_width"] = int(self._main_width)
                try:
                    save_config(self.cfg)
                except Exception:
                    pass
            self._layout_fit_done = False
            # The manual button immediately performs a content-measured fit.
            # Do not first force the monitor-width geometry in that path: Tk
            # applies the new root width before its expanding Listbox receives
            # the matching <Configure>, so chrome_w is briefly inflated by the
            # width delta and repeated clicks alternate narrow <-> wide.  DPI,
            # fonts and the monitor signature are still refreshed here; the
            # stable current viewport is then measured by _fit_to_content.
            if apply_geometry:
                self._fit_main_geometry(force=True)
            after = self._current_tk_scaling()
            try:
                work = self._monitor_work_area_for_window()
                self._last_display_signature = (
                    round(float(dpi), 1) if dpi else None,
                    int(mon_w), tuple(int(v) for v in work))
            except Exception:
                pass
            try:
                self._last_screen_size = (int(self.winfo_screenwidth()),
                                          int(self.winfo_screenheight()))
            except Exception:
                pass
            self._log(
                f"fit-to-monitor ({reason}): dpi={dpi} mon_w={mon_w} "
                f"target={target} scale {before}->{after} "
                f"width->{self._main_width} mode={mode}/{raw} persist={persist}")
            return target
        except Exception as exc:
            self._log(f"fit-to-monitor failed ({reason}): "
                      f"{type(exc).__name__}: {exc}")
            return None

    def _do_fit_monitor(self):
        """Manual recovery: resync live DPI/fonts, then fit actual content."""
        self._fit_to_monitor(
            persist=False, reason="button", apply_geometry=False)
        self.update_idletasks()
        self._fit_to_content(persist=True)

    def _auto_fit_monitor(self, reason="startup"):
        """Run the per-monitor fit automatically (post-map, and on monitor/DPI
        change via the guard). This is what makes 'window stuck small'
        impossible WITHOUT a manual click. Persists the width hint so later
        launches do not flash."""
        if getattr(self, "_closing", False):
            return
        self._fit_to_monitor(persist=False, reason=reason)

    def _auto_fit_startup(self):
        """Run the same content fit as the Fit Screen button once at startup.

        First settle per-monitor DPI/width, then wait one more idle turn so the
        initial node rows and widget chrome have their final measured sizes.
        This is deliberately one-shot; later manual window resizing is kept.
        """
        if getattr(self, "_closing", False):
            return
        self._auto_fit_monitor(reason="startup")
        self.after(500, self._auto_fit_startup_content)

    def _auto_fit_startup_content(self):
        if getattr(self, "_closing", False):
            return
        self._fit_to_content(persist=True)

    def _schedule_duplicate_guard(self):
        if self._closing or not _IS_WIN:
            return
        if _test_disable_duplicate_guard():
            return
        if getattr(self, "_duplicate_guard_job", None) is not None:
            return
        try:
            self._duplicate_guard_job = self.after(
                12000, self._duplicate_guard_tick)
        except tk.TclError:
            self._duplicate_guard_job = None

    def _duplicate_guard_tick(self):
        self._duplicate_guard_job = None
        if self._closing or not _IS_WIN:
            return
        if self._duplicate_guard_running:
            self._schedule_duplicate_guard()
            return
        self._duplicate_guard_running = True

        def work():
            ok = True
            msg = ""
            try:
                ok, msg = _cleanup_duplicate_rcm_processes(
                    self._log,
                    should_continue=lambda: not self._closing)
            except Exception as exc:
                ok = False
                msg = f"duplicate guard failed: {type(exc).__name__}: {exc}"

            def apply():
                self._duplicate_guard_running = False
                if self._closing:
                    return
                if msg and msg != "no duplicate RCM processes":
                    self._queue_radio_notice("DUPLICATE RCM :: " + msg)
                if not ok:
                    self._set_diag(
                        "WARN",
                        "DIAG WARN multiple RCM processes",
                        "NEXT Run current RCM as admin or close old RCM in Task Manager.",
                        display_line1="LOG WARN " + msg)
                self._schedule_duplicate_guard()

            self._post(apply)

        threading.Thread(target=work, daemon=True,
                         name="DuplicateRcmGuard").start()

    def _sync_watchdog_runtime(self):
        """Keep the role-specific worker/head recovery guard in sync."""
        want = (self.role == "worker"
                and not self.controller_only
                and self.cfg.get("watchdog_enabled", True))
        if _test_disable_watchdog():
            want = False
        cur = getattr(self, "_watchdog", None)
        if want:
            interval = int(self.cfg.get("watchdog_interval_sec", 60))
            watchdog_current = (
                cur is not None and cur.is_alive()
                and cur.cfg is self.cfg
                and cur.base_interval == max(20, interval))
            if not watchdog_current:
                if cur is not None:
                    cur.stop()
                self._watchdog = WorkerWatchdog(
                    self.controller, self.cfg, self._log,
                    interval=interval)
                self._watchdog.start()
                self._log(
                    f"watchdog: enabled (base "
                    f"{self._watchdog.base_interval}s, backoff cap 10x)")
        else:
            if cur is not None:
                try:
                    cur.stop()
                except Exception as exc:
                    self._log(f"watchdog stop error: {exc}")
                self._watchdog = None
                self._log("watchdog: disabled")

        want_head_guard = (
            self.role == "head"
            and not self.controller_only
            and bool(self.cfg.get("head_dashboard_guard_enabled", True)))
        if _test_disable_watchdog():
            want_head_guard = False
        guard = getattr(self, "_head_guard", None)
        guard_interval = max(
            1.0, float(
                self.cfg.get("head_dashboard_guard_interval_sec", 20)))
        guard_cycles = max(
            1, int(self.cfg.get("head_dashboard_guard_cycles", 3)))
        if want_head_guard:
            if (guard is not None and guard.is_alive()
                    and guard.cfg is self.cfg
                    and guard.base_interval == guard_interval
                    and guard.required_cycles == guard_cycles):
                return
            if guard is not None:
                guard.stop()
            self._head_guard = HeadDashboardGuard(
                self.controller, self.cfg, self._log,
                on_trouble=self._record_guard_trouble,
                interval=guard_interval, cycles=guard_cycles)
            self._head_guard.start()
            self._log(
                "dashboard guard: enabled "
                f"({guard_cycles} × {guard_interval:g}s, "
                "backoff cap 10x)")
        elif guard is not None:
            try:
                guard.stop()
            except Exception as exc:
                self._log(f"dashboard guard stop error: {exc}")
            self._head_guard = None
            self._log("dashboard guard: disabled")

    def _record_guard_trouble(self, message: str):
        try:
            _append_log_record(
                TROUBLE_LOG_PATH,
                time.strftime("%Y-%m-%d %H:%M:%S ")
                + f"[WARN] {message}\n\n")
        except Exception:
            pass

    def _sync_metrics_runtime(self):
        """Keep the local 8866 server/poller aligned with Settings changes.

        Temperature polling is optional and can require admin privileges.
        OS CPU/RAM metrics only need the HTTP server and psutil, so keep the
        server alive when metrics are enabled even if temperature is disabled.
        """
        if not _HAS_TEMPS_SERVER:
            self._log(f"metrics server unavailable: {_temps_server_import_error}")
            return
        if getattr(self, "_metrics_retry_job", None) is not None:
            try:
                self.after_cancel(self._metrics_retry_job)
            except Exception:
                pass
            self._metrics_retry_job = None

        temp_on = bool(self.cfg.get("temp_enabled", True)) and not self.controller_only
        metrics_on = bool(self.cfg.get("metrics_enabled", True)) and not self.controller_only
        want_server = needs_rcm_control_server(self.cfg, self.controller_only)
        port = int(self.cfg.get("temp_port", 8866))
        poll_sec = max(0.5, float(self.cfg.get("temp_poll_sec", 2.0)))

        if temp_on and _HAS_SENSOR:
            if (not getattr(self, "_temp_polling", False)
                    or getattr(self, "_temp_poll_sec", None) != poll_sec):
                try:
                    if getattr(self, "_temp_polling", False):
                        sensor_poller.stop_background_poll()
                    sensor_poller.start_background_poll(interval_sec=poll_sec)
                    self._temp_polling = True
                    self._temp_poll_sec = poll_sec
                    self._log(f"sensor_poller: running ({poll_sec}s)")
                except Exception as exc:
                    self._log(f"sensor_poller start error: {exc}")
        elif temp_on and not _HAS_SENSOR:
            if getattr(self, "_temp_polling", False):
                self._temp_polling = False
                self._temp_poll_sec = None
            self._log(f"sensor_poller unavailable: {_sensor_import_error}")
        elif getattr(self, "_temp_polling", False):
            try:
                if _HAS_SENSOR:
                    sensor_poller.stop_background_poll()
            except Exception as exc:
                self._log(f"sensor_poller stop error: {exc}")
            self._temp_polling = False
            self._temp_poll_sec = None
            self._log("sensor_poller: stopped (temperature monitoring disabled)")

        current_port = getattr(self, "_temp_srv_port", None)
        if self._temp_srv and (not want_server or current_port != port):
            try:
                self._temp_srv.stop()
            except Exception as exc:
                self._log(f"metrics server stop error: {exc}")
            self._temp_srv = None
            self._temp_srv_port = None

        if want_server and self._temp_srv is None:
            try:
                self._temp_srv = temps_server.TempsServer(
                    port=port,
                    bind="127.0.0.1",
                    health_provider=self._health_snapshot)
                self._temp_srv.start()
                self._temp_srv_port = port
                if self._temp_srv.wait_ready(timeout=2.0):
                    self._log(
                        f"metrics server: http://127.0.0.1:{port}/metrics")
                else:
                    self._log(f"metrics server FAILED: {self._temp_srv.error}")
                    try:
                        self._temp_srv.stop()
                        self._temp_srv.join(timeout=1.0)
                    except Exception:
                        pass
                    self._temp_srv = None
                    self._temp_srv_port = None
                    if not self._closing:
                        self._metrics_retry_job = self.after(
                            15000, self._sync_metrics_runtime)
            except Exception as exc:
                self._temp_srv = None
                self._temp_srv_port = None
                self._log(f"metrics server init error: {exc}")
                if not self._closing:
                    self._metrics_retry_job = self.after(
                        15000, self._sync_metrics_runtime)
        elif not want_server:
            self._log("metrics server: stopped (metrics and temperature disabled)")

    def _check_auto_pause(self, view):
        """v1.3.1: auto-pause + K-cycle rearm hysteresis + controller.auto_paused
        flag for watchdog coordination.
        - critical 도달 시 1회 ray stop 발화, controller.auto_paused=True
        - K(=5) 연속 cycle 모든 노드 < warn 이어야 재 arm (flap 방지)"""
        if (not self.cfg.get("temp_auto_pause", False)
                or not self.cfg.get("temp_enabled", True)):
            self._auto_pause_fired = False
            self._cool_streak = 0
            self.controller.auto_paused = False
            return
        crit = float(self.cfg.get("temp_critical_c", 100))
        warn = float(self.cfg.get("temp_warn_c", 80))
        # Auto-pause stops local Ray, so only local temperature may trigger it.
        local_nodes = [n for n in view.nodes if n.is_this]
        hot = []
        any_known = False
        all_cool = True
        for n in local_nodes:
            v = n.temp_cpu_max if n.temp_cpu_max is not None else n.temp_cpu_pkg
            if v is None:
                continue
            any_known = True
            if v >= crit:
                hot.append((n.name or n.ip, v))
            if v >= warn:
                all_cool = False
        # 재 arm: K(=5) 연속 cycle 모든 노드 < warn (~10s @ 2s poll)
        if self._auto_pause_fired and any_known and all_cool:
            self._cool_streak += 1
            if self._cool_streak >= 5:
                self._auto_pause_fired = False
                self._cool_streak = 0
                self.controller.auto_paused = False
                self._log("AUTO-PAUSE: rearmed (5 cycles < warn)")
        else:
            self._cool_streak = 0
        # 신규 발화
        if hot and not self._auto_pause_fired and not self._busy:
            self._auto_pause_fired = True
            self.controller.auto_paused = True
            names = ", ".join(f"{n}={int(round(t))}°C" for n, t in hot)
            self._log(f"AUTO-PAUSE: {names} ≥ {int(crit)}°C — stopping local ray")
            threading.Thread(target=self.controller.stop, daemon=True).start()

    # ------------------------------------------------------------------
    def _post(self, fn):
        self._ui_q.put(fn)

    def _drain_ui_q(self):
        if self._closing:
            return
        try:
            while True:
                fn = self._ui_q.get_nowait()
                try: fn()
                except tk.TclError: continue   # keep pump alive (P0-fix)
                except Exception as exc: print("ui task error:", exc)
        except queue.Empty:
            pass
        if not self._closing:
            self.after(25, self._drain_ui_q)

    # ------------------------------------------------------------------
    def _init_ui_fonts(self):
        """Create semantic named fonts shared by every main-window widget."""
        self._ui_font_specs = {
            "default": dict(family="Tahoma", size=8, weight="normal"),
            "bold": dict(family="Tahoma", size=8, weight="bold"),
            "value": dict(family="Tahoma", size=9, weight="bold"),
            "small": dict(family="Tahoma", size=7, weight="normal"),
            "mono": dict(family="Consolas", size=9, weight="normal"),
            "mono_bold": dict(family="Consolas", size=9, weight="bold"),
            "diag": dict(family=self._diag_font_family(), size=9, weight="normal"),
        }
        self._ui_font_names = {
            "default": "RCMDefaultFont",
            "bold": "RCMBoldFont",
            "value": "RCMValueFont",
            "small": "RCMSmallFont",
            "mono": "RCMMonoFont",
            "mono_bold": "RCMMonoBoldFont",
            "diag": "RCMDiagnosticFont",
        }
        self._ui_fonts = {}
        for role, name in self._ui_font_names.items():
            spec = self._ui_font_specs[role]
            try:
                font = tkfont.Font(root=self, name=name, exists=True)
            except tk.TclError:
                font = tkfont.Font(root=self, name=name, **spec)
            font.configure(**spec)
            self._ui_fonts[role] = font
        self._diag_font = self._ui_fonts["diag"]

    def _font_name(self, role: str) -> str:
        return self._ui_font_names.get(role, "RCMDefaultFont")

    def _refresh_ui_fonts(self):
        """Force every named font to rebuild its pixel metrics at live scale."""
        if not getattr(self, "_ui_fonts", None):
            return
        self._ui_font_specs["diag"]["family"] = self._diag_font_family()
        for role, font in self._ui_fonts.items():
            font.configure(**self._ui_font_specs[role])
        self._diag_font = self._ui_fonts["diag"]
        try:
            self._refresh_diag()
        except Exception:
            pass
        try:
            self._redraw_bar()
        except Exception:
            pass
        for drive in getattr(self, "disk_rows", {}) or {}:
            try:
                self._redraw_disk_bar(drive)
            except Exception:
                pass

    def _refresh_content_fonts(self):
        """Compatibility name retained for release checks and older tests."""
        self._refresh_ui_fonts()

    def _diag_font_family(self) -> str:
        family = str(self.cfg.get("diagnostic_font") or "Consolas")
        return family if family in DIAG_FONT_CHOICES else "Consolas"

    def _diag_font_tuple(self):
        return (self._diag_font_family(), 9)

    def _apply_diag_font(self):
        if not hasattr(self, "diag_canvas"):
            return
        try:
            if getattr(self, "_ui_fonts", None):
                self._ui_font_specs["diag"]["family"] = self._diag_font_family()
                self._ui_fonts["diag"].configure(**self._ui_font_specs["diag"])
                self._diag_font = self._ui_fonts["diag"]
            else:
                self._diag_font = tkfont.Font(root=self, font=self._diag_font_tuple())
            self._refresh_diag()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    def _build_ui(self):
        # v1.3.1: two separate stacked banner labels (admin + ray.exe).
        # v1.3 had a single alert_lbl that raced — non-admin banner was
        # silently clobbered when _check_ray_exe scan posted pack_forget.
        self.admin_lbl = tk.Label(self, text="", bg=RED, fg=WHITE,
                                  font=self._font_name("bold"))
        self.admin_lbl.pack(fill="x", side="top")
        self.admin_lbl.pack_forget()
        self.ray_lbl = tk.Label(self, text="", bg=RED, fg=WHITE,
                                font=self._font_name("bold"))
        self.ray_lbl.pack(fill="x", side="top")
        self.ray_lbl.pack_forget()
        # Back-compat alias for older code paths
        self.alert_lbl = self.ray_lbl

        # --- header line: identity ------------------------------------
        head = tk.Frame(self, bg=GRAY)
        head.pack(fill="x", padx=8, pady=(8, 4))
        self._head_frame = head
        identity_role = "CONTROLLER" if self.controller_only else self.role.upper()
        self.id_lbl = tk.Label(head,
            text=f"{identity_role} on {self.ip or 'no-ip'}   "
                 f"({self.cpus} CPU)",
            bg=GRAY, anchor="w", font=self._font_name("bold"))
        self.id_lbl.pack(side="left")
        # v1.1: build/version chip on the right of the header
        tk.Label(head, text=f"v{APP_VERSION} {APP_BUILD_TAG}",
                 bg=GRAY, fg=GRAY_DKR,
                 font=self._font_name("default")).pack(side="right")

        # --- cluster status group box ---------------------------------
        grp1 = tk.LabelFrame(self, text=" Cluster ", bg=GRAY, bd=2,
                             relief="groove", padx=8, pady=6)
        grp1.pack(fill="x", padx=8, pady=4)

        row1 = tk.Frame(grp1, bg=GRAY); row1.pack(fill="x")
        tk.Label(row1, text="Ray:",      bg=GRAY, width=8,
                 anchor="w").pack(side="left")
        self.cpu_lbl = tk.Label(row1, text="-- / --",
                                bg=GRAY, fg=BLACK,
                                font=self._font_name("value"), anchor="w")
        self.cpu_lbl.pack(side="left")
        self.state_lbl = tk.Label(row1, text="",
                                  bg=GRAY, fg=GRAY_DK, anchor="w")
        self.state_lbl.pack(side="left", padx=(8, 0))
        # v1.4.3: OS CPU + CPU temperature live next to Ray CPU.
        self.temp_lbl = tk.Label(row1, text="",
                                 bg=GRAY, fg=BLACK,
                                 font=self._font_name("value"), anchor="e")
        self.temp_lbl.pack(side="right")

        row2 = tk.Frame(grp1, bg=GRAY); row2.pack(fill="x", pady=(2, 4))
        tk.Label(row2, text="Nodes:",    bg=GRAY, width=8,
                 anchor="w").pack(side="left")
        self.nodes_lbl = tk.Label(row2, text="-- / -- connected",
                                  bg=GRAY, fg=BLACK, anchor="w")
        self.nodes_lbl.pack(side="left")
        self.sys_lbl = tk.Label(row2, text="",
                                bg=GRAY, fg=BLACK, anchor="e")
        self.sys_lbl.pack(side="right")

        row3 = tk.Frame(grp1, bg=GRAY); row3.pack(fill="x", pady=(0, 4))
        tk.Label(row3, text="Net:", bg=GRAY, width=8,
                 anchor="w").pack(side="left")
        self.net_lbl = tk.Label(row3, text="--",
                                bg=GRAY, fg=BLACK, anchor="w")
        self.net_lbl.pack(side="left", fill="x", expand=True)

        # v1.5: black status board replaces the low-value percent bar.
        diag_wrap = tk.Frame(grp1, bg=GRAY_DK, bd=1, relief="sunken")
        diag_wrap.pack(fill="x", pady=(2, 0))
        self.diag_canvas = tk.Canvas(diag_wrap, height=52, bg=BLACK,
                                     bd=0, relief="flat",
                                     highlightthickness=0)
        self.diag_canvas.pack(fill="x")
        self.diag_canvas.bind("<Configure>", lambda _e: self._refresh_diag())
        self._bar_pct = 0.0
        self._bar_color = BLUE98

        # --- connected nodes list -------------------------------------
        grp2 = tk.LabelFrame(self, text=" Connected nodes ", bg=GRAY,
                             bd=2, relief="groove", padx=4, pady=4)
        grp2.pack(fill="both", expand=True, padx=8, pady=4)

        nodes_head = tk.Frame(grp2, bg=GRAY)
        nodes_head.pack(fill="x")
        self.btn_rdp = tk.Button(nodes_head, text="RDP", width=5,
                                 command=self._open_rdp,
                                 state="disabled")
        self.btn_rdp.pack(side="right", padx=(4, 0), pady=(0, 1))
        self.nodes_header = tk.Label(
            nodes_head,
            text=self._node_row_header(show_metrics=True),
            bg=GRAY, fg=GRAY_DKR, anchor="w", font=self._font_name("mono"))
        self.nodes_header.pack(side="left", fill="x", expand=True)

        list_wrap = tk.Frame(grp2, bg=GRAY_DK)
        list_wrap.pack(fill="both", expand=True)
        self.nodes_list_wrap = list_wrap
        self.nodes_list = tk.Listbox(list_wrap, font=self._font_name("mono"),
                                     bg=WHITE, fg=BLACK,
                                     selectmode="single", relief="flat",
                                     bd=0, highlightthickness=0,
                                     activestyle="none", height=5)
        sb = tk.Scrollbar(list_wrap, orient="vertical",
                          command=self.nodes_list.yview)
        xsb = tk.Scrollbar(list_wrap, orient="horizontal",
                           command=self.nodes_list.xview)
        self.nodes_vscroll = sb
        self.nodes_hscroll = xsb
        self.nodes_list.configure(yscrollcommand=sb.set,
                                  xscrollcommand=xsb.set)
        sb.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")
        self.nodes_list.pack(side="left", fill="both", expand=True)
        self.nodes_list.bind("<<ListboxSelect>>", self._on_node_select)

        # --- action button row ----------------------------------------
        btnrow = tk.Frame(self, bg=GRAY)
        self.btnrow = btnrow
        self._btnrow_outer_pad_x = 8
        btnrow.pack(fill="x", side="bottom", padx=self._btnrow_outer_pad_x,
                    pady=(0, 2))
        primary_row = tk.Frame(btnrow, bg=GRAY)
        primary_row.pack(fill="x")
        utility_row = tk.Frame(btnrow, bg=GRAY)
        utility_row.pack(fill="x", pady=(3, 0))

        bw = 8  # button width in chars
        start_txt = "Start" if self.role == "head" else "Join"
        self.btn_start = tk.Button(primary_row, text=start_txt, width=bw,
                                   command=self._do_start)
        self.btn_start.pack(side="left", padx=(0, 4))
        self.btn_stop = tk.Button(primary_row, text="Stop", width=bw,
                                  command=self._do_stop)
        self.btn_stop.pack(side="left", padx=4)
        self.btn_restart = tk.Button(primary_row, text="Restart", width=bw,
                                     command=self._do_restart)
        self.btn_restart.pack(side="left", padx=4)
        self.btn_reset = tk.Button(primary_row, text="Reset", width=bw,
                                   command=self._do_reset)
        self.btn_reset.pack(side="left", padx=4)
        self.btn_repair = tk.Button(primary_row, text="Repair", width=bw,
                                    command=self._do_repair)
        self.btn_repair.pack(side="left", padx=4)
        if self.controller_only:
            self.btn_start.configure(text="Controller", state="disabled")
            for button in (self.btn_stop, self.btn_restart,
                           self.btn_reset, self.btn_repair):
                button.configure(state="disabled")
        tk.Button(primary_row, text="Dashboard", width=9,
                  command=self._open_dashboard).pack(side="left", padx=4)
        tk.Button(
            utility_row, text="Cleanup...", width=11,
            command=self._open_process_cleanup).pack(side="left")
        tk.Button(utility_row, text="Settings...", width=12,
                  command=self._open_settings).pack(side="right")
        self.btn_fleet_update = tk.Button(
            utility_row, text="Update Fleet", width=11,
            command=self._do_fleet_update)
        self.btn_fleet_update.pack(side="right", padx=(4, 0))
        tk.Button(utility_row, text="Logs...", width=8,
                  command=self._open_logs).pack(side="right", padx=(4, 0))
        # v1.5.33 [fitscreen]: packed AFTER Logs... so it lands to its LEFT.
        tk.Button(utility_row, text="Fit Screen", width=10,
                  command=self._do_fit_monitor).pack(side="right", padx=(4, 0))

    def _redraw_bar(self):
        if not hasattr(self, "bar_canvas"):
            return
        c = self.bar_canvas
        c.delete("all")
        w = c.winfo_width()
        h = c.winfo_height()
        if w <= 2 or h <= 2:
            return
        fw = max(0, int((w - 2) * self._bar_pct))
        if fw > 0:
            c.create_rectangle(1, 1, 1 + fw, h - 1,
                               fill=self._bar_color, outline="")
        # classic Win98-style centered percentage text (like Defrag)
        c.create_text(w // 2, h // 2 + 1,
                      text=f"{int(self._bar_pct * 100)}%",
                      fill=GRAY_DKR, font=self._font_name("small"))

    def _set_diag(self, severity: str, line1: str, line2: str = "",
                  display_line1: Optional[str] = None):
        if display_line1 is None:
            display_line1 = line1 or ""
        key = (severity, line1 or "", line2 or "", display_line1 or "")
        if key != getattr(self, "_diag_ticker_key", None):
            self._diag_ticker_offset = 0
            self._diag_ticker_key = key
        self._diag_raw = (severity, line1 or "", line2 or "")
        self._diag_log_line = display_line1 or line1 or ""
        self._refresh_diag()
        self._record_trouble_event(severity, line1 or "", line2 or "")

    def _record_trouble_event(self, severity: str, line1: str, line2: str = ""):
        if severity not in ("WARN", "ERR"):
            return
        diag_key = (line1 or "").split("|", 1)[0].strip()
        key = (severity, diag_key)
        now = time.time()
        if key == self._last_trouble_key and now - self._last_trouble_ts < 180:
            return
        self._last_trouble_key = key
        self._last_trouble_ts = now
        try:
            head_ip = str(self.cfg.get("head_ip") or "")
            head_port = int(self.cfg.get("head_port") or 6379)
            dash_port = int(self.cfg.get("dashboard_port") or 8265)
            temp_port = int(self.cfg.get("temp_port") or 8866)
            ray_path = find_ray_exe(self.cfg.get("ray_exe", "auto")) or "<not found>"
            gcs_open = _tcp_open(head_ip, head_port)
            dash_open = _tcp_open(head_ip, dash_port)
            metrics_open = _tcp_open("127.0.0.1", temp_port)
            rcm_count = _process_count("RayClusterManager.exe")
            raylet_count = _process_count("raylet.exe")
            gcs_count = _process_count("gcs_server.exe")
            view = self._last_view
            if view is None:
                view_summary = "view=<none>"
                node_lines = []
            else:
                view_summary = (
                    f"reachable={view.reachable} stale={view.stale} "
                    f"ray_cpu={view.used_cpu}/{view.total_cpu} "
                    f"nodes={view.alive_nodes}/{len(view.nodes)} "
                    f"error={view.error!r}")
                node_lines = []
                for n in view.nodes[:8]:
                    temp = n.temp_cpu_pkg if n.temp_cpu_pkg is not None else n.temp_cpu_max
                    metric_age_value = getattr(n, "metrics_age_sec", None)
                    metric_age = (
                        f"{metric_age_value:.1f}s"
                        if metric_age_value is not None else "--")
                    node_lines.append(
                        f"    - {n.name or n.hostname or n.ip}: "
                        f"ip={n.ip} alive={n.alive} head={n.is_head} "
                        f"ray={n.cpu_used}/{n.cpu} cpu={n.os_cpu_pct} "
                        f"temp={temp} ram={n.ram_used_gb}/{n.ram_total_gb} "
                        f"metrics_error={n.metrics_error or '--'} "
                        f"metrics_age={metric_age}")
            recent = _current_session_log(_tail_text(LOG_PATH, max_bytes=12000))
            recent_lines = recent.splitlines()[-30:]
            record = [
                time.strftime("%Y-%m-%d %H:%M:%S ")
                + f"[{severity}] RCM_DIAG_EVENT\n",
                f"diagnosis: {line1.strip()}\n",
            ]
            if line2:
                record.append(f"next: {line2.strip()}\n")
            record.extend([
                f"context: version={APP_VERSION} build={APP_BUILD_DATE} "
                f"role={self.role} local_ip={self.ip} "
                f"local_cpus={self.cpus}\n",
                f"config: head={head_ip}:{head_port} "
                f"dashboard={head_ip}:{dash_port} "
                f"metrics=127.0.0.1:{temp_port} ray_exe={ray_path}\n",
                f"ports: gcs_open={gcs_open} dashboard_open={dash_open} "
                f"metrics_open={metrics_open}\n",
                f"processes: RCM={rcm_count} raylet={raylet_count} "
                f"gcs_server={gcs_count}\n",
                f"cluster_view: {view_summary}\n",
            ])
            if node_lines:
                record.extend(["nodes:\n", "\n".join(node_lines) + "\n"])
            if recent_lines:
                record.append("recent_ray_monitor_log_tail:\n")
                record.extend(f"    {line}\n" for line in recent_lines)
            record.append("\n")
            _append_log_record(TROUBLE_LOG_PATH, "".join(record))
        except Exception:
            pass

    def diagnostic_snapshot_text(self) -> str:
        try:
            severity, line1, line2 = self._diag_raw
        except Exception:
            severity, line1, line2 = ("", "", "")
        head_ip = str(self.cfg.get("head_ip") or "")
        head_port = int(self.cfg.get("head_port") or 6379)
        dash_port = int(self.cfg.get("dashboard_port") or 8265)
        temp_port = int(self.cfg.get("temp_port") or 8866)
        ray_path = find_ray_exe(self.cfg.get("ray_exe", "auto")) or "<not found>"
        view = self._last_view
        rows = [
            f"RCM v{APP_VERSION} build {APP_BUILD_DATE} {APP_BUILD_TAG}",
            f"binary: {current_binary_path()}",
            f"sha256: {file_sha256(current_binary_path())}",
            f"role: {self.role}  local_ip: {self.ip}  cpus: {self.cpus}",
            f"ray.exe: {ray_path}",
            f"diag: [{severity}] {line1}",
            f"board_line1: {getattr(self, '_diag_log_line', '')}",
        ]
        if line2:
            rows.append(f"next: {line2}")
        rows.extend([
            f"head: {head_ip}:{head_port}",
            f"dashboard: http://{head_ip}:{dash_port}",
            f"metrics: local :{temp_port}",
            f"ports: gcs={_tcp_open(head_ip, head_port)} "
            f"dashboard={_tcp_open(head_ip, dash_port)} "
            f"metrics={_tcp_open('127.0.0.1', temp_port)}",
        ])
        if view is None:
            rows.append("cluster: <no view yet>")
        else:
            rows.append(
                f"cluster: reachable={view.reachable} stale={view.stale} "
                f"ray={view.used_cpu}/{view.total_cpu} "
                f"nodes={view.alive_nodes}/{len(view.nodes)} "
                f"error={view.error!r}")
            if view.net_down_bps is not None:
                rows.append(
                    f"net all: down={self._rate_text(view.net_down_bps)} "
                    f"up={self._rate_text(view.net_up_bps)} "
                    f"used={self._bytes_text(view.net_down_total_bytes)}/"
                    f"{self._bytes_text(view.net_up_total_bytes)} "
                    f"duration={self._duration_text(view.net_uptime_sec)}")
            rows.append("nodes:")
            for n in view.nodes[:12]:
                temp = n.temp_cpu_max if n.temp_cpu_max is not None else n.temp_cpu_pkg
                metric_age_value = getattr(n, "metrics_age_sec", None)
                metric_age = (
                    f"{metric_age_value:.1f}s"
                    if metric_age_value is not None else "--")
                rows.append(
                    f"  - {n.name or n.hostname or n.ip}: ip={n.ip} "
                    f"alive={n.alive} role={'head' if n.is_head else 'worker'} "
                    f"ray={n.cpu_used}/{n.cpu} cpu={n.os_cpu_pct} "
                    f"ram={n.ram_used_gb}/{n.ram_total_gb} temp={temp} "
                    f"net={self._rate_text(n.net_down_bps)}/"
                    f"{self._rate_text(n.net_up_bps)} "
                    f"uptime={self._duration_text(n.metrics_uptime_sec)} "
                    f"conn={n.conn_label or '--'} "
                    f"metrics_error={n.metrics_error or '--'} "
                    f"metrics_age={metric_age}")
        return "\n".join(rows)

    def _fit_diag_line(self, line: str, pixel_width: int) -> str:
        line = (line or "").replace("\r", " ").replace("\n", " ").strip()
        if not line:
            return ""
        try:
            if self._diag_font is None:
                self._diag_font = tkfont.Font(
                    root=self, font=self._diag_font_tuple())
            measure = self._diag_font.measure
            if measure(line) <= pixel_width:
                return line
            ell = "..."
            if measure(ell) >= pixel_width:
                return ell
            lo, hi = 0, len(line)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                candidate = line[:mid].rstrip() + ell
                if measure(candidate) <= pixel_width:
                    lo = mid
                else:
                    hi = mid - 1
            return (line[:lo].rstrip() + ell) if lo > 0 else ell
        except tk.TclError:
            return line[:96]

    def _clip_diag_line(self, line: str, pixel_width: int) -> str:
        line = (line or "").replace("\r", " ").replace("\n", " ").strip()
        if not line:
            return ""
        try:
            if self._diag_font is None:
                self._diag_font = tkfont.Font(
                    root=self, font=self._diag_font_tuple())
            measure = self._diag_font.measure
            if measure(line) <= pixel_width:
                return line
            lo, hi = 0, len(line)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if measure(line[:mid]) <= pixel_width:
                    lo = mid
                else:
                    hi = mid - 1
            return line[:lo].rstrip()
        except tk.TclError:
            return line[:96]

    def _duration_text(self, seconds) -> str:
        if seconds is None:
            return "--"
        try:
            secs = max(0, int(float(seconds)))
        except Exception:
            return "--"
        if secs < 60:
            return f"{secs}s"
        mins = secs // 60
        if mins < 60:
            return f"{mins}m"
        hours = mins // 60
        rem_m = mins % 60
        if hours < 24:
            return f"{hours}h{rem_m:02d}m"
        days = hours // 24
        rem_h = hours % 24
        return f"{days}d{rem_h}h"

    def _diag_info_text(self) -> str:
        view = self._last_view
        if view is None or not view.reachable:
            return f"RCM v{APP_VERSION} waiting for dashboard | Conn local probe active"
        parts = [
            f"Ray {int(round(view.used_cpu))}/{int(round(view.total_cpu))} CPU",
            f"Nodes {view.alive_nodes}/{len(view.nodes)}",
        ]
        if view.net_down_bps is not None:
            used = (
                f"{self._bytes_text(view.net_down_total_bytes)}/"
                f"{self._bytes_text(view.net_up_total_bytes)}")
            duration = self._duration_text(view.net_uptime_sec)
            parts.append(f"Used {used} {duration}")
        conn = ""
        for n in view.nodes:
            if n.is_this and n.conn_label:
                conn = n.conn_label
                break
        if not conn:
            for n in view.nodes:
                if n.alive and n.conn_label:
                    conn = n.conn_label
                    break
        if conn:
            parts.append(f"Conn {conn}")
        return " | ".join(parts)

    def _diag_tip_text(self) -> str:
        tips = (
            "Tip Reset clears local Ray state and keeps RCM open.",
            "Fact Tailscale 100.x IPs stay stable across Wi-Fi changes.",
            "Tip Dashboard can lag a little after Ray runtime starts.",
            "All quiet on the cluster front.",
            "Tip Fixed worker ports make firewall checks less mysterious.",
            "Ray nodes report OS metrics through the tiny RCM :8866 server.",
        )
        try:
            return tips[int(time.time() // 20) % len(tips)]
        except Exception:
            return tips[0]

    def _scroll_diag_line(self, text: str, pixel_width: int) -> str:
        text = (text or "").replace("\r", " ").replace("\n", " ").strip()
        if not text:
            return ""
        try:
            if self._diag_font is None:
                self._diag_font = tkfont.Font(
                    root=self, font=self._diag_font_tuple())
            measure = self._diag_font.measure
            if measure(text) <= pixel_width:
                return text
            char_w = max(1, int(measure("M") or 8))
            visible = max(8, int(pixel_width / char_w) + 3)
            source = "   " + text + "   "
            offset = int(getattr(self, "_diag_ticker_offset", 0)) % len(source)
            chunk = (source[offset:] + source[:offset] + source)[:visible]
            return self._clip_diag_line(chunk, pixel_width)
        except tk.TclError:
            return text[:96]

    def _next_board_line(self) -> str:
        feed = getattr(self, "_board_feed", None)
        if feed is not None:
            try:
                line = str(feed.next_line() or "").strip()
                if line:
                    return line
            except Exception:
                pass
        return "RCM RADIO :: the black rectangle is warming up its pixels."

    def _radio_head(self, text: str) -> str:
        text = (text or "").strip()
        if not text:
            return ""
        if "::" in text:
            text = text.split("::", 1)[0].strip()
        return text.split(" ", 1)[0].upper()

    def _next_radio_segment(self) -> str:
        for _ in range(8):
            line = self._next_board_line()
            head = self._radio_head(line)
            if head and head in self._radio_recent_heads[-2:]:
                continue
            self._radio_recent_heads.append(head)
            self._radio_recent_heads = self._radio_recent_heads[-6:]
            return line
        line = self._next_board_line()
        head = self._radio_head(line)
        if head:
            self._radio_recent_heads.append(head)
            self._radio_recent_heads = self._radio_recent_heads[-6:]
        return line

    def _next_board_scene(self):
        feed = getattr(self, "_board_feed", None)
        if feed is not None:
            try:
                return feed.next_scene()
            except Exception:
                return None
        return None

    def _current_board_scene(self):
        now = time.time()
        if getattr(self, "_board_scene", None) is None:
            self._board_scene = self._next_board_scene()
            self._board_scene_ts = now
            self._board_prev_scene = None
            self._board_scene_transition_start = 0.0
        elif (self._board_prev_scene is None
              and now - self._board_scene_ts >= self._board_scene_hold_sec):
            nxt = self._next_board_scene()
            if nxt is not None:
                self._board_prev_scene = self._board_scene
                self._board_scene = nxt
                self._board_scene_ts = now
                self._board_scene_transition_start = now
        return self._board_scene

    def _board_scene_transition_progress(self) -> float:
        if self._board_prev_scene is None:
            return 1.0
        try:
            elapsed = time.time() - float(self._board_scene_transition_start or 0.0)
            progress = elapsed / max(0.2, float(self._board_scene_transition_sec))
        except Exception:
            progress = 1.0
        if progress >= 1.0:
            self._board_prev_scene = None
            self._board_scene_transition_start = 0.0
            return 1.0
        return max(0.0, min(1.0, progress))

    def _draw_pixel_scene(self, canvas, scene, x: int, y: int,
                          line_h: int, color: str) -> int:
        if scene is None:
            return 0
        try:
            frames = getattr(scene, "frames", None) or ()
            if not frames:
                return 0
            frame = frames[(int(self._diag_ticker_offset) // 2) % len(frames)]
            rows = [str(row) for row in frame]
            if not rows:
                return 0
            dot = 4
            gap = 1
            cols = max(len(row) for row in rows)
            sprite_h = len(rows) * dot + max(0, len(rows) - 1) * gap
            top = y + max(0, (line_h - sprite_h) // 2)
            primary = getattr(scene, "color", None) or color
            accent = getattr(scene, "accent", None) or "#40c0ff"
            for r, row in enumerate(rows):
                for c, ch in enumerate(row.ljust(cols)):
                    if ch == " ":
                        continue
                    fill = accent if ch in ("o", "O", "*", "#", "@") else primary
                    x0 = x + c * (dot + gap)
                    y0 = top + r * (dot + gap)
                    canvas.create_rectangle(
                        x0, y0, x0 + dot - 1, y0 + dot - 1,
                        fill=fill, outline=fill)
            return cols * dot + max(0, cols - 1) * gap
        except tk.TclError:
            return 0

    def _draw_board_scene_line(self, canvas, x: int, y: int,
                               line_h: int, color: str, pixel_width: int):
        scene = self._current_board_scene()
        prev = getattr(self, "_board_prev_scene", None)
        progress = self._board_scene_transition_progress()
        sprite_w = 0
        if prev is not None and progress < 1.0:
            slide = 34
            old_x = x - int(progress * slide)
            new_x = x + int((1.0 - progress) * slide)
            sprite_w = max(
                self._draw_pixel_scene(canvas, prev, old_x, y, line_h, "#806800"),
                self._draw_pixel_scene(canvas, scene, new_x, y, line_h, color),
            )
            scan_x = x + int(max(0, pixel_width - 1) * progress)
            canvas.create_line(scan_x, y, scan_x, y + line_h,
                               fill="#40c0ff", width=1)
            caption = getattr(scene, "caption", "") or "pixels tuning the next scene"
            caption = f"tuning pixels... {caption}"
        else:
            sprite_w = self._draw_pixel_scene(canvas, scene, x, y, line_h, color)
            caption = getattr(scene, "caption", "") if scene is not None else ""
        if not caption:
            caption = "pixels holding a tiny scene before the next handoff"
        caption_x = x + sprite_w + (8 if sprite_w else 0)
        caption_w = max(32, pixel_width - (caption_x - x))
        caption = self._clip_diag_line(caption, caption_w)
        canvas.create_text(caption_x, y, anchor="nw", text=caption,
                           fill="#d0a000", font=self._diag_font)

    def _measure_diag_text(self, text: str) -> int:
        try:
            if self._diag_font is None:
                self._diag_font = tkfont.Font(
                    root=self, font=self._diag_font_tuple())
            return int(self._diag_font.measure(text or ""))
        except tk.TclError:
            return max(1, len(text or "") * 8)

    def _radio_segment_limit(self, pixel_width: int) -> int:
        # Generous safety ceiling, NOT a truncation tool. Full content
        # sentences (and queued WARN/ERR notices) render whole and scroll past
        # as a marquee; this only guards a pathological multi-thousand-char
        # line from blowing up font.measure or letting one notice monopolise
        # the ribbon forever.
        return max(1600, int(max(1, pixel_width) * 4))

    def _radio_segment_display(self, text: str, pixel_width: int) -> str:
        text = (text or "").replace("\r", " ").replace("\n", " ")
        text = " ".join(text.split())
        if not text:
            text = "RCM RADIO :: waiting for the next packet of trivia."
        # Show the FULL sentence in natural case; the ribbon scrolls it
        # right-to-left. _clip_diag_line is a no-op for real content at this
        # ceiling and only trims a pathological line.
        return self._clip_diag_line(text, self._radio_segment_limit(pixel_width))

    def _radio_segment_width(self, text: str, pixel_width: int) -> int:
        display = self._radio_segment_display(text, pixel_width)
        return max(1, self._measure_diag_text(display + self._radio_separator))

    def _queue_radio_notice(self, text: str):
        notice = " ".join(str(text or "").split())
        if not notice:
            return
        now = time.time()
        if (notice == self._radio_notice_last
                and now - self._radio_notice_ts < self._radio_notice_cooldown_sec):
            return
        if notice in self._radio_segments:
            return
        self._radio_notice_last = notice
        self._radio_notice_ts = now
        self._radio_segments.append(notice)

    def _ensure_radio_segments(self, pixel_width: int):
        target_w = max(240, pixel_width * 3)
        if not self._radio_segments:
            self._radio_segments.append(self._next_radio_segment())
        width = sum(self._radio_segment_width(s, pixel_width)
                    for s in self._radio_segments)
        while width < target_w:
            self._radio_segments.append(self._next_radio_segment())
            width += self._radio_segment_width(self._radio_segments[-1], pixel_width)

    def _advance_radio_scroll(self, pixel_width: int):
        self._ensure_radio_segments(pixel_width)
        self._radio_scroll_px += 7
        while len(self._radio_segments) > 1:
            first_w = self._radio_segment_width(self._radio_segments[0], pixel_width)
            if self._radio_scroll_px < first_w:
                break
            self._radio_scroll_px -= first_w
            self._radio_segments.pop(0)
        self._ensure_radio_segments(pixel_width)

    def _radio_ribbon_text(self, pixel_width: int) -> str:
        self._ensure_radio_segments(pixel_width)
        return self._radio_separator.join(
            self._radio_segment_display(s, pixel_width)
            for s in self._radio_segments)

    def _draw_radio_ribbon(self, canvas, x: int, y: int, pixel_width: int):
        self._ensure_radio_segments(pixel_width)
        cur_x = x - int(self._radio_scroll_px)
        end_x = x + pixel_width + 32
        sep_w = self._measure_diag_text(self._radio_separator)
        for segment in list(self._radio_segments):
            display = self._radio_segment_display(segment, pixel_width)
            seg_w = self._measure_diag_text(display)
            if cur_x + seg_w >= x - 16:
                canvas.create_text(cur_x, y, anchor="nw", text=display,
                                   fill="#b8d878", font=self._diag_font)
            cur_x += seg_w
            if cur_x >= x - sep_w and cur_x <= end_x:
                canvas.create_text(cur_x, y, anchor="nw",
                                   text=self._radio_separator,
                                   fill="#6f986f", font=self._diag_font)
            cur_x += sep_w
            if cur_x > end_x:
                break

    def _diag_display_lines(self, severity: str, line1: str, line2: str,
                            pixel_width: int) -> tuple[str, str, str]:
        diag = getattr(self, "_diag_log_line", "") or line1 or self._diag_info_text()
        return (
            self._fit_diag_line(diag, pixel_width),
            "",
            "",
        )

    def _schedule_diag_tick(self):
        if self._closing or getattr(self, "_diag_tick_job", None) is not None:
            return
        try:
            self._diag_tick_job = self.after(350, self._diag_tick)
        except tk.TclError:
            self._diag_tick_job = None

    def _diag_tick(self):
        self._diag_tick_job = None
        if self._closing:
            return
        self._diag_ticker_offset += 1
        try:
            width = max(32, self.diag_canvas.winfo_width() - 12)
            self._advance_radio_scroll(width)
        except Exception:
            pass
        self._refresh_diag()

    def _refresh_diag(self):
        severity, line1, line2 = self._diag_raw
        colors = {
            "OK": GREEN,
            "WARN": "#d0a000",
            "ERR": RED,
            "STOP": GRAY_LT,
            "RUN": "#40c0ff",
        }
        fg = colors.get(severity, GREEN)
        try:
            c = self.diag_canvas
            if self._diag_font is None:
                self._diag_font = tkfont.Font(
                    root=self, font=self._diag_font_tuple())
            line_h = max(15, int(self._diag_font.metrics("linespace") or 15))
            wanted_h = max(52, line_h * 3 + 7)
            if int(c.cget("height") or 0) != wanted_h:
                c.configure(height=wanted_h)
            c.delete("all")
            pad_x = 4
            width = max(32, c.winfo_width() - pad_x * 2 - 4)
            fitted1, _scene_line, fitted3 = self._diag_display_lines(
                severity, line1, line2, width)
            y0 = 2
            c.create_text(pad_x, y0, anchor="nw", text=fitted1,
                          fill=fg, font=self._diag_font)
            scene_y = y0 + line_h
            self._draw_board_scene_line(c, pad_x, scene_y, line_h, fg, width)
            if severity not in ("OK", "STOP") and line2:
                priority = str(line2 or "").strip()
                self._queue_radio_notice(priority)
            self._draw_radio_ribbon(c, pad_x, y0 + line_h * 2, width)
        except tk.TclError:
            pass
        self._schedule_diag_tick()

    def _update_diag(self, view: Optional[ClusterView], state: str = ""):
        try:
            recent = _current_session_log(_tail_text(LOG_PATH))
            ray_path = find_ray_exe(self.cfg.get("ray_exe", "auto"))
            now = time.time()
            if now - self._diag_probe_ts > 5:
                head_ip = str(self.cfg.get("head_ip") or "")
                head_port = int(self.cfg.get("head_port") or 6379)
                dash_port = int(self.cfg.get("dashboard_port") or 8265)
                temp_port = int(self.cfg.get("temp_port") or 8866)
                self._diag_probe = (
                    _tcp_open(head_ip, head_port),
                    _tcp_open(head_ip, dash_port),
                    _tcp_open("127.0.0.1", temp_port),
                    _process_count("RayClusterManager.exe"))
                self._diag_probe_ts = now
            gcs_open, dash_open, metrics_open, rcm_count = self._diag_probe
            severity, line1, line2 = diagnose_cluster_state(
                self.cfg, view, recent_log=recent, ray_path=ray_path,
                gcs_open=gcs_open, dash_open=dash_open,
                metrics_open=metrics_open, rcm_count=rcm_count,
                role=self.role)
            if state in ("busy", "maxed") and severity == "OK":
                line2 = "NEXT Cluster is saturated; wait or reduce submitted work."
            display_line1 = _log_status_explanation(
                recent, view, severity, line1, line2,
                bool(gcs_open), bool(dash_open), bool(metrics_open),
                int(rcm_count or 0))
            self._set_diag(severity, line1, line2, display_line1=display_line1)
        except Exception as exc:
            self._set_diag("WARN", "DIAG WARN diagnostic console failed",
                           f"NEXT {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    def _log(self, msg):
        line = time.strftime("[%H:%M:%S] ") + msg
        try: print(line)
        except Exception: pass
        # also persist to a rotating-by-size file (~256 KB cap)
        try:
            _append_log_record(
                LOG_PATH, time.strftime("%Y-%m-%d ") + line + "\n")
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _start_monitor(self):
        if self.monitor:
            self.monitor.stop()
        self._mon_gen += 1
        gen = self._mon_gen
        self.monitor = ClusterMonitor(self.cfg, lambda v: self._on_view(v, gen))
        self.monitor.start()

    def _on_view(self, view, gen=0):
        if gen != self._mon_gen:
            return
        self._post(lambda: self._render(view))

    def _render(self, view: ClusterView):
        if self._closing or not self.cpu_lbl.winfo_exists():
            return
        self._last_view = view

        if not view.reachable or view.total_cpu <= 0:
            state = "offline"
        elif view.used_cpu <= 0:
            state = "idle"
        elif view.used_cpu / view.total_cpu >= 1.0:
            state = "maxed"
        elif view.used_cpu / view.total_cpu >= 0.9:
            state = "busy"
        else:
            state = "running"

        used = int(round(view.used_cpu))
        total = int(round(view.total_cpu))
        pct = (view.used_cpu / view.total_cpu) if view.total_cpu else 0
        alive = view.alive_nodes
        tot_n = len(view.nodes)
        stale = bool(getattr(view, "stale", False))
        busy = bool(getattr(self, "_busy", False))

        if state == "offline":
            self.cpu_lbl.configure(text="-- / --", fg=GRAY_DK)
            if not busy:
                if getattr(view, "gcs_open", None):
                    self.state_lbl.configure(
                        text="(dashboard offline)", fg="#a06000")
                else:
                    self.state_lbl.configure(
                        text="(head unreachable)", fg=RED)
            self.nodes_lbl.configure(text="0 / 0 connected", fg=GRAY_DK)
            self.temp_lbl.configure(text="CPU --", fg=GRAY_DK)
            self.sys_lbl.configure(text="RAM --", fg=GRAY_DK)
            self.net_lbl.configure(text="--", fg=GRAY_DK)
            self._bar_pct = 0; self._bar_color = GRAY_DK
        else:
            self.cpu_lbl.configure(text=f"{used} / {total}", fg=BLACK)
            if not busy:
                if stale:
                    self.state_lbl.configure(text="(refresh retry)", fg="#a06000")
                elif state in ("busy", "maxed"):
                    self.state_lbl.configure(text=f"({state})", fg=RED)
                elif state == "running":
                    self.state_lbl.configure(text=f"({state})", fg=GREEN)
                else:
                    self.state_lbl.configure(text=f"({state})", fg=GRAY_DK)
            self.nodes_lbl.configure(text=f"{alive} / {tot_n} connected",
                                     fg=BLACK)
            self._render_system_summary(view)
            self._bar_pct = min(1.0, pct)
            self._bar_color = (RED if state in ("busy", "maxed")
                               else BLUE98 if state == "running" else GRAY_DK)
        self._redraw_bar()
        if not busy:
            self._update_diag(view, state)
        self._render_nodes(view.nodes)
        self._render_selected_disks()
        if not self._layout_fit_done and view.nodes:
            self._fit_main_geometry(force=True)
            self._layout_fit_done = True
        # v1.1: include max temp + auto-pause check
        tray_extra = ""
        warn = float(self.cfg.get("temp_warn_c", 80))
        crit = float(self.cfg.get("temp_critical_c", 100))
        if view.max_temp_c is not None:
            mt = int(round(view.max_temp_c))
            tray_extra = f" · max {mt}°C"
            color = (RED if view.max_temp_c >= crit
                     else "#a06000" if view.max_temp_c >= warn
                     else BLACK)
        sys_extra = ""
        if self.cfg.get("metrics_enabled", True):
            if view.os_cpu_avg_pct is not None:
                sys_extra += f" · CPU {int(round(view.os_cpu_avg_pct))}%"
            if view.ram_pct is not None:
                sys_extra += f" · RAM {int(round(view.ram_pct))}%"
        tray_state = "refresh retry" if stale else state
        self._refresh_tray_title(f"{used}/{total} Ray CPU · {tray_state}{sys_extra}{tray_extra}")
        self._check_auto_pause(view)

    def _render_system_summary(self, view: ClusterView):
        metrics_on = self.cfg.get("metrics_enabled", True)
        temp_on = self.cfg.get("temp_enabled", True)
        cpu_parts = []
        if metrics_on and view.os_cpu_avg_pct is not None:
            cpu_parts.append(f"CPU {int(round(view.os_cpu_avg_pct))}%")
        elif metrics_on:
            cpu_parts.append("CPU --")
        if temp_on and view.max_temp_c is not None:
            node_part = f" ({view.max_temp_node})" if view.max_temp_node else ""
            cpu_parts.append(f"{int(round(view.max_temp_c))}°C{node_part}")
        elif temp_on:
            cpu_parts.append("Temp --")

        ram_text = "" if not metrics_on else "RAM --"
        if not metrics_on:
            ram_text = ""
        elif view.ram_used_gb is None or view.ram_total_gb is None:
            ram_text = "RAM --"
        elif metrics_on:
            ram_text = (
                f"RAM {int(round(view.ram_used_gb))}/{int(round(view.ram_total_gb))}G")
        cpu_color = BLACK
        ram_color = BLACK
        ram_crit = float(self.cfg.get("ram_critical_pct", 95))
        ram_warn = float(self.cfg.get("ram_warn_pct", 85))
        cpu_crit = float(self.cfg.get("os_cpu_critical_pct", 95))
        cpu_warn = float(self.cfg.get("os_cpu_warn_pct", 80))
        temp_crit = float(self.cfg.get("temp_critical_c", 100))
        temp_warn = float(self.cfg.get("temp_warn_c", 80))
        if ((view.os_cpu_avg_pct is not None and view.os_cpu_avg_pct >= cpu_crit)
                or (view.max_temp_c is not None and view.max_temp_c >= temp_crit)):
            cpu_color = RED
        elif ((view.os_cpu_avg_pct is not None and view.os_cpu_avg_pct >= cpu_warn)
                or (view.max_temp_c is not None and view.max_temp_c >= temp_warn)):
            cpu_color = "#a06000"
        if view.ram_pct is not None and view.ram_pct >= ram_crit:
            ram_color = RED
        elif view.ram_pct is not None and view.ram_pct >= ram_warn:
            ram_color = "#a06000"
        try:
            self.temp_lbl.configure(text="  ".join(cpu_parts), fg=cpu_color)
            if metrics_on and view.g_disk:
                g_text = self._disk_mini_bar(view.g_disk, "G")
                ram_text = f"{ram_text}  {g_text}" if ram_text else g_text
                g_pct = _num_or_none(view.g_disk.get("pct"))
                if g_pct is not None:
                    if g_pct >= float(self.cfg.get("disk_critical_pct", 95)):
                        ram_color = RED
                    elif g_pct >= float(self.cfg.get("disk_warn_pct", 85)) and ram_color != RED:
                        ram_color = "#a06000"
            self.sys_lbl.configure(text=ram_text, fg=ram_color)
            self.net_lbl.configure(
                text=self._cluster_net_text(view, metrics_on=metrics_on),
                fg=(BLACK if view.net_down_bps is not None else GRAY_DK))
        except tk.TclError:
            pass

    def _render_nodes(self, nodes):
        nodes = complete_ray_display_nodes(
            nodes, self.cfg, this_ip=getattr(self, "ip", ""))
        controller_ips = {
            str(item.get("ip") or "").strip()
            for item in self.cfg.get("nodes", []) or []
            if isinstance(item, dict)
            and is_controller_node(item)
        }
        nodes = [n for n in nodes
                 if str(getattr(n, "ip", "") or "").strip() not in controller_ips]
        sel = self.nodes_list.curselection()
        sel_idx = sel[0] if sel else None
        self._displayed_nodes = list(nodes)
        temp_warn = float(self.cfg.get("temp_warn_c", 80))
        temp_crit = float(self.cfg.get("temp_critical_c", 100))
        ram_warn = float(self.cfg.get("ram_warn_pct", 85))
        ram_crit = float(self.cfg.get("ram_critical_pct", 95))
        cpu_warn = float(self.cfg.get("os_cpu_warn_pct", 80))
        cpu_crit = float(self.cfg.get("os_cpu_critical_pct", 95))
        disk_warn = float(self.cfg.get("disk_warn_pct", 85))
        disk_crit = float(self.cfg.get("disk_critical_pct", 95))
        show_metrics = self.cfg.get("metrics_enabled", True)
        # v1.07.16d [flexcols]: responsive column widths from the actual
        # rows about to be rendered (digit-reserved, session-monotonic).
        self._node_cols = self._node_col_widths(nodes, show_metrics)
        try:
            self.nodes_header.configure(
                text=self._node_row_header(show_metrics=show_metrics))
        except tk.TclError:
            pass
        self.nodes_list.delete(0, "end")
        for n in nodes:
            t = n.temp_cpu_max if n.temp_cpu_max is not None else n.temp_cpu_pkg
            disk_pct = self._node_disk_max_pct(n) if show_metrics else None
            line = self._node_row_line(n, t, show_metrics=show_metrics)
            self.nodes_list.insert("end", line)
            idx = self.nodes_list.size() - 1                  # real index (P0-fix)
            if not n.alive:
                self.nodes_list.itemconfigure(idx, foreground=GRAY_DK)
            elif t is not None and t >= temp_crit:
                self.nodes_list.itemconfigure(idx, foreground=RED)
            elif show_metrics and n.ram_pct is not None and n.ram_pct >= ram_crit:
                self.nodes_list.itemconfigure(idx, foreground=RED)
            elif show_metrics and n.os_cpu_pct is not None and n.os_cpu_pct >= cpu_crit:
                self.nodes_list.itemconfigure(idx, foreground=RED)
            elif show_metrics and disk_pct is not None and disk_pct >= disk_crit:
                self.nodes_list.itemconfigure(idx, foreground=RED)
            elif t is not None and t >= temp_warn:
                self.nodes_list.itemconfigure(idx, foreground="#a06000")  # amber
            elif show_metrics and n.ram_pct is not None and n.ram_pct >= ram_warn:
                self.nodes_list.itemconfigure(idx, foreground="#a06000")  # amber
            elif show_metrics and n.os_cpu_pct is not None and n.os_cpu_pct >= cpu_warn:
                self.nodes_list.itemconfigure(idx, foreground="#a06000")  # amber
            elif show_metrics and disk_pct is not None and disk_pct >= disk_warn:
                self.nodes_list.itemconfigure(idx, foreground="#a06000")  # amber
            elif n.is_this:
                self.nodes_list.itemconfigure(idx, foreground=BLUE98)
        if sel_idx is not None and sel_idx < self.nodes_list.size():
            self.nodes_list.selection_set(sel_idx)
        self._update_rdp_button()

    def _node_col_widths(self, nodes, show_metrics=True):
        """v1.07.16d [flexcols]: responsive table columns.

        Widths follow the widest actual cell (header label as the floor)
        instead of fixed generous constants, so at most one space sits
        between the widest cell and each ``|`` separator.  Numeric cells
        additionally reserve every digit count they can legitimately
        reach — Ray sizes for ``total/total`` (used can grow to total),
        RAM for ``total/total`` GB, CPU stays 4 wide (``100%``), the disk
        column keeps its 100%/3-digit-temperature capacity, and ping keeps
        4 digits — so changing digit counts never shift the table.
        Widths are also monotonic within a session (never shrink), which
        prevents refresh-to-refresh jitter.
        """
        widths = {
            "name": len("Node"),
            "ray": len("Ray"),
            "ram": len("RAM"),
            "disk": max(len("Disk C: / SSD"), NODE_DISK_COL_WIDTH),
            "net": NODE_NET_COL_WIDTH,
            "ping": NODE_PING_COL_WIDTH,
            "conn": len("Cn"),
        }
        if show_metrics:
            for n in nodes:
                widths["name"] = max(widths["name"], len(self._node_name(n)))
                total = self._count_text(n.cpu)
                widths["ray"] = max(widths["ray"], len(self._ray_text(n)),
                                    2 * len(total) + 1)
                widths["ram"] = max(widths["ram"], len(self._ram_text(n)))
                if n.ram_total_gb:
                    ram_total = self._gb_text(n.ram_total_gb)
                    widths["ram"] = max(
                        widths["ram"], min(2 * len(ram_total) + 1, 6))
                widths["conn"] = max(widths["conn"],
                                     len(self._node_conn_text(n)))
        previous = getattr(self, "_node_cols", None) or {}
        for key in widths:
            widths[key] = max(widths[key], int(previous.get(key, 0)))
        return widths

    def _node_col(self, key, fallback):
        cols = getattr(self, "_node_cols", None) or {}
        try:
            value = int(cols.get(key, fallback))
        except (TypeError, ValueError):
            return fallback
        return value if value > 0 else fallback

    def _node_row_header(self, show_metrics=True):
        if show_metrics:
            return (f"   {'Node':<{self._node_col('name', NODE_COL_WIDTH)}} "
                    f"R {'Ray':<{self._node_col('ray', NODE_RAY_COL_WIDTH)}} | "
                    f"{'CPU':>4} {'Tmp':>4} | "
                    f"{'RAM':<{self._node_col('ram', NODE_RAM_COL_WIDTH)}} | "
                    f"{'Disk C: / SSD':<{self._node_col('disk', NODE_DISK_COL_WIDTH)}} | "
                    f"{'D/U/s':<{self._node_col('net', NODE_NET_COL_WIDTH)}} | "
                    f"{'Png':<{self._node_col('ping', NODE_PING_COL_WIDTH)}} | "
                    f"{'Cn':<{self._node_col('conn', NODE_CONN_COL_WIDTH)}}")
        return f"   {'Node':<{NODE_COL_WIDTH}} R Ray    Temp"

    def _node_name(self, n):
        base = str(n.name or n.hostname or n.ip or "")
        if n.is_this:
            return base + "(me)"
        if not bool(getattr(n, "registered", True)):
            return base + "*"
        return base

    def _count_text(self, value):
        try:
            v = int(round(float(value)))
        except Exception:
            return "--"
        if v < 1000:
            return str(v)
        return f"{v // 1000}k+"

    def _ray_text(self, n):
        total = self._count_text(n.cpu)
        if not n.alive:
            return f"--/{total}"[:NODE_RAY_COL_WIDTH]
        try:
            if float(n.cpu) == 0.0:
                return "drv"
        except (TypeError, ValueError):
            pass
        return f"{self._count_text(n.cpu_used)}/{total}"[:NODE_RAY_COL_WIDTH]

    def _pct_text(self, value):
        if value is None:
            return "--"
        try:
            v = int(round(float(value)))
        except Exception:
            return "--"
        return f"{min(v, 999)}%"

    def _gb_text(self, value):
        if value is None:
            return "--"
        try:
            v = float(value)
        except Exception:
            return "--"
        if v < 1000:
            return str(int(round(v)))
        return f"{v / 1024:.1f}".rstrip("0").rstrip(".") + "T"

    def _bytes_text(self, value):
        if value is None:
            return "--"
        try:
            v = max(0.0, float(value))
        except Exception:
            return "--"
        units = ("B", "K", "M", "G", "T")
        idx = 0
        while v >= 1024 and idx < len(units) - 1:
            v /= 1024.0
            idx += 1
        if idx == 0:
            return f"{int(round(v))}{units[idx]}"
        if v < 10:
            return f"{v:.1f}{units[idx]}".rstrip("0").rstrip(".")
        return f"{int(round(v))}{units[idx]}"

    def _rate_text(self, bps):
        text = self._bytes_text(bps)
        return "--" if text == "--" else f"{text}/s"

    def _cluster_net_text(self, view, metrics_on=True):
        if not metrics_on:
            return "metrics off"
        if view.net_down_bps is None or view.net_up_bps is None:
            return "All Dn -- Up --  Used --/--"
        down = self._rate_text(view.net_down_bps)
        up = self._rate_text(view.net_up_bps)
        total_down = self._bytes_text(view.net_down_total_bytes)
        total_up = self._bytes_text(view.net_up_total_bytes)
        duration = self._duration_text(view.net_uptime_sec)
        suffix = f" {duration}" if duration != "--" else ""
        return f"All Dn {down} Up {up}  Used {total_down}/{total_up}{suffix}"

    def _node_net_text(self, n):
        if n.net_down_bps is None or n.net_up_bps is None:
            return "--/--"
        return f"{self._bytes_text(n.net_down_bps)}/{self._bytes_text(n.net_up_bps)}"[:NODE_NET_COL_WIDTH]

    def _node_ping_text(self, n):
        # HTTP round-trip time to the node's :8866 metrics endpoint, not ICMP.
        if getattr(n, "is_this", False):
            return "loc"
        ping = getattr(n, "ping_ms", None)
        if ping is None:
            return "--"
        try:
            return str(int(round(float(ping))))[:NODE_PING_COL_WIDTH]
        except (TypeError, ValueError):
            return "--"

    def _node_conn_text(self, n):
        label = str(getattr(n, "conn_label", "") or "").strip()
        if not label:
            return "--"
        return label[:NODE_CONN_COL_WIDTH]

    def _ram_text(self, n):
        if n.ram_used_gb is None or not n.ram_total_gb:
            return "--"
        text = f"{self._gb_text(n.ram_used_gb)}/{self._gb_text(n.ram_total_gb)}"
        return text[:6]

    def _disk_mini_bar(self, data, label, slots=6):
        mark = " "
        if data and data.get("active"):
            mark = "*"
        empty = "-" * slots
        if not data or not data.get("present"):
            return f"{label}{mark}[{empty}]--%"
        pct = _num_or_none(data.get("pct"))
        if pct is None:
            return f"{label}{mark}[{empty}]--%"
        pct_i = max(0, min(100, int(round(pct))))
        fill = int(round(slots * pct_i / 100.0))
        if pct_i > 0:
            fill = max(1, fill)
        fill = max(0, min(slots, fill))
        bar = "#" * fill + "-" * (slots - fill)
        return f"{label}{mark}[{bar}]{pct_i:>2}%"

    def _node_disk_text(self, n):
        data = self._disk_for(n, "C:")
        capacity = self._disk_mini_bar(data, "C", slots=4)
        temp = _num_or_none(data.get("temperature_c")) if data else None
        temp_text = "--°" if temp is None else f"{int(round(temp))}°"
        return f"{capacity} {temp_text}"[:NODE_DISK_COL_WIDTH]

    def _node_disk_max_pct(self, n):
        vals = []
        for drive in ("C:",):
            data = self._disk_for(n, drive)
            if data and data.get("present"):
                pct = _num_or_none(data.get("pct"))
                if pct is not None:
                    vals.append(pct)
        return max(vals) if vals else None

    def _node_row_line(self, n, temp_value, show_metrics=True):
        dot = "●" if n.alive else "○"
        name = self._node_name(n)
        role = "H" if n.is_head else "W"
        ray_text = self._ray_text(n)
        temp_text = " ---" if temp_value is None else f"{int(round(temp_value)):>3}°"
        if show_metrics:
            return (f" {dot} {name:<{self._node_col('name', NODE_COL_WIDTH)}} "
                    f"{role} {ray_text:<{self._node_col('ray', NODE_RAY_COL_WIDTH)}} | "
                    f"{self._pct_text(n.os_cpu_pct):>4} {temp_text} | "
                    f"{self._ram_text(n):<{self._node_col('ram', NODE_RAM_COL_WIDTH)}} | "
                    f"{self._node_disk_text(n):<{self._node_col('disk', NODE_DISK_COL_WIDTH)}} | "
                    f"{self._node_net_text(n):<{self._node_col('net', NODE_NET_COL_WIDTH)}} | "
                    f"{self._node_ping_text(n):<{self._node_col('ping', NODE_PING_COL_WIDTH)}} | "
                    f"{self._node_conn_text(n):<{self._node_col('conn', NODE_CONN_COL_WIDTH)}}")
        return f" {dot} {name:<{NODE_COL_WIDTH}} {role} Ray {ray_text:<6} {temp_text}"

    def _render_selected_disks(self):
        if not hasattr(self, "disk_rows"):
            return
        node = self._selected_disk_node()
        title = "Disk: --"
        if node is not None:
            title = f"Disk: {self._node_name(node).strip() or node.ip}"
        try:
            self.disk_title_lbl.configure(text=title)
        except tk.TclError:
            pass
        for drive in ("C:", "D:"):
            data = self._disk_for(node, drive) if node is not None else None
            rec = self.disk_rows.get(drive)
            if not rec:
                continue
            rec["data"] = data
            try:
                rec["label"].configure(
                    text=self._disk_text(data),
                    fg=self._disk_text_color(data))
            except tk.TclError:
                pass
            self._redraw_disk_bar(drive)

    def _selected_node(self, fallback=True):
        nodes = getattr(self, "_displayed_nodes", [])
        if not nodes:
            return None
        try:
            sel = self.nodes_list.curselection()
            if sel and 0 <= sel[0] < len(nodes):
                return nodes[sel[0]]
        except tk.TclError:
            pass
        if not fallback:
            return None
        for n in nodes:
            if n.is_this:
                return n
        for n in nodes:
            if n.alive:
                return n
        return nodes[0]

    def _selected_disk_node(self):
        return self._selected_node(fallback=True)

    def _on_node_select(self, _event=None):
        self._render_selected_disks()
        self._update_rdp_button()

    def _rdp_target_node(self):
        node = self._selected_node(fallback=False)
        if node is None or node.is_this:
            return None
        if not str(getattr(node, "ip", "") or "").strip():
            return None
        return node

    def _rdp_username_for_node(self, node) -> str:
        user = str(getattr(node, "rdp_user", "") or "").strip()
        if user:
            return user
        ip = str(getattr(node, "ip", "") or "").strip()
        for item in self.cfg.get("nodes", []) or []:
            if isinstance(item, dict) and str(item.get("ip") or "").strip() == ip:
                return str(item.get("rdp_user") or "").strip()
        return ""

    def _rdp_port_for_node(self, node) -> int:
        value = getattr(node, "rdp_port", None)
        ip = str(getattr(node, "ip", "") or "").strip()
        for item in self.cfg.get("nodes", []) or []:
            if isinstance(item, dict) and str(item.get("ip") or "").strip() == ip:
                value = item.get("rdp_port", value)
                break
        return normalized_rdp_port(value)

    def _rdp_file_for(self, ip: str, username: str, port=3389) -> str:
        safe = "".join(ch if ch.isalnum() else "_" for ch in ip) or "node"
        path = os.path.join(config_dir(), f"rdp_{safe}.rdp")
        try:
            # A TERMSRV entry is safe for passwordless reuse only when its
            # username matches this node's explicit inventory identity.
            # Otherwise an old Microsoft-account entry can override
            # ``username:s:SYNTHETIC\USER`` and create an impossible login.
            use_saved = bool(
                username and rdp_credential_matches(ip, username))
        except Exception:
            use_saved = False
        lines = [
            "screen mode id:i:2",
            "use multimon:i:0",
            "desktopwidth:i:1280",
            "desktopheight:i:720",
            "session bpp:i:32",
            f"full address:s:{rdp_target_address(ip, port)}",
            f"prompt for credentials:i:{0 if use_saved else 1}",
            "authentication level:i:2",
            "enablecredsspsupport:i:1",
        ]
        if username:
            lines.append(f"username:s:{username}")
        with open(path, "w", encoding="utf-16") as f:
            f.write("\r\n".join(lines) + "\r\n")
        return path

    def _update_rdp_button(self):
        btn = getattr(self, "btn_rdp", None)
        if btn is None:
            return
        try:
            available = bool(self._rdp_target_node()) and not bool(
                getattr(self, "_rdp_probe_running", False))
            btn.configure(state=("normal" if available else "disabled"))
        except tk.TclError:
            pass

    def _disk_for(self, node, drive):
        if node is None:
            return None
        target = str(drive or "").upper()[:2]
        for d in getattr(node, "disks", []) or []:
            if not isinstance(d, dict):
                continue
            cur = str(d.get("drive") or "").upper()[:2]
            if cur == target:
                return d
        return None

    def _disk_text(self, data):
        if not data or not data.get("present"):
            return "--"
        used = self._gb_text(data.get("used_gb"))
        total = self._gb_text(data.get("total_gb"))
        pct = self._pct_text(data.get("pct"))
        state = self._disk_activity_text(data)
        temp = _num_or_none(data.get("temperature_c"))
        temp_text = "" if temp is None else f" {int(round(temp))}°C"
        base = f"{used}/{total}G {pct}{temp_text}"
        if not state:
            return base[:24]
        room = 24 - len(base) - 1
        if room >= len(state):
            return f"{base} {state}"
        if data.get("active") and room >= 3:
            return f"{base} run"
        return base[:24]

    def _disk_activity_text(self, data):
        if not data or not data.get("active"):
            return "idle"
        bps = _num_or_none(data.get("io_bps"))
        if bps is None or bps < 1024:
            return "run"
        if bps < 1024 ** 2:
            return f"{int(round(bps / 1024))}K"
        if bps < 100 * (1024 ** 2):
            return f"{bps / (1024 ** 2):.1f}M"
        return f"{int(round(bps / (1024 ** 2)))}M"

    def _disk_text_color(self, data):
        if not data or not data.get("present"):
            return GRAY_DK
        pct = _num_or_none(data.get("pct"))
        if pct is None:
            return BLACK
        if pct >= float(self.cfg.get("disk_critical_pct", 95)):
            return RED
        if pct >= float(self.cfg.get("disk_warn_pct", 85)):
            return "#a06000"
        return BLACK

    def _redraw_disk_bar(self, drive):
        rec = getattr(self, "disk_rows", {}).get(drive)
        if not rec:
            return
        canvas = rec.get("canvas")
        data = rec.get("data")
        try:
            canvas.delete("all")
            w = canvas.winfo_width()
            h = canvas.winfo_height()
            if w <= 2 or h <= 2:
                return
            pct = _num_or_none(data.get("pct")) if data else None
            if not data or not data.get("present") or pct is None:
                canvas.create_text(w // 2, h // 2 + 1, text="--",
                                   fill=GRAY_DKR, font=self._font_name("small"))
                return
            fill_w = max(0, min(w - 2, int((w - 2) * min(100, pct) / 100.0)))
            color = BLUE98
            if pct >= float(self.cfg.get("disk_critical_pct", 95)):
                color = RED
            elif pct >= float(self.cfg.get("disk_warn_pct", 85)):
                color = "#a06000"
            canvas.create_rectangle(1, 1, 1 + fill_w, h - 1,
                                    fill=color, outline="")
            if data.get("active"):
                canvas.create_rectangle(max(1, w - 9), 2, w - 3, h - 2,
                                        fill=GREEN, outline="")
            canvas.create_text(w // 2, h // 2 + 1,
                               text=f"{int(round(pct))}%",
                               fill=GRAY_DKR, font=self._font_name("small"))
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    def _set_busy(self, busy, label=""):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for name in (
                "btn_start", "btn_stop", "btn_restart", "btn_reset",
                "btn_repair", "btn_fleet_update"):
            try: getattr(self, name).configure(state=state)
            except Exception: pass
        if busy and label:
            try:
                self.state_lbl.configure(text=f"({label})", fg=BLUE98)
                self._set_diag("RUN", f"DIAG RUN  {label}",
                               "NEXT Please wait for this action to finish.")
            except Exception:
                pass

    def _optimistic(self, label):
        try:
            self.state_lbl.configure(text=f"({label})", fg=BLUE98)
            self._set_diag("RUN", f"DIAG RUN  {label}",
                           "NEXT Working...")
        except tk.TclError:
            pass

    def _run_bg(self, fn, label):
        if self._busy:
            return
        self._set_busy(True, label)
        def work():
            try: res = fn()
            except Exception as exc: res = ActionResult(False, f"unexpected: {exc}")
            def done():
                self._set_busy(False)
                self._log(("OK: " if res.ok else "FAILED: ") + res.message)
                if not res.ok:
                    self._set_diag("ERR", "DIAG ERR action failed",
                                   f"NEXT {res.message[:140]}")
                if self.monitor:
                    self.monitor.poke()
            self._post(done)
        threading.Thread(target=work, daemon=True).start()

    def _do_start(self):
        if self.controller_only:
            self._set_diag("OK", "DIAG OK   Controller mode",
                           "NEXT Select a remote node for RDP or open Dashboard.")
            return
        # v1.3.1: user-initiated start clears auto-pause so watchdog resumes
        self.controller.auto_paused = False
        self._auto_pause_fired = False
        self._cool_streak = 0
        if self.role == "head":
            self._optimistic("starting...")
            self._run_bg(self.controller.start_head, "starting...")
        else:
            self._optimistic("joining...")
            self._run_bg(self.controller.start_worker, "joining...")

    def _do_stop(self):
        if self.controller_only:
            return
        self._optimistic("stopping...")
        self._run_bg(self.controller.stop, "stopping...")

    def _do_restart(self):
        if self.controller_only:
            return
        self._optimistic("restarting...")
        def restart():
            self.controller.stop()
            time.sleep(12)
            return (self.controller.start_head()
                    if self.role == "head"
                    else self.controller.start_worker())
        self._run_bg(restart, "restarting...")

    def _do_reset(self):
        if self.controller_only:
            return
        if self._busy:
            return
        next_action = "Start" if self.role == "head" else "Join"
        ok = messagebox.askyesno(
            "Clean Reset",
            "Stop local Ray background processes and clear stuck RCM state?\n\n"
            f"After reset finishes, press {next_action}.")
        if not ok:
            return
        self.controller.auto_paused = False
        self._auto_pause_fired = False
        self._cool_streak = 0
        self._optimistic("resetting...")

        def reset():
            result = self.controller.clean_reset()
            if self.monitor:
                try:
                    with self.monitor._metrics_lock:
                        self.monitor._metrics_cache.clear()
                        self.monitor._metrics_fail_count.clear()
                        self.monitor._metrics_soft_miss_count.clear()
                        self.monitor._metrics_skip_until.clear()
                        self.monitor._metrics_remote_progress.clear()
                except Exception:
                    pass
            return result

        self._run_bg(reset, "resetting...")

    def _clear_monitor_metric_cache(self):
        if self.monitor:
            try:
                with self.monitor._metrics_lock:
                    self.monitor._metrics_cache.clear()
                    self.monitor._metrics_fail_count.clear()
                    self.monitor._metrics_soft_miss_count.clear()
                    self.monitor._metrics_skip_until.clear()
                    self.monitor._metrics_remote_progress.clear()
            except Exception:
                pass
            try:
                self.monitor.poke()
            except Exception:
                pass













    def _password_payload_fingerprint(
            self, username: str, old_password: str, new_password: str) -> str:
        key = getattr(self, "_password_request_hmac_key", None)
        if not isinstance(key, bytes) or len(key) < 32:
            key = os.urandom(32)
            self._password_request_hmac_key = key
        # JSON array encoding is length/unicode unambiguous; HMAC ensures the
        # digest cannot be used as an offline password verifier without this
        # process's ephemeral key.
        body = json.dumps(
            [str(username), str(old_password), str(new_password)],
            ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hmac.new(key, body, hashlib.sha256).hexdigest()

    def _handle_rdp_password_change(
            self, username: str, old_password: str,
            new_password: str, request_id: str) -> dict:
        """Serialized, idempotent normal password change on this PC.

        The old password is mandatory so this remains a Windows password
        change, not an administrative reset that can orphan DPAPI/EFS data.
        Only safe status fields are returned to the HTTP layer.
        """
        if self.controller_only:
            return {"ok": False, "accepted": False,
                    "message": "controller is outbound-only", "request_id": ""}
        request_id = str(request_id or "").strip()
        if not request_id or len(request_id) > 128:
            return {"ok": False, "accepted": False,
                    "message": "invalid operation ID", "request_id": ""}
        with self._password_change_lock:
            fingerprint = self._password_payload_fingerprint(
                username, old_password, new_password)
            cached = self._password_request_cache.get(request_id)
            if cached is not None:
                cached_fingerprint = str(cached.get("fingerprint") or "")
                if not hmac.compare_digest(cached_fingerprint, fingerprint):
                    return {
                        "ok": False,
                        "accepted": False,
                        "message": "operation ID payload mismatch",
                        "request_id": request_id,
                    }
                return dict(cached.get("result") or {})
            try:
                change_local_account_password(
                    username, old_password, new_password,
                    local_computer=socket.gethostname())
                result = {
                    "ok": True,
                    "accepted": True,
                    "message": "local RDP account password changed",
                    "request_id": request_id,
                }
                self._log(
                    "rdp credential: local password changed for validated account")
            except (AccountValidationError, CredentialValidationError) as exc:
                result = {
                    "ok": False,
                    "accepted": False,
                    "message": str(exc),
                    "request_id": request_id,
                }
            except WindowsSecurityError:
                result = {
                    "ok": False,
                    "accepted": True,
                    "message": "Windows rejected the current or new password",
                    "request_id": request_id,
                }
            except Exception as exc:
                result = {
                    "ok": False,
                    "accepted": False,
                    "message": f"password change failed ({type(exc).__name__})",
                    "request_id": request_id,
                }
            self._password_request_cache[request_id] = {
                "fingerprint": fingerprint,
                "result": dict(result),
            }
            while len(self._password_request_cache) > 32:
                self._password_request_cache.pop(next(iter(self._password_request_cache)))
            return result







    def _open_dashboard(self):
        url = f"http://{self.cfg['head_ip']}:{self.cfg['dashboard_port']}"
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()

    def _open_rdp(self):
        node = self._selected_node(fallback=False)
        if node is None:
            self._set_diag("WARN", "DIAG WARN RDP target not selected",
                           "NEXT Select another remote node, then press RDP.")
            return
        name = (str(getattr(node, "name", "") or "").strip()
                or str(getattr(node, "hostname", "") or "").strip()
                or str(getattr(node, "ip", "") or "").strip()
                or "node")
        ip = str(getattr(node, "ip", "") or "").strip()
        if node.is_this:
            self._set_diag("WARN", "DIAG WARN RDP target is this PC",
                           "NEXT Select a remote worker node.")
            return
        if not ip:
            self._set_diag("WARN", "DIAG WARN RDP target has no IP",
                           f"NEXT Check Settings for {name}.")
            return
        if self._rdp_probe_running:
            return
        port = self._rdp_port_for_node(node)
        self._rdp_probe_generation += 1
        generation = self._rdp_probe_generation
        snapshot = replace(node, rdp_port=port)
        self._rdp_probe_running = True
        self._update_rdp_button()
        self._set_diag(
            "RUN", f"DIAG RUN  checking RDP {name}",
            f"NEXT Testing {rdp_target_address(ip, port)} without blocking the UI.")

        def work():
            try:
                result = probe_remote_access(
                    ip, port, int(self.cfg.get("temp_port") or 8866), timeout=1.2)
            except Exception:
                result = {"rdp": "error", "rcm": "error"}
            self._post(
                lambda: self._finish_rdp_preflight(generation, snapshot, result))

        threading.Thread(
            target=work, daemon=True, name="RdpPreflight").start()

    def _finish_rdp_preflight(self, generation: int, node, result: dict):
        if self._closing or generation != self._rdp_probe_generation:
            return
        self._rdp_probe_running = False
        selected = self._selected_node(fallback=False)
        if (selected is None
                or str(getattr(selected, "ip", "") or "").strip()
                != str(getattr(node, "ip", "") or "").strip()):
            self._update_rdp_button()
            self._set_diag(
                "WARN", "DIAG WARN RDP target changed",
                "NEXT Select the intended remote node and press RDP again.")
            return
        self._update_rdp_button()
        name = (str(getattr(node, "name", "") or "").strip()
                or str(getattr(node, "hostname", "") or "").strip()
                or str(getattr(node, "ip", "") or "").strip()
                or "node")
        ip = str(getattr(node, "ip", "") or "").strip()
        port = self._rdp_port_for_node(node)
        rdp_state = str(result.get("rdp") or "error")
        rcm_state = str(
            result.get("rcm") or "legacy_remote_retired")
        self._log(
            f"rdp preflight: {name} {rdp_target_address(ip, port)} "
            f"rdp={rdp_state} rcm={rcm_state}")
        if rdp_state == "open":
            self._launch_rdp(node)
            return

        rdp_reason = {
            "refused": "The connection was refused. The target is reachable, "
                       "but no listener answered on this port.",
            "timeout": "The target did not respond in time. Check the firewall, "
                       "ACL, network path, and listener.",
            "error": "RCM could not determine the port state.",
        }.get(rdp_state, "RCM could not determine the port state.")
        rcm_line = (
            "Only the selected RDP port was probed; "
            "legacy RCM remote health is retired.")
        registered_line = (
            "This node is not registered in this PC's Settings inventory.\n"
            if not bool(getattr(node, "registered", True)) else "")
        message = (
            f"The RDP listener on {name} "
            f"({rdp_target_address(ip, port)}) is unreachable.\n\n"
            f"{rdp_reason}\n{rcm_line}\n\n{registered_line}"
            "Possible causes: unsupported or disabled Windows RDP host, "
            "TermService, Windows Firewall, Tailscale ACL, or a different RDP port.\n\n"
            "Open Windows Remote Desktop anyway?")
        self._set_diag(
            "WARN", f"DIAG WARN RDP listener unreachable: {name}",
            f"NEXT Check Windows RDP host, service, firewall/ACL, and port {port}.")
        if messagebox.askyesno("RDP connection check", message, parent=self):
            self._launch_rdp(node)

    def _launch_rdp(self, node):
        name = (str(getattr(node, "name", "") or "").strip()
                or str(getattr(node, "hostname", "") or "").strip()
                or str(getattr(node, "ip", "") or "").strip()
                or "node")
        ip = str(getattr(node, "ip", "") or "").strip()
        port = self._rdp_port_for_node(node)
        try:
            rdp_user = self._rdp_username_for_node(node)
            address = rdp_target_address(ip, port)
            cmd = ["mstsc.exe", f"/v:{address}"]
            next_text = "NEXT Enter Windows credentials in Remote Desktop."
            if rdp_user:
                rdp_file = self._rdp_file_for(ip, rdp_user, port)
                cmd = ["mstsc.exe", rdp_file]
                next_text = f"NEXT Enter password for {rdp_user}."
            self._log(
                f"rdp: launching {name} at {address}"
                f"{' as ' + rdp_user if rdp_user else ''}")
            subprocess.Popen(cmd, creationflags=CREATE_NEW_PROCESS_GROUP)
            self._set_diag("OK", f"DIAG OK   RDP client opened: {name}",
                           next_text)
        except Exception as exc:
            self._log(
                f"rdp launch failed: {name} {ip}: "
                f"{type(exc).__name__}: {exc}")
            self._set_diag("WARN", "DIAG WARN RDP launch failed",
                           f"NEXT {name} {ip}: {type(exc).__name__}: {exc}")

    def _open_logs(self):
        win = self._logs_win
        try:
            if win is not None and win.winfo_exists():
                win.reload()
                win.lift(); win.focus_force(); return
        except Exception:
            pass
        self._logs_win = LogViewerDialog(self, LOG_PATH)

    def _process_cleanup_log(self, text):
        line = str(text or "").replace("\r", " ").replace("\n", " ").strip()
        if not line:
            return
        # The cleanup dialog emits summaries only. Never write commands,
        # paths, or process environment values to either log.
        self._log(line)
        try:
            _append_log_record(
                PROCESS_CLEANUP_LOG_PATH,
                time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")
        except Exception:
            pass

    def _open_process_cleanup(self):
        win = self._cleanup_win
        try:
            if win is not None and win.winfo_exists():
                win.lift()
                win.focus_force()
                return
        except Exception:
            pass
        if not _HAS_PROCESS_CLEANUP:
            messagebox.showerror(
                "Process Cleanup",
                "Process cleanup is unavailable in this build.\n\n"
                f"{_process_cleanup_import_error}",
                parent=self)
            return
        values = self.cfg.get("process_cleanup", {})
        if not isinstance(values, dict):
            values = {}
        try:
            ignored = values.get("ignored_fingerprints", [])
            if not isinstance(ignored, (list, tuple, set, frozenset)):
                ignored = []
            policy = CleanupPolicy(
                sample_sec=max(
                    1.0, min(60.0, float(values.get("sample_sec", 8.0)))),
                grace_sec=max(
                    0.5, min(30.0, float(values.get("grace_sec", 3.0)))),
                result_max_age_sec=max(
                    10.0, min(600.0, float(
                        values.get("result_max_age_sec", 60.0)))),
                ignored_fingerprints=frozenset(
                    str(value) for value in ignored
                    if str(value).strip()))
            self._cleanup_win = ProcessCleanupDialog(
                self, policy=policy, on_log=self._process_cleanup_log)
        except Exception as exc:
            self._process_cleanup_log(
                f"Process cleanup UI failed: {type(exc).__name__}")
            messagebox.showerror(
                "Process Cleanup",
                f"Could not open Process Cleanup:\n{type(exc).__name__}: {exc}",
                parent=self)


    def _settings_password_action(self, action: str, node: dict, parent):
        if action == "batch":
            targets = rdp_password_targets(node if isinstance(node, list) else [])
            if len(targets) < 2:
                messagebox.showinfo(
                    "Multiple-PC passwords",
                    "At least two Ray targets with configured RDP accounts are required.",
                    parent=parent)
                return
            BatchRdpPasswordDialog(parent, targets, self._execute_rdp_password_change)
            return
        ip = str(node.get("ip") or "").strip()
        username = str(node.get("rdp_user") or "").strip()
        if is_controller_node(node):
            messagebox.showinfo(
                "RDP credentials",
                "A controller PC is not a connection target. Select another Ray PC.",
                parent=parent)
            return
        if not ip or not username:
            messagebox.showerror(
                "RDP credentials",
                "Enter a Tailscale IP and RDP account for the selected node first.",
                parent=parent)
            return
        if action == "delete":
            try:
                existed = delete_rdp_credential(ip)
                messagebox.showinfo(
                    "Delete saved credential",
                    "The saved credential was deleted."
                    if existed else "No saved credential was found.",
                    parent=parent)
                refresh = getattr(parent, "_populate_node_tree", None)
                if callable(refresh):
                    refresh()
            except Exception as exc:
                messagebox.showerror(
                    "Delete saved credential",
                    f"Could not delete the credential ({type(exc).__name__}).",
                    parent=parent)
            return
        if action == "change":
            RdpPasswordDialog(
                parent, node, self._execute_rdp_password_change)

    def _execute_rdp_password_change(
            self, node: dict, old_password: str, new_password: str,
            save_credential: bool, operation_id: str) -> tuple[str, str]:
        ip = str(node.get("ip") or "").strip()
        username = str(node.get("rdp_user") or "").strip()
        if is_controller_node(node):
            return "failure", "A controller PC is not a password-change target."
        try:
            target_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return "failure", "The target Tailscale IP is invalid."
        if not username:
            return "failure", "No RDP account is configured."
        if ip != str(self.ip or "").strip():
            return "failure", "legacy_remote_retired"

        operation_id = str(operation_id or "").strip()
        completed = operation_id in self._password_completed_operations

        def mark_completed():
            if operation_id and operation_id not in self._password_completed_operations:
                self._password_completed_operations.append(operation_id)
                del self._password_completed_operations[:-64]

        if not completed and ip == str(self.ip or "").strip():
            try:
                change_local_account_password(
                    username, old_password, new_password,
                    local_computer=socket.gethostname())
            except (AccountValidationError, CredentialValidationError) as exc:
                return "failure", str(exc)
            except WindowsSecurityError:
                return (
                    "failure",
                    "Windows rejected the current password or the new password.")
            mark_completed()
        elif not completed:
            port = int(self.cfg.get("temp_port", 8866))
            try:
                health = requests.get(
                    f"http://{ip}:{port}/health", timeout=2.5)
                health.raise_for_status()
                health_payload = health.json() or {}
                try:
                    reported_ip = str(ipaddress.ip_address(
                        str(health_payload.get("local_ip") or "").strip()))
                except ValueError:
                    return "failure", "The target RCM reported an invalid local IP."
                if reported_ip != target_ip:
                    return (
                        "failure",
                        "The target RCM local IP does not match the requested PC.")
                health_host = str(health_payload.get("host") or "").strip()
                if not health_host:
                    return "failure", "The target RCM did not report a host identity."
                capability = bool(health_payload.get("rdp_password_change_v1"))
                if not capability:
                    return (
                        "failure",
                        "The target PC must run a newer RCM before changing passwords.")
                response = requests.post(
                    f"http://{ip}:{port}/rdp-password",
                    headers={"X-RCM-Control": "rdp-password-v1"},
                    json={
                        "username": username,
                        "old_password": old_password,
                        "new_password": new_password,
                        "request_id": operation_id,
                    },
                    timeout=8.0)
            except requests.Timeout:
                return (
                    "partial",
                    "The response timed out, so the result is uncertain. "
                    "Keep this window open and retry with the same values.")
            except Exception as exc:
                return (
                    "failure",
                    f"Could not connect to the target RCM ({type(exc).__name__}).")
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if str(payload.get("request_id") or "") != operation_id:
                return "failure", "The target RCM returned a different operation ID."
            response_host = str(payload.get("host") or "").strip()
            if (not response_host
                    or response_host.casefold() != health_host.casefold()):
                return (
                    "failure",
                    "The target RCM response host does not match its health identity.")
            if not response.ok or not payload.get("ok"):
                message = str(
                    payload.get("message") or "The password change was rejected.")
                return "failure", message
            mark_completed()

        if save_credential:
            try:
                write_rdp_credential(ip, username, new_password)
            except Exception as exc:
                return (
                    "partial",
                    "The password changed, but saving the Windows credential failed "
                    f"({type(exc).__name__}). Keep the new password and retry.")
        return (
            "success",
            "The password changed and the Windows credential was saved."
            if save_credential else "The password change completed.")

    def _open_settings(self):
        win = self._settings_win
        try:
            if win is not None and win.winfo_exists():
                win.lift(); win.focus_force(); return
        except Exception:
            pass
        self._settings_win = SettingsDialog(
            self, self.cfg, self._on_settings_saved,
            on_password_action=self._settings_password_action,
            on_make_head=self._start_head_change)

    def _start_head_change(self, candidate: dict, parent=None):
        del candidate
        messagebox.showinfo(
            "Head change unavailable",
            "legacy_remote_retired",
            parent=parent or self)
        return "legacy_remote_retired"
        if self._busy:
            return
        if parent is not None:
            try:
                parent.destroy()
            except Exception:
                pass
        name = str(candidate.get("name") or candidate.get("ip") or "node")
        progress = OperationProgressDialog(
            self, f"Make {name} the head")
        self._set_busy(True, "head preflight...")

        def progress_cb(stage, node_name, state, reason=""):
            suffix = f" — {reason}" if reason else ""
            self._post(
                lambda: progress.append(
                    f"{stage:<9} {node_name}: {state}{suffix}"))

        orchestrator = ClusterReconfigurator(
            self.cfg, controller=self.controller,
            on_progress=progress_cb,
            on_event=self._record_cluster_event)

        def run_preflight():
            info = orchestrator.preflight(candidate)
            self._post(lambda: confirm(info))

        def confirm(info):
            if not progress.winfo_exists():
                self._set_busy(False)
                return
            unreachable = [
                str(node.get("name") or node.get("ip"))
                for node in info.get("unreachable", [])]
            incompatible = [
                str(item["node"].get("name") or item["node"].get("ip"))
                + f" ({item['reason']})"
                for item in info.get("incompatible", [])]
            if not info.get("candidate_ready"):
                details = []
                if info.get("candidate_firewall_ready") is False:
                    details.append(
                        "Ray-Tailscale-In firewall rule is not ready.")
                if incompatible:
                    details.append("Incompatible: " + ", ".join(incompatible))
                messagebox.showerror(
                    "Head change preflight failed",
                    f"{name} cannot become the head.\n\n"
                    + "\n".join(details or [
                        "The candidate RCM is unreachable or incompatible."]),
                    parent=progress)
                self._set_busy(False)
                progress.finish("Preflight failed", ok=False)
                return
            text = (
                f"Move the Ray head to {name}?\n\n"
                "• The Ray cluster will restart and all running jobs and actors will end.\n"
                "• Windows does not need to restart.\n"
                "• Unreachable nodes: "
                + (", ".join(unreachable) if unreachable else "none")
                + " — they will adopt the newer epoch when they return.")
            if incompatible:
                text += (
                    "\n\nOld or incompatible nodes excluded from this change: "
                    + ", ".join(incompatible))
            if not messagebox.askyesno(
                    "Make this the head", text, parent=progress):
                self._set_busy(False)
                progress.finish("Cancelled", ok=False)
                return
            threading.Thread(
                target=run_execute, args=(info,), daemon=True,
                name="ClusterReconfigure").start()

        def run_execute(info):
            result = orchestrator.execute(
                candidate, preflight=info,
                cancel_event=progress.cancel_event)
            self._post(lambda: (
                self._set_busy(False),
                progress.append(result.message),
                progress.finish(result.message, ok=result.ok)))

        threading.Thread(
            target=run_preflight, daemon=True,
            name="ClusterPreflight").start()

    def _on_settings_saved(self, cfg):
        # Commit to disk before mutating the live controller.  SettingsDialog
        # stays open and shows the exception when this atomic replace fails.
        save_config(cfg, raise_on_error=True)
        self.cfg = cfg
        self.role, self.ip, self.cpus = resolve_identity(cfg)
        self.controller_only = is_controller_config(cfg, self.ip)
        self.controller.cfg = cfg
        identity_role = "CONTROLLER" if self.controller_only else self.role.upper()
        self.id_lbl.configure(
            text=f"{identity_role} on {self.ip or 'no-ip'}   "
                 f"({self.cpus} CPU)")
        if self.controller_only:
            self.btn_start.configure(text="Controller", state="disabled")
            for button in (self.btn_stop, self.btn_restart,
                           self.btn_reset, self.btn_repair):
                button.configure(state="disabled")
        else:
            self.btn_start.configure(
                text=("Start" if self.role == "head" else "Join"), state="normal")
            for button in (self.btn_stop, self.btn_restart,
                           self.btn_reset, self.btn_repair):
                button.configure(state="normal")
        self.apply_login_autostart(cfg.get("autostart_login", False))
        self._apply_ui_scaling_from_config()
        self._apply_diag_font()
        self.update_idletasks()
        self._fit_to_content(persist=False)
        self._sync_metrics_runtime()
        self._sync_watchdog_runtime()
        if _HAS_TRAY:
            self._rebuild_tray()
        self._start_monitor()
        # v1.2: re-check ray.exe after settings change
        self._check_ray_exe()
        return True

    # ------------------------------------------------------------------
    def apply_login_autostart(self, enabled):
        if not _IS_WIN:
            return
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            name = "RayClusterManager"
            if enabled:
                if getattr(sys, "frozen", False):
                    target = f'"{sys.executable}"'
                else:
                    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
                    exe = pyw if os.path.exists(pyw) else sys.executable
                    target = f'"{exe}" "{os.path.abspath(__file__)}"'
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, target)
            else:
                try: winreg.DeleteValue(key, name)
                except FileNotFoundError: pass
            winreg.CloseKey(key)
        except Exception as exc:
            self._log("autostart error: " + str(exc))

    # ------------------------------------------------------------------
    def _build_tray(self):
        if not _HAS_TRAY:
            self.tray = None
            return False
        try: img = Image.open(resource_path("assets/icon.png"))
        except Exception: img = Image.new("RGB", (64, 64), (192, 192, 192))
        menu_items = [
            pystray.MenuItem("Show", lambda *a: self._post(self._show_window),
                             default=True),
        ]
        if not self.controller_only:
            menu_items.extend([
                pystray.MenuItem(
                    ("Start Head" if self.role == "head" else "Connect Worker"),
                    lambda *a: self._post(self._do_start)),
                pystray.MenuItem("Stop", lambda *a: self._post(self._do_stop)),
                pystray.MenuItem("Reset", lambda *a: self._post(self._do_reset)),
            ])
        menu_items.extend([
            pystray.MenuItem("Dashboard", lambda *a: self._post(self._open_dashboard)),
            pystray.MenuItem(
                "Process Cleanup",
                lambda *a: self._post(self._open_process_cleanup)),
            pystray.MenuItem("Logs", lambda *a: self._post(self._open_logs)),
            pystray.Menu.SEPARATOR,
            # v1.07.16b [cleanquit]: honor the Settings "Stop Ray when
            # quitting from the tray" checkbox (stop_on_quit, default off)
            # instead of always stopping local Ray.  controller_only is
            # checked first so a controller never reads cfg here.
            pystray.MenuItem("Quit", lambda *a: self._post(
                lambda: self._quit(
                    stop_ray=((not self.controller_only)
                              and bool(self.cfg.get("stop_on_quit", False))),
                    source="tray"))),
        ])
        menu = pystray.Menu(*menu_items)
        icon = pystray.Icon("RayClusterManager", img, APP_NAME, menu)
        self.tray = icon

        def _run_tray():
            try:
                icon.run()
            except Exception as exc:
                if self.tray is icon:
                    self.tray = None
                try:
                    self._post(lambda exc=exc: self._log(f"tray icon error: {exc}"))
                except Exception:
                    pass
            finally:
                if self.tray is icon and not self._closing:
                    self.tray = None

        threading.Thread(target=_run_tray, daemon=True,
                         name="TrayIcon").start()
        return True

    def _rebuild_tray(self):
        if self.tray:
            try: self.tray.stop()
            except Exception: pass
            self.tray = None
        return self._build_tray()

    def _ensure_tray(self):
        if self.tray:
            return True
        try:
            return bool(self._build_tray())
        except Exception as exc:
            self.tray = None
            self._log(f"tray build failed: {exc}")
            return False

    def _refresh_tray_title(self, text):
        if self.tray:
            try: self.tray.title = f"{APP_NAME}\n{text}"
            except Exception: pass

    def _show_window(self):
        try:
            self.deiconify(); self.lift(); self.focus_force()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    def _on_close_button(self):
        self.cfg["on_close"] = "tray"
        if self._ensure_tray():
            self.withdraw()
            self._log("minimized to tray (cluster still running)")
        else:
            self._show_window()
            self._log("close ignored because tray icon is unavailable")

    def _quit(self, stop_ray, source="window"):
        # Tray Quit must look and behave immediate. Hide the UI/tray first,
        # then finish Ray cleanup on a worker thread with a hard exit fallback.
        # A controller does not own local Ray.  This invariant is enforced at
        # the cleanup boundary as well as in the tray callback so every future
        # quit caller remains safe.
        stop_ray = bool(stop_ray) and not self.controller_only
        if self._closing:
            return
        self._closing = True
        try:
            self.controller.request_shutdown()
        except Exception:
            pass
        self._log(f"quit requested from {source} - cleaning up...")
        _schedule_frozen_temp_cleanup(self._log)
        cleanup_win = self._cleanup_win
        try:
            if cleanup_win is not None and cleanup_win.winfo_exists():
                cleanup_win.cancel_and_close()
        except Exception:
            pass
        try:
            self.withdraw()
        except Exception:
            pass
        tray = self.tray
        self.tray = None
        if tray:
            try:
                tray.stop()
                self._log("tray icon stopped")
            except Exception as exc:
                self._log(f"  cleanup tray: {exc}")
        for job_name in ("_diag_tick_job", "_ui_scaling_guard_job",
                         "_duplicate_guard_job", "_metrics_retry_job"):
            job = getattr(self, job_name, None)
            if job is not None:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                try:
                    setattr(self, job_name, None)
                except Exception:
                    pass

        def _hard_kill():
            time.sleep(60.0 if stop_ray else 8.0)
            try:
                self._log("quit hard-exit timeout reached")
            except Exception:
                pass
            os._exit(0)
        threading.Thread(target=_hard_kill, daemon=True).start()

        def _safe(fn, label):
            try: fn()
            except Exception as exc:
                try: self._log(f"  cleanup {label}: {exc}")
                except Exception: pass

        def _finish_normal_exit():
            try:
                self.quit()
            except Exception:
                pass
            try:
                self.destroy()
            except Exception:
                pass

        # v1.07.16b [cleanquit]: _drain_ui_q stops pumping as soon as
        # _closing is set, so posting _finish_normal_exit through the UI
        # queue could never run.  Every quit therefore idled until the
        # hard-exit timer (8s, or 60s with Ray stop) and left the process
        # lingering in Task Manager while it still held the singleton
        # mutex.  A main-thread after-loop now watches an explicit
        # completion event and leaves Tk as soon as cleanup finishes.
        quit_done = threading.Event()
        self._quit_done = quit_done

        def _watch_quit_done():
            if quit_done.is_set():
                _finish_normal_exit()
                return
            try:
                self.after(100, _watch_quit_done)
            except Exception:
                pass  # Tk unavailable; the cleanup backstop exits instead

        try:
            self.after(100, _watch_quit_done)
        except Exception:
            pass

        def _cleanup_and_exit():
            if self._watchdog:
                _safe(self._watchdog.stop, "watchdog")
                try:
                    self._watchdog.join(timeout=2.0)
                except Exception:
                    pass
            if self._head_guard:
                _safe(self._head_guard.stop, "dashboard guard")
                try:
                    self._head_guard.join(timeout=2.0)
                except Exception:
                    pass
            if self.monitor:
                _safe(self.monitor.stop, "monitor")
                try:
                    self.monitor.join(timeout=2.0)
                except Exception:
                    pass
            if self._temp_srv:
                _safe(self._temp_srv.stop, "temp_srv")
                try: self._temp_srv.join(timeout=2.0)
                except Exception: pass
            if _HAS_SENSOR:
                _safe(sensor_poller.stop_background_poll, "sensor_poller")
            if stop_ray:
                self._log("stopping local ray before exit...")
                def stop_for_quit():
                    res = self.controller.stop_for_quit()
                    if not res.ok:
                        self._log("  cleanup ray.stop: " + res.message)
                _safe(stop_for_quit, "ray.stop")
            self._log("quit cleanup complete")
            quit_done.set()
            # Backstop: if Tk cannot service _watch_quit_done (already
            # destroyed or wedged), end the process shortly after cleanup
            # instead of waiting for the 8-60s hard-exit timer.  On the
            # normal path the interpreter exits during this sleep and the
            # daemon thread simply disappears.
            time.sleep(3.0)
            os._exit(0)

        threading.Thread(
            target=_cleanup_and_exit, daemon=True, name="QuitCleanup").start()


def _acquire_single_instance() -> bool:
    """Return True if we are the only instance. Uses use_last_error=True so
    GetLastError() isn't clobbered by intermediate ctypes calls (P0-fix)."""
    global _mutex_handle
    if _test_bypass_singleton():
        return True
    if not _IS_WIN:
        return True
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.SetLastError(0)
        _mutex_handle = k32.CreateMutexW(
            None, False, "Global\\RayClusterManager_singleton")
        if ctypes.get_last_error() == 183:   # ERROR_ALREADY_EXISTS
            try:
                k32.CloseHandle(_mutex_handle)
            except Exception:
                pass
            _mutex_handle = None
            return False
        return True
    except Exception:
        return True


def _release_single_instance():
    global _mutex_handle
    if not _IS_WIN or not _mutex_handle:
        _mutex_handle = None
        return
    try:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(_mutex_handle)
    except Exception:
        pass
    _mutex_handle = None


def _local_rcm_health_ports() -> list[int]:
    ports = [8866]
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        port = int((raw or {}).get("temp_port") or 0)
        if 0 < port <= 65535 and port not in ports:
            ports.insert(0, port)
    except Exception:
        pass
    return ports


def _local_rcm_health(timeout: float = 1.5) -> tuple[Optional[dict], str]:
    errors: list[str] = []
    for port in _local_rcm_health_ports():
        try:
            res = requests.get(f"http://127.0.0.1:{port}/health", timeout=timeout)
            if not res.ok:
                errors.append(f":{port} HTTP {res.status_code}")
                continue
            data = res.json()
            if isinstance(data, dict):
                data.setdefault("_health_port", port)
                return data, ""
            errors.append(f":{port} invalid JSON")
        except Exception as exc:
            errors.append(f":{port} {type(exc).__name__}: {exc}")
    return None, "; ".join(errors) if errors else "no health ports"


def _local_health_server_expected() -> bool:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            temp_on = bool(raw.get("temp_enabled", DEFAULT_CONFIG["temp_enabled"]))
            metrics_on = bool(raw.get("metrics_enabled", DEFAULT_CONFIG["metrics_enabled"]))
            return temp_on or metrics_on
    except Exception:
        pass
    return True


def _wait_for_local_rcm_health(
        grace_sec: float = 6.0,
        timeout: float = 0.6) -> tuple[Optional[dict], str]:
    deadline = time.monotonic() + max(0.0, grace_sec)
    last_err = ""
    while time.monotonic() < deadline:
        health, err = _local_rcm_health(timeout=timeout)
        if health is not None:
            return health, ""
        last_err = err
        time.sleep(0.3)
    return None, last_err


def _try_replace_stale_rcm_instance() -> tuple[bool, str, bool]:
    """If a stale RCM owns the singleton, replace it and let startup retry.

    Returns (replaced, message, needs_admin). Prefer /health proof, but fall
    back to process path/SHA inspection when a build is wedged before the local
    health server starts.
    """
    if not (_IS_WIN and getattr(sys, "frozen", False)):
        return False, "not a frozen Windows startup", False
    health, err = _local_rcm_health()
    if health is None:
        targets, same, unknown, details = _replacement_targets_from_processes()
        if targets is None:
            return False, (
                f"existing RCM did not answer /health ({err}); {details}"), False
        if targets:
            ok, msg = _cleanup_duplicate_rcm_processes(
                wait_sec=8.0, target_pids=targets)
            if ok:
                return True, (
                    "replaced non-responsive older/different RCM: " + msg), False
            if not _is_admin():
                return False, (
                    "non-responsive older/different RCM owns the singleton; "
                    + msg), True
            return False, msg, False
        if unknown:
            unknown_pids = [pid for pid, _reason in unknown]
            if not _is_admin():
                return False, (
                    f"existing RCM did not answer /health ({err}); "
                    f"process identity needs admin: {details}"), True
            ok, msg = _cleanup_duplicate_rcm_processes(
                wait_sec=8.0, target_pids=unknown_pids)
            if ok:
                return True, (
                    "replaced non-responsive RCM with unreadable identity: "
                    + msg), False
            return False, msg, False
        if same:
            if not _local_health_server_expected():
                return False, (
                    "current build is already running and local /health is "
                    f"disabled by config; {details}"), False
            later_health, later_err = _wait_for_local_rcm_health()
            if later_health is not None:
                later_version = str(later_health.get("version") or "")
                later_tag = str(later_health.get("build_tag") or "")
                later_sha = str(later_health.get("sha256") or "").upper()
                if (later_version == APP_VERSION and later_tag == APP_BUILD_TAG
                        and _is_real_sha(later_sha)
                        and later_sha == file_sha256(current_binary_path())):
                    return False, "current build is already running", False
            ok, msg = _cleanup_duplicate_rcm_processes(
                wait_sec=8.0, target_pids=same)
            if ok:
                return True, (
                    "replaced non-responsive current-build RCM after "
                    f"health grace ({later_err or err}): {msg}"), False
            if not _is_admin():
                return False, (
                    "non-responsive current-build RCM owns the singleton; "
                    + msg), True
            return False, msg, False
        return False, f"existing RCM did not answer /health ({err})", False
    version = str(health.get("version") or "")
    tag = str(health.get("build_tag") or "")
    sha = str(health.get("sha256") or "").upper()
    current_sha = file_sha256(current_binary_path())
    same_build = (
        version == APP_VERSION and tag == APP_BUILD_TAG
        and _is_real_sha(sha) and sha == current_sha)
    if same_build:
        return False, "current build is already running", False
    label = f"{version or '?'} {tag or '?'}".strip()
    target_pids = None
    try:
        health_pid = int(health.get("pid") or 0)
        if health_pid and health_pid != os.getpid():
            target_pids = [health_pid]
    except Exception:
        target_pids = None
    ok, msg = _cleanup_duplicate_rcm_processes(
        wait_sec=8.0, target_pids=target_pids)
    if ok:
        return True, f"replaced older RCM {label}: {msg}", False
    if not _is_admin():
        return False, f"older RCM {label} owns the singleton; {msg}", True
    else:
        return False, msg, False


def _show_existing_instance_window() -> bool:
    """Best-effort restore/focus when a second launch hits the mutex."""
    if not _IS_WIN:
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        matches = []

        enum_proc = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def visit(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            if buf.value.startswith(APP_NAME):
                matches.append(hwnd)
                return False
            return True

        user32.EnumWindows(enum_proc(visit), 0)
        if not matches:
            return False
        hwnd = matches[0]
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.ShowWindow(hwnd, 5)  # SW_SHOW
        user32.SetForegroundWindow(hwnd)
        return True
    except Exception:
        return False


def _notify_existing_instance(reason: str = ""):
    if not _IS_WIN:
        return
    try:
        msg = (
            "Ray Cluster Manager is already running.\n\n"
            "Use the existing tray/window, or quit it first before launching "
            "the updated build."
        )
        if reason:
            msg += f"\n\n{reason}"
        ctypes.windll.user32.MessageBoxW(None, msg, APP_NAME, 0x40)
    except Exception:
        pass


def _is_admin() -> bool:
    """v1.3: Windows admin 권한 체크."""
    if not _IS_WIN:
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _try_elevate() -> bool:
    """v1.3: 자동 admin elevation 시도. UAC 동의 시 True (이 instance는 종료해야)."""
    if not _IS_WIN:
        return False
    try:
        # rebuild argv as quoted string
        args = " ".join(f'"{a}"' for a in sys.argv[1:])
        # frozen exe: re-launch self. dev: re-launch python with script
        if getattr(sys, "frozen", False):
            target = sys.executable
            arg_str = args
        else:
            target = sys.executable
            arg_str = f'"{os.path.abspath(sys.argv[0])}" {args}'.strip()
        rv = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, arg_str, None, 1)
        # rv > 32 = success (new elevated process started)
        return rv > 32
    except Exception:
        return False


def _skip_uac_for_tests() -> bool:
    return os.environ.get("RCM_SKIP_UAC_FOR_TESTS") == "1"


def _test_bypass_singleton() -> bool:
    return (_skip_uac_for_tests()
            and os.environ.get("RCM_TEST_BYPASS_SINGLETON") == "1")


def _test_disable_duplicate_guard() -> bool:
    return (_skip_uac_for_tests()
            and os.environ.get("RCM_TEST_DISABLE_DUPLICATE_GUARD") == "1")


def _test_disable_watchdog() -> bool:
    return (_skip_uac_for_tests()
            and os.environ.get("RCM_TEST_DISABLE_WATCHDOG") == "1")


bind_legacy_globals(globals())


def main():
    if not _acquire_single_instance():
        replaced, msg, needs_admin = _try_replace_stale_rcm_instance()
        if needs_admin:
            if _try_elevate():
                raise SystemExit(0)
            _show_existing_instance_window()
            _notify_existing_instance(
                msg + "\n\nRun the current build as administrator to replace it.")
            raise SystemExit(0)
        if replaced and _acquire_single_instance():
            os.environ["RCM_STARTUP_DUP_CLEANUP"] = msg
        else:
            _show_existing_instance_window()
            _notify_existing_instance(msg if msg else "")
            raise SystemExit(0)
    # v1.5.24: release the mutex before spawning the elevated child. Otherwise
    # the child can see the parent as the existing singleton and exit.
    if _IS_WIN and not _is_admin() and not _skip_uac_for_tests():
        _release_single_instance()
        if _try_elevate():
            raise SystemExit(0)
        if not _acquire_single_instance():
            _show_existing_instance_window()
            _notify_existing_instance()
            raise SystemExit(0)
        os.environ["RCM_NON_ADMIN"] = "1"
    # v1.5.24: after we own the stable mutex, any remaining RCM process is an
    # older side-by-side build or a stale background copy. Clean it before the
    # new instance binds :8866 so the duplicate state heals itself on launch.
    if (_IS_WIN and getattr(sys, "frozen", False)
            and not _test_disable_duplicate_guard()):
        ok, msg = _cleanup_duplicate_rcm_processes()
        if msg and msg != "no duplicate RCM processes":
            os.environ["RCM_STARTUP_DUP_CLEANUP"] = msg
        if not ok:
            _notify_existing_instance(
                "Could not close the older background process.\n\n"
                f"{msg}\n\nRun the current build as administrator or close "
                "the old RCM from Task Manager.")
            raise SystemExit(0)
    app = RayApp()
    app.mainloop()


if __name__ == "__main__":
    main()
