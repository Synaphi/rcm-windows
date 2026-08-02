"""Regression test for RCM stale singleton-owner recovery.

This test is intentionally standalone so it can be run after a release build:

    python test_stale_owner_recovery.py

It verifies two things:
- Source contract: a same-build owner with no health server is replaced when
  health is expected and remains untouched when health is disabled by config.
- Packaged exe behavior: a non-responsive same-name owner holds the stable
  mutex, then the official exe replaces it and publishes /health for both head
  and worker roles.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OFFICIAL_EXE = ROOT.parent / "RayClusterManager.exe"
PORT = 8866
HEALTH_URL = f"http://127.0.0.1:{PORT}/health"
# Source the expected version/tag from the app so this test never drifts.
try:
    import ray_monitor as _rm
    EXPECTED_VERSION = _rm.APP_VERSION
    EXPECTED_TAG = _rm.APP_BUILD_TAG
except Exception:
    EXPECTED_VERSION = "1.5.33"
    EXPECTED_TAG = "fitscreen"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def list_rcm_pids() -> list[int]:
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq RayClusterManager.exe",
             "/FO", "CSV", "/NH"],
            text=True, encoding="utf-8", errors="replace")
    except Exception:
        return []
    pids: list[int] = []
    for line in out.splitlines():
        if not line or line.startswith("INFO:"):
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        if len(row) >= 2 and row[0].lower() == "rayclustermanager.exe":
            try:
                pids.append(int(row[1]))
            except ValueError:
                pass
    return pids


def kill_pid(pid: int):
    subprocess.run(
        ["taskkill", "/PID", str(pid), "/F"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def health(timeout: float = 1.0) -> dict | None:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return None


def wait_health(role: str, expected_sha: str, timeout: float = 45.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = health()
        if (last and last.get("version") == EXPECTED_VERSION
                and last.get("build_tag") == EXPECTED_TAG
                and str(last.get("role") or "").lower() == role
                and str(last.get("sha256") or "").upper() == expected_sha):
            return last
        time.sleep(0.4)
    raise RuntimeError(f"timeout waiting for {role} health; last={last!r}")


def write_config(appdata: Path, role: str):
    cfg_dir = appdata / "RayClusterManager"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    ip = "192.0.2.27" if role == "head" else "192.0.2.28"
    cfg = {
        "schema_version": 9,
        "head_ip": "192.0.2.27",
        "head_port": 6379,
        "dashboard_port": 8265,
        "ray_exe": "auto",
        "this": {"role": role, "ip": ip, "num_cpus": 2},
        "nodes": [
            {"name": "SYNTHETIC_NODE_A", "ip": "192.0.2.27",
             "role": "head", "num_cpus": 12, "rdp_user": ""},
            {"name": "SYNTHETIC_NODE_C", "ip": "192.0.2.28",
             "role": "worker", "num_cpus": 12, "rdp_user": ""},
        ],
        "start_on_launch": False,
        "autostart_login": False,
        "watchdog_enabled": False,
        "temp_enabled": False,
        "metrics_enabled": True,
        "temp_port": PORT,
        "dashboard_timeout_sec": 1.0,
        "dashboard_unreachable_failures": 1,
        "dashboard_stale_grace_sec": 2.0,
        "poll_interval": 1.5,
        "on_close": "quit",
    }
    (cfg_dir / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")


def make_fake_owner(root: Path) -> subprocess.Popen:
    fake_dir = root / "fake_owner"
    fake_dir.mkdir(parents=True, exist_ok=True)
    fake_exe = fake_dir / "RayClusterManager.exe"
    shutil.copy2(sys.executable, fake_exe)
    script = fake_dir / "hold_mutex.py"
    script.write_text(
        "import ctypes, time\n"
        "k32=ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "h=k32.CreateMutexW(None, False, "
        "'Global\\\\RayClusterManager_singleton')\n"
        "print('READY', flush=True)\n"
        "while True: time.sleep(1)\n",
        encoding="utf-8")
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    proc = subprocess.Popen(
        [str(fake_exe), str(script)], cwd=str(fake_dir),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", startupinfo=si)
    line = proc.stdout.readline().strip() if proc.stdout else ""
    if line != "READY":
        raise RuntimeError(f"fake owner did not start: {line}")
    return proc


def start_official(envroot: Path) -> subprocess.Popen:
    env = os.environ.copy()
    env["APPDATA"] = str(envroot / "Roaming")
    env["LOCALAPPDATA"] = str(envroot / "Local")
    env["TEMP"] = str(envroot / "Temp")
    env["TMP"] = str(envroot / "Temp")
    env["RCM_SKIP_UAC_FOR_TESTS"] = "1"
    for key in ("APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        Path(env[key]).mkdir(parents=True, exist_ok=True)
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return subprocess.Popen(
        [str(OFFICIAL_EXE)], cwd=str(OFFICIAL_EXE.parent),
        env=env, startupinfo=si)


def run_packaged_role(role: str, expected_sha: str) -> dict:
    envroot = Path(tempfile.mkdtemp(prefix=f"rcm_stale_{role}_"))
    fake = None
    official = None
    row = {"role": role}
    try:
        for sub in ("Roaming", "Local", "Temp"):
            (envroot / sub).mkdir(parents=True, exist_ok=True)
        write_config(envroot / "Roaming", role)
        fake = make_fake_owner(envroot)
        row["fake_pid"] = fake.pid
        row["fake_health_before"] = health(timeout=0.25)
        row["pids_before_new"] = list_rcm_pids()
        official = start_official(envroot)
        row["launcher_pid"] = official.pid
        h = wait_health(role, expected_sha)
        row.update({
            "health_pid": h.get("pid"),
            "version": h.get("version"),
            "tag": h.get("build_tag"),
            "health_role": h.get("role"),
            "local_ip": h.get("local_ip"),
            "sha256": str(h.get("sha256") or "").upper(),
        })
        time.sleep(0.8)
        row["fake_alive_after"] = fake.poll() is None
        row["pids_after_repair"] = list_rcm_pids()
        row["passed"] = (
            row["fake_health_before"] is None
            and not row["fake_alive_after"]
            and row["version"] == EXPECTED_VERSION
            and row["tag"] == EXPECTED_TAG
            and row["health_role"] == role
            and row["sha256"] == expected_sha
            and int(row["health_pid"] or 0) in row["pids_after_repair"]
        )
        if not row["passed"]:
            raise AssertionError(row)
        return row
    finally:
        h = health(timeout=0.4)
        if h and h.get("pid"):
            kill_pid(int(h["pid"]))
        for proc in (official, fake):
            if proc and proc.poll() is None:
                kill_pid(proc.pid)
        time.sleep(1.0)
        shutil.rmtree(envroot, ignore_errors=True)


def run_source_contracts() -> list[dict]:
    import ray_monitor

    original = {
        "frozen": getattr(ray_monitor.sys, "frozen", None),
        "health": ray_monitor._local_rcm_health,
        "targets": ray_monitor._replacement_targets_from_processes,
        "expected": ray_monitor._local_health_server_expected,
        "wait": ray_monitor._wait_for_local_rcm_health,
        "cleanup": ray_monitor._cleanup_duplicate_rcm_processes,
        "pids_checked": ray_monitor._rcm_process_pids_checked,
        "orphan_cleanup": ray_monitor._kill_orphan_ray_python_processes,
        "subprocess_run": ray_monitor.subprocess.run,
        "admin": ray_monitor._is_admin,
    }
    results: list[dict] = []
    try:
        setattr(ray_monitor.sys, "frozen", True)
        ray_monitor._local_rcm_health = lambda timeout=1.5: (None, "down")
        ray_monitor._replacement_targets_from_processes = (
            lambda: ([], [12345], [], "pid 12345: current build"))
        ray_monitor._wait_for_local_rcm_health = (
            lambda grace_sec=6.0, timeout=0.6: (None, "still down"))
        ray_monitor._is_admin = lambda: False

        calls = []

        def cleanup_ok(*_args, **kwargs):
            calls.append((kwargs.get("target_pids"),
                          kwargs.get("cleanup_ray_orphans")))
            return True, "closed duplicate RCM pid(s): 12345"

        ray_monitor._cleanup_duplicate_rcm_processes = cleanup_ok
        ray_monitor._local_health_server_expected = lambda: True
        replaced, msg, needs_admin = ray_monitor._try_replace_stale_rcm_instance()
        assert replaced and not needs_admin and calls == [([12345], None)], (
            replaced, msg, calls)
        results.append({"source_contract": "same_build_no_health_replaced", "passed": True})

        calls.clear()
        ray_monitor._local_health_server_expected = lambda: False
        replaced, msg, needs_admin = ray_monitor._try_replace_stale_rcm_instance()
        assert not replaced and not needs_admin and not calls, (replaced, msg, calls)
        results.append({"source_contract": "health_disabled_same_build_kept", "passed": True})

        # Model the elevated child closing its non-admin elevation parent.  The
        # duplicate process disappears, while Ray orphan cleanup must never be
        # invoked as part of duplicate cleanup.
        parent_pid = 37832
        snapshots = iter([
            ([ray_monitor.os.getpid(), parent_pid], ""),
            ([ray_monitor.os.getpid()], ""),
        ])
        ray_monitor._rcm_process_pids_checked = lambda: next(snapshots)
        ray_cleanup_calls = []
        ray_monitor._kill_orphan_ray_python_processes = (
            lambda *_args, **_kwargs: ray_cleanup_calls.append(True) or 0)
        ray_monitor.subprocess.run = lambda *_args, **_kwargs: type(
            "Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        ok, cleanup_msg = original["cleanup"](
            target_pids=[parent_pid], wait_sec=0.5)
        assert ok and not ray_cleanup_calls, (cleanup_msg, ray_cleanup_calls)
        results.append({
            "source_contract": "elevation_parent_cleanup_preserves_ray",
            "passed": True,
        })
    finally:
        if original["frozen"] is None:
            try:
                delattr(ray_monitor.sys, "frozen")
            except AttributeError:
                pass
        else:
            setattr(ray_monitor.sys, "frozen", original["frozen"])
        ray_monitor._local_rcm_health = original["health"]
        ray_monitor._replacement_targets_from_processes = original["targets"]
        ray_monitor._local_health_server_expected = original["expected"]
        ray_monitor._wait_for_local_rcm_health = original["wait"]
        ray_monitor._cleanup_duplicate_rcm_processes = original["cleanup"]
        ray_monitor._rcm_process_pids_checked = original["pids_checked"]
        ray_monitor._kill_orphan_ray_python_processes = original["orphan_cleanup"]
        ray_monitor.subprocess.run = original["subprocess_run"]
        ray_monitor._is_admin = original["admin"]
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-packaged", action="store_true")
    args = parser.parse_args()

    results = {"source_contracts": run_source_contracts()}
    if not args.skip_packaged:
        if not OFFICIAL_EXE.exists():
            raise SystemExit(f"missing official exe: {OFFICIAL_EXE}")
        existing = list_rcm_pids()
        if existing:
            raise SystemExit(
                f"abort: existing RayClusterManager.exe before test: {existing}")
        expected_sha = sha256(OFFICIAL_EXE)
        packaged = []
        try:
            for role in ("head", "worker"):
                packaged.append(run_packaged_role(role, expected_sha))
        finally:
            for pid in list_rcm_pids():
                kill_pid(pid)
        results["expected_sha"] = expected_sha
        results["packaged"] = packaged
        results["leftovers"] = list_rcm_pids()
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
