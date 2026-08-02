"""
sensor_poller.py — RCM v1.1 LHM-embedded temperature poller.

Uses pythonnet to call LibreHardwareMonitorLib.dll directly (no separate LHM
exe needed). Returns normalized {cpu_pkg, cpu_max, gpu, ts} dict.

Requires admin privileges to read CPU temperatures (PawnIO kernel driver).
Returns 0.0 / None values gracefully when admin not granted.

Generic parser priority (validated against 7535HS / 7950X / i5-10500):
  cpu_pkg:  "Package" > "CPU Package" > "Core (Tctl/Tdie)" > first temp sensor
  cpu_max:  "CCDs Max (Tdie)" > "Core Max" > cpu_pkg
  gpu:      nvidia-smi (NVIDIA dGPU only, AMD iGPU ignored)
  storage:  composite/primary temperature from the physical SSD containing C:
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# --- LHM constants (paths relative to bundled exe) -----------------------
_LHM_SUBDIR = "lhm"  # PyInstaller bundles LHM DLLs under this folder
_LHM_DLL = "LibreHardwareMonitorLib.dll"

_CREATE_NO_WINDOW = 0x08000000

# Sensor name priority for cpu_pkg (first match wins)
_CPU_PKG_PRIORITY = (
    "Package",
    "CPU Package",
    "Core (Tctl/Tdie)",
)
_CPU_MAX_PRIORITY = (
    "CCDs Max (Tdie)",   # Ryzen Zen 4/5 (7950X)
    "Core Max",          # Intel (i5-10500)
    "CCDs Average (Tdie)",
)
# Intel exposes per-core sensors as "CPU Core #1" .. "CPU Core #N" — used
# as fallback to compute max() over individual cores when no priority name
# matches (v1.2.1 fix).
_CPU_CORE_PREFIX = ("CPU Core #", "Core #")


# =========================================================================
@dataclass
class TempReading:
    cpu_pkg: Optional[float] = None
    cpu_max: Optional[float] = None
    gpu: Optional[float] = None
    cpu_name: str = ""
    gpu_name: str = ""
    storage_temps_c: dict[str, float] = field(default_factory=dict)
    ts: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        # v1.2.1: coerce non-finite (NaN/Inf) to None — strict JSON clients reject them
        import math
        def _safe(x):
            if x is None or (isinstance(x, float) and not math.isfinite(x)):
                return None
            return x
        return {
            "cpu_pkg": _safe(self.cpu_pkg),
            "cpu_max": _safe(self.cpu_max),
            "gpu": _safe(self.gpu),
            "cpu_name": self.cpu_name,
            "gpu_name": self.gpu_name,
            "storage_temps_c": {
                str(drive): _safe(value)
                for drive, value in self.storage_temps_c.items()
                if _safe(value) is not None
            },
            "ts": self.ts,
            "error": self.error,
        }


# =========================================================================
def _bundled_lhm_dir() -> str:
    base = getattr(sys, "_MEIPASS", None)
    if base is None:
        base = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(base, _LHM_SUBDIR)
    if os.path.exists(p):
        return p
    # dev fallback: assume LHM portable on Desktop
    return os.path.expandvars(r"%USERPROFILE%\Desktop\LibreHardwareMonitor")


class LHMSensorPoller:
    """
    Holds a live LibreHardwareMonitor `Computer` instance.

    Thread-safe single-instance polling. Open() once at startup, then call
    read() periodically. Closes cleanly on shutdown.
    """

    def __init__(self):
        self._computer = None
        # v1.2.1: RLock — read() may call open() while holding the lock
        self._lock = threading.RLock()
        self._opened = False
        self._open_error: Optional[str] = None
        self._last_open_fail_ts: float = 0.0

    def open(self) -> Optional[str]:
        """Returns None on success, error string on failure."""
        with self._lock:
            if self._opened:
                return None
            try:
                lhm_dir = _bundled_lhm_dir()
                dll = os.path.join(lhm_dir, _LHM_DLL)
                if not os.path.exists(dll):
                    return f"LHM dll not found: {dll}"

                sys.path.insert(0, lhm_dir)
                import clr  # noqa: F401  (pythonnet)
                clr.AddReference(dll)
                from LibreHardwareMonitor.Hardware import Computer

                c = Computer()
                c.IsCpuEnabled = True
                c.IsGpuEnabled = True
                c.IsMotherboardEnabled = False
                c.IsStorageEnabled = True
                c.IsMemoryEnabled = False
                c.IsNetworkEnabled = False
                c.IsControllerEnabled = False
                c.IsBatteryEnabled = False
                c.Open()

                self._computer = c
                self._opened = True
                return None
            except Exception as exc:
                self._open_error = f"{type(exc).__name__}: {exc}"
                return self._open_error

    def close(self):
        with self._lock:
            if self._computer is not None:
                try:
                    self._computer.Close()
                except Exception:
                    pass
            self._computer = None
            self._opened = False

    def read(self) -> TempReading:
        """Single non-blocking read. Caller should run in a thread."""
        r = TempReading(ts=time.time())
        with self._lock:
            if not self._opened:
                # v1.2.1: backoff retry — don't spam open() on persistent failure
                now = time.time()
                if (self._open_error and
                        now - self._last_open_fail_ts < 30.0):
                    r.error = self._open_error
                    return r
                err = self.open()
                if err:
                    self._last_open_fail_ts = now
                    r.error = err
                    return r
            c = self._computer

        try:
            cpu_pkg_val: Optional[float] = None
            cpu_pkg_key: str = ""
            cpu_max_val: Optional[float] = None
            cpu_max_key: str = ""
            cpu_per_core_max: Optional[float] = None  # v1.2.1: Intel fallback
            gpu_val: Optional[float] = None
            gpu_name: str = ""
            storage_temps_c: dict[str, float] = {}

            # iterate hardware
            for hw in c.Hardware:
                hw_type = str(hw.HardwareType)
                try:
                    hw.Update()
                except Exception:
                    # Storage telemetry is additive.  A drive/driver that does
                    # not expose SMART must not blank otherwise healthy CPU or
                    # GPU readings for the node.
                    if hw_type == "Storage":
                        continue
                    raise
                is_cpu = (hw_type == "Cpu")
                is_gpu_nvidia = (hw_type == "GpuNvidia")
                is_storage = (hw_type == "Storage")
                if not (is_cpu or is_gpu_nvidia or is_storage):
                    continue

                if is_storage:
                    # LibreHardwareMonitor 0.9.6 exposes the backing physical
                    # disk's partitions.  Match by drive letter so a second SSD
                    # can never be mistaken for the Windows (C:) SSD.
                    if "C:" in _storage_drive_letters(hw):
                        value = _primary_storage_temp_c(hw)
                        if value is not None:
                            storage_temps_c["C:"] = value
                    continue

                if is_cpu and not r.cpu_name:
                    r.cpu_name = hw.Name
                if is_gpu_nvidia and not gpu_name:
                    gpu_name = hw.Name

                for s in hw.Sensors:
                    if str(s.SensorType) != "Temperature":
                        continue
                    if s.Value is None:
                        continue
                    name = s.Name
                    val = float(s.Value)
                    if val <= 0 or val > 150:
                        continue  # filter ghost values

                    if is_cpu:
                        # cpu_pkg: prefer earlier priority match
                        if name in _CPU_PKG_PRIORITY:
                            new_rank = _CPU_PKG_PRIORITY.index(name)
                            cur_rank = (_CPU_PKG_PRIORITY.index(cpu_pkg_key)
                                        if cpu_pkg_key in _CPU_PKG_PRIORITY
                                        else 999)
                            if new_rank < cur_rank:
                                cpu_pkg_val = val
                                cpu_pkg_key = name
                        # cpu_max: prefer earlier priority match
                        if name in _CPU_MAX_PRIORITY:
                            new_rank = _CPU_MAX_PRIORITY.index(name)
                            cur_rank = (_CPU_MAX_PRIORITY.index(cpu_max_key)
                                        if cpu_max_key in _CPU_MAX_PRIORITY
                                        else 999)
                            if new_rank < cur_rank:
                                cpu_max_val = val
                                cpu_max_key = name
                        # v1.2.1: track per-core max (Intel fallback)
                        if any(name.startswith(p) for p in _CPU_CORE_PREFIX):
                            if cpu_per_core_max is None or val > cpu_per_core_max:
                                cpu_per_core_max = val

                    elif is_gpu_nvidia:
                        # take the highest GPU temperature reading
                        if gpu_val is None or val > gpu_val:
                            gpu_val = val

            # fallback: if no priority name matched, pick the first CPU temp
            if cpu_pkg_val is None or cpu_max_val is None:
                for hw in c.Hardware:
                    if str(hw.HardwareType) != "Cpu":
                        continue
                    for s in hw.Sensors:
                        if (str(s.SensorType) == "Temperature"
                                and s.Value is not None):
                            v = float(s.Value)
                            if 0 < v < 150:
                                if cpu_pkg_val is None:
                                    cpu_pkg_val = v
                                if cpu_max_val is None:
                                    cpu_max_val = v
                                break
                    break

            r.cpu_pkg = cpu_pkg_val
            # v1.2.1: cpu_max resolution order — priority key > per-core max
            # (Intel) > cpu_pkg (last resort)
            r.cpu_max = (cpu_max_val
                         if cpu_max_val is not None
                         else cpu_per_core_max
                         if cpu_per_core_max is not None
                         else cpu_pkg_val)
            r.gpu_name = gpu_name
            r.gpu = gpu_val if gpu_val is not None else _nvidia_smi_temp()
            r.storage_temps_c = storage_temps_c
        except Exception as exc:
            r.error = f"{type(exc).__name__}: {exc}"
        return r


def _normalize_drive_letter(value) -> str:
    text = str(value or "").strip().upper()
    if len(text) == 1 and text.isalpha():
        return f"{text}:"
    if len(text) >= 2 and text[0].isalpha() and text[1] == ":":
        return text[:2]
    return ""


def _member_value(obj, name):
    """Read ``obj.<name>`` across pythonnet's static-type boundary.

    v1.07.16c [retrofit]: pythonnet 3.x wraps ``Computer.Hardware`` items as
    the declared interface type (``IHardware``), so concrete-class members
    such as ``StorageDevice.Storage`` raise AttributeError on direct access.
    .NET reflection against the runtime type reaches them reliably, and the
    returned object is wrapped by its runtime class, so subsequent member
    access works directly.  Returns None when the member cannot be read.
    """
    try:
        return getattr(obj, name)
    except AttributeError:
        pass
    except Exception:
        return None
    try:
        prop = obj.GetType().GetProperty(name)
        if prop is None:
            return None
        return prop.GetValue(obj)
    except Exception:
        return None


def _storage_drive_letters(hw) -> set[str]:
    """Return logical drive letters backed by one LHM physical disk."""
    letters: set[str] = set()
    storage = _member_value(hw, "Storage")
    if storage is None:
        return letters
    partitions = _member_value(storage, "Partitions")
    if partitions is None:
        return letters
    try:
        for partition in partitions:
            drive = _normalize_drive_letter(
                _member_value(partition, "DriveLetter"))
            if drive:
                letters.add(drive)
    except Exception:
        return letters
    return letters


def _primary_storage_temp_c(hw) -> Optional[float]:
    """Pick the SSD's operational temperature, excluding limit sensors."""
    candidates: list[tuple[int, float]] = []
    for sensor in getattr(hw, "Sensors", ()):
        try:
            if str(sensor.SensorType) != "Temperature" or sensor.Value is None:
                continue
            name = str(sensor.Name or "").strip()
            lower = name.lower()
            if "warning" in lower or "critical" in lower:
                continue
            value = float(sensor.Value)
            if not 0 < value < 150:
                continue
            if name == "Composite Temperature":
                rank = 0
            elif name == "Temperature":
                rank = 1
            elif name.startswith("Temperature #"):
                rank = 2
            else:
                rank = 3
            candidates.append((rank, value))
        except Exception:
            continue
    return min(candidates, key=lambda item: item[0])[1] if candidates else None


# =========================================================================
def _nvidia_smi_temp() -> Optional[float]:
    """Fallback GPU temp via nvidia-smi (NVIDIA only)."""
    try:
        p = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2,
            creationflags=_CREATE_NO_WINDOW,
        )
        if p.returncode == 0:
            line = (p.stdout or "").strip().splitlines()[0].strip()
            if line:
                return float(line)
    except Exception:
        pass
    return None


# =========================================================================
# Singleton accessor + non-blocking thread wrapper
# =========================================================================
_poller: Optional[LHMSensorPoller] = None
_last_reading: TempReading = TempReading(ts=0.0)
_poll_thread: Optional[threading.Thread] = None
_stop_event = threading.Event()


def get_poller() -> LHMSensorPoller:
    global _poller
    if _poller is None:
        _poller = LHMSensorPoller()
    return _poller


def start_background_poll(interval_sec: float = 2.0):
    """Start a daemon thread that updates _last_reading every interval."""
    global _poll_thread
    if _poll_thread is not None and _poll_thread.is_alive():
        return
    _stop_event.clear()
    p = get_poller()

    def loop():
        global _last_reading
        while not _stop_event.is_set():
            try:
                _last_reading = p.read()
            except Exception:
                pass
            _stop_event.wait(timeout=interval_sec)

    _poll_thread = threading.Thread(target=loop, daemon=True, name="LHMPoll")
    _poll_thread.start()


def stop_background_poll():
    global _poll_thread
    _stop_event.set()
    p = _poller
    if p is not None:
        p.close()
    t = _poll_thread
    if t is not None and t.is_alive():
        try:
            t.join(timeout=2.0)
        except Exception:
            pass
    if t is not None and not t.is_alive():
        _poll_thread = None


def last() -> TempReading:
    return _last_reading


# =========================================================================
# CLI test mode
# =========================================================================
if __name__ == "__main__":
    print("LHM sensor_poller test")
    p = get_poller()
    err = p.open()
    if err:
        print(f"OPEN FAILED: {err}")
        sys.exit(1)
    for i in range(3):
        r = p.read()
        print(f"\n[read {i+1}]  {r.to_dict()}")
        time.sleep(1)
    p.close()
    print("\nclosed.")
