"""Safe, on-demand discovery and cleanup of residual Windows process trees.

The engine is deliberately local-only and fail-closed.  High CPU or RAM usage
is impact information, never sufficient evidence that a process is unwanted.
Candidates are grouped and scored from lifecycle, process-tree, window,
network, age, and recognized development-workload evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import getpass
import hashlib
import os
import re
import threading
import time
from typing import Iterable, Optional, Sequence

try:
    import psutil
except Exception:  # pragma: no cover - packaged RCM always includes psutil
    psutil = None


_IS_WIN = os.name == "nt"
CLASS_RECOMMENDED = "Recommended"
CLASS_REVIEW = "Review"
CLASS_INFO = "Info"
CLASS_PROTECTED = "Protected"

_WRAPPER_NAMES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
    "node.exe", "python.exe", "pythonw.exe", "java.exe", "javaw.exe",
    "dotnet.exe", "npm.exe", "npx.exe", "yarn.exe", "pnpm.exe",
}
_CRITICAL_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe",
    "taskhostw.exe", "explorer.exe", "securityhealthservice.exe",
    "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe",
    "audiodg.exe", "searchindexer.exe",
}
_RCM_RAY_NAMES = {
    "rayclustermanager.exe", "raylet.exe", "gcs_server.exe",
    "plasma_store_server.exe", "dashboard.exe",
}
_REMOTE_CONTROL_NAMES = {
    "tailscale.exe", "tailscaled.exe", "mstsc.exe", "termsrv.exe",
}
_SENSITIVE_COMMAND_WORDS = (
    "password", "passwd", "pwd", "token", "secret", "api-key", "apikey",
    "api_key", "access-key", "access_key", "client-secret", "credential",
    "authorization",
)
_LOOPBACKS = {"127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}


@dataclass(frozen=True)
class WorkloadMatch:
    kind: str = ""
    label: str = ""
    recognized: bool = False
    recommendable: bool = False


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float
    exe_path: str
    command_fingerprint: str


@dataclass(frozen=True)
class ConnectionRecord:
    status: str = ""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0

    @property
    def established(self) -> bool:
        # Any remote endpoint means the process has or is establishing a
        # peer relationship.  Treat half-open/closing TCP and connected UDP
        # conservatively too; only endpoint-free listeners are considered idle.
        return bool(self.remote_ip or self.remote_port)

    @property
    def listening(self) -> bool:
        return self.status.upper() == "LISTEN"

    @property
    def loopback_listener(self) -> bool:
        return self.listening and self.local_ip in _LOOPBACKS


@dataclass
class ProcessRecord:
    pid: int
    ppid: int = 0
    create_time: float = 0.0
    name: str = ""
    exe_path: str = ""
    cmdline: tuple[str, ...] = ()
    safe_command: str = ""
    command_fingerprint: str = ""
    username: str = ""
    session_id: Optional[int] = None
    cwd: str = ""
    cpu_time: float = 0.0
    cpu_pct: float = 0.0
    memory_bytes: int = 0
    visible_window: bool = False
    foreground: bool = False
    service: bool = False
    connections: tuple[ConnectionRecord, ...] = ()
    workload: WorkloadMatch = field(default_factory=WorkloadMatch)
    project_root: str = ""
    protected_reason: str = ""
    accessible: bool = True

    @property
    def identity(self) -> ProcessIdentity:
        return ProcessIdentity(
            int(self.pid), float(self.create_time),
            normalize_path(self.exe_path), self.command_fingerprint)

    @property
    def age_sec(self) -> float:
        return max(0.0, time.time() - float(self.create_time or 0.0))


@dataclass
class CleanupCandidate:
    group_id: str
    root: ProcessIdentity
    members: tuple[ProcessIdentity, ...]
    member_pids: tuple[int, ...]
    label: str
    classification: str
    score: int
    reasons: tuple[str, ...]
    cpu_pct: float
    memory_bytes: int
    age_sec: float
    workload_kind: str = ""
    project_root: str = ""
    ports: tuple[int, ...] = ()
    active_connection: bool = False
    protected_reason: str = ""
    safe_command: str = ""
    scanned_monotonic: float = 0.0

    @property
    def recommended(self) -> bool:
        return self.classification == CLASS_RECOMMENDED


@dataclass
class ScanResult:
    candidates: list[CleanupCandidate]
    process_count: int
    sample_sec: float
    started_at: float
    finished_at: float
    cancelled: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def recommended_count(self) -> int:
        return sum(item.recommended for item in self.candidates)


@dataclass
class TerminationItem:
    group_id: str
    label: str
    status: str
    message: str = ""
    ended_pids: tuple[int, ...] = ()
    remaining_pids: tuple[int, ...] = ()
    memory_bytes: int = 0
    cpu_pct: float = 0.0


@dataclass
class TerminationReport:
    items: list[TerminationItem]
    started_at: float
    finished_at: float
    cancelled: bool = False

    @property
    def ended_count(self) -> int:
        return sum(item.status == "Ended" for item in self.items)


@dataclass
class CleanupPolicy:
    sample_sec: float = 8.0
    grace_sec: float = 3.0
    result_max_age_sec: float = 60.0
    min_age_sec: float = 30.0 * 60.0
    recommend_score: int = 75
    review_score: int = 45
    heavy_cpu_pct: float = 1.0
    very_heavy_cpu_pct: float = 5.0
    heavy_memory_bytes: int = 200 * 1024 * 1024
    very_heavy_memory_bytes: int = 1024 * 1024 * 1024
    ignored_fingerprints: frozenset[str] = frozenset()


def normalize_path(path: str) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    try:
        return os.path.normcase(os.path.abspath(text))
    except Exception:
        return os.path.normcase(text)


def _joined_command(command: Sequence[str] | str) -> str:
    if isinstance(command, str):
        return command
    return " ".join(str(part) for part in command)


def redact_command_line(command: Sequence[str] | str) -> str:
    """Return a display-safe command line without common credential forms."""
    if not isinstance(command, str):
        parts = [str(value) for value in command]
        safe_parts: list[str] = []
        redact_next = False
        secret_names = "|".join(re.escape(word) for word in _SENSITIVE_COMMAND_WORDS)
        for part in parts:
            if redact_next:
                safe_parts.append("<redacted>")
                redact_next = False
                continue
            if re.fullmatch(
                    rf"(?i)--?(?:{secret_names})", part.strip()):
                safe_parts.append(part)
                redact_next = True
                continue
            if re.match(
                    rf"(?i)^--?(?:{secret_names})\s*=", part.strip()):
                safe_parts.append(re.sub(
                    r"^([^=]+=).*$", r"\1<redacted>", part))
                continue
            assignment = re.match(
                r"^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)$",
                part, re.DOTALL)
            if assignment:
                key_flat = re.sub(
                    r"[^a-z0-9]", "", assignment.group(1).casefold())
                if any(marker in key_flat for marker in (
                        "token", "secret", "password", "passwd", "apikey",
                        "accesskey", "clientsecret", "credential",
                        "authorization")):
                    safe_parts.append(
                        f"{assignment.group(1)}=<redacted>")
                    continue
            if re.search(r"(?i)\bauthorization\s*[:=]", part):
                safe_parts.append(re.sub(
                    r"(?i)(\bauthorization\s*[:=]\s*).*$",
                    r"\1<redacted>", part))
                continue
            if re.search(r"(?i)\bbearer\s+", part):
                safe_parts.append(re.sub(
                    r"(?i)(\bbearer\s+).*$", r"\1<redacted>", part))
                continue
            if part.strip().casefold() == "bearer":
                safe_parts.append(part)
                redact_next = True
                continue
            safe_parts.append(redact_command_line(part))
        if redact_next:
            # A dangling secret flag has no value to expose.
            pass
        return " ".join(safe_parts)
    text = _joined_command(command)
    if not text:
        return ""
    secret = "|".join(re.escape(word) for word in _SENSITIVE_COMMAND_WORDS)
    value = r"(?:\"[^\"]*\"|'[^']*'|[^\s;&]+)"
    text = re.sub(
        r"(?i)(\b(?:authorization\s*[:=]\s*)?bearer\s+)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1<redacted>", text)
    text = re.sub(
        rf"(?i)(--?(?:{secret})\s*=\s*){value}",
        r"\1<redacted>", text)
    text = re.sub(
        rf"(?i)(--?(?:{secret})\s+){value}",
        r"\1<redacted>", text)
    text = re.sub(
        rf"(?i)(\b(?:{secret})\s*[:=]\s*){value}",
        r"\1<redacted>", text)
    text = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/@\s]+)@",
        r"\1<redacted>:<redacted>@", text)
    text = re.sub(
        r"(?i)(\b[a-z0-9_.-]*(?:token|secret|password|passwd|api[_-]?key|"
        r"access[_-]?key|client[_-]?secret|credential|authorization)"
        r"[a-z0-9_.-]*\s*=\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s;&]+)",
        r"\1<redacted>", text)
    text = re.sub(
        rf"(?i)([?&](?:{secret})=)([^&#\s]+)",
        r"\1<redacted>", text)
    return text


def command_fingerprint(command: Sequence[str] | str) -> str:
    raw = _joined_command(command).strip()
    if not raw:
        return ""
    normalized = re.sub(r"\s+", " ", raw).casefold()
    return hashlib.sha256(normalized.encode("utf-8", "surrogatepass")).hexdigest()


def recognize_workload(command: Sequence[str] | str, name: str = "") -> WorkloadMatch:
    """Recognize extensible development/runtime patterns, never projects."""
    if isinstance(command, str):
        parts = tuple(
            value.strip("\"'") for value in re.findall(
                r'"[^"]*"|\'[^\']*\'|\S+', command))
    else:
        parts = tuple(str(value) for value in command)
    low_parts = tuple(value.casefold() for value in parts)
    low = (" " + " ".join(low_parts) + " ")
    process_name = str(name or "").casefold()

    def base(value: str) -> str:
        normalized = value.replace("\\", "/").rstrip("/")
        return normalized.rsplit("/", 1)[-1].casefold()

    runners = {
        "npm", "npm.cmd", "npm.exe", "npm-cli.js",
        "npx", "npx.cmd", "npx.exe",
        "pnpm", "pnpm.cmd", "pnpm.exe",
        "yarn", "yarn.cmd", "yarn.exe",
    }

    def runner_invokes(runner_index: int, tool_index: int) -> bool:
        runner = base(low_parts[runner_index])
        between = low_parts[runner_index + 1:tool_index]
        if runner in {"npm", "npm.cmd", "npm.exe", "npm-cli.js"}:
            return len(between) == 1 and between[0] == "exec"
        if runner in {"npx", "npx.cmd", "npx.exe"}:
            return not between
        if runner in {"pnpm", "pnpm.cmd", "pnpm.exe"}:
            return not between or between in (("exec",), ("dlx",))
        if runner in {"yarn", "yarn.cmd", "yarn.exe"}:
            return not between or between == ("dlx",)
        return False

    def tool(name_: str) -> bool:
        aliases = {
            name_, f"{name_}.js", f"{name_}.mjs", f"{name_}.cjs",
            f"{name_}.cmd", f"{name_}.exe",
        }
        if low_parts and base(low_parts[0]) in aliases:
            return True
        first = base(low_parts[0]) if low_parts else ""
        if first in {"cmd", "cmd.exe", "powershell", "powershell.exe",
                     "pwsh", "pwsh.exe"}:
            control = next(
                (index for index, value in enumerate(low_parts)
                 if value in {"/c", "-c", "-command"}),
                -1)
            if control >= 0 and control + 1 < len(low_parts):
                tail = " ".join(low_parts[control + 1:]).replace("\\", "/")
                alias_pattern = (
                    rf"(?:{re.escape(name_)})"
                    rf"(?:\.(?:js|mjs|cjs|cmd|exe))?")
                if re.match(
                        rf"^(?:\"?[^\s\"]*/)?{alias_pattern}(?:\s|$)",
                        tail):
                    return True
                if re.search(
                        rf"(?:npm|npx|pnpm|yarn)(?:\.cmd|\.exe)?"
                        rf"(?:\s+exec)?\s+{alias_pattern}(?:\s|$)",
                        tail):
                    return True
        for index, value in enumerate(low_parts):
            pathish = value.replace("\\", "/")
            if f"/node_modules/{name_}/" in pathish:
                return True
            if base(value) in aliases:
                if index == 1 and low_parts and base(low_parts[0]) in {
                        "node", "node.exe"}:
                    return True
                if any(
                        base(low_parts[runner_index]) in runners
                        and runner_invokes(runner_index, index)
                        for runner_index in range(index)):
                    return True
        return False

    def module(name_: str) -> bool:
        return any(
            value == "-m" and index + 1 < len(low_parts)
            and base(low_parts[index + 1]) == name_
            for index, value in enumerate(low_parts))

    if tool("astro") and " dev " in low:
        return WorkloadMatch(
            "astro-dev", "Astro development server", True, True)
    if tool("vite") and " build " not in low:
        return WorkloadMatch(
            "vite-dev", "Vite development server", True, True)
    if tool("next") and " dev " in low:
        return WorkloadMatch(
            "next-dev", "Next.js development server", True, True)
    if tool("webpack") and " serve " in low:
        return WorkloadMatch(
            "webpack-dev", "webpack development server", True, True)
    patterns: tuple[tuple[str, str, bool, tuple[str, ...]], ...] = (
        ("spring-dev", "Spring development server", False,
         (" spring-boot:run",)),
        ("quarkus-dev", "Quarkus development server", False,
         (" quarkus:dev",)),
    )
    if tool("react-scripts") and " start " in low:
        return WorkloadMatch(
            "react-dev", "React development server", True, True)
    if module("http.server"):
        return WorkloadMatch(
            "python-http", "Python HTTP development server", True, True)
    if tool("uvicorn") or module("uvicorn"):
        return WorkloadMatch(
            "uvicorn-dev", "Uvicorn development server", True,
            "--reload" in low_parts or "--reload-dir" in low_parts)
    if (tool("flask") or module("flask")) and " run " in low:
        return WorkloadMatch(
            "flask-dev", "Flask development server", True, True)
    if (any(base(value) == "manage.py" for value in low_parts)
            and " runserver " in low):
        return WorkloadMatch(
            "django-dev", "Django development server", True, True)
    if tool("jupyter") or module("jupyter"):
        return WorkloadMatch("jupyter", "Jupyter session", True, False)
    if ((tool("streamlit") or module("streamlit")) and " run " in low):
        return WorkloadMatch(
            "streamlit", "Streamlit development server", True, False)
    first_base = base(low_parts[0]) if low_parts else ""
    if first_base in {"dotnet", "dotnet.exe"} and " watch " in low:
        return WorkloadMatch(
            "dotnet-watch", ".NET watch process", True, False)
    if first_base in {"dotnet", "dotnet.exe"} and " run " in low:
        return WorkloadMatch(
            "dotnet-run", ".NET run process", True, False)
    if first_base in {
            "gradle", "gradle.exe", "gradle.bat", "gradlew", "gradlew.bat"}:
        return WorkloadMatch(
            "gradle-dev", "Gradle development process", True, False)
    for kind, label, recommendable, needles in patterns:
        if all(needle in low for needle in needles):
            return WorkloadMatch(kind, label, True, recommendable)
    # npm/pnpm/yarn "dev" wrappers remain generic unless their child reveals
    # the concrete tool. They are still useful lifecycle evidence.
    if (" dev " in low and any(tool in low for tool in (
            " npm ", " npm-cli", " npx ", " pnpm ", " yarn "))):
        return WorkloadMatch(
            "generic-js-dev", "JavaScript development task", True, False)
    if process_name in {"java.exe", "javaw.exe", "dotnet.exe"}:
        return WorkloadMatch(
            "generic-dev-runtime", "Development runtime", False, False)
    return WorkloadMatch()


def _extract_project_root(command: Sequence[str] | str, cwd: str = "") -> str:
    if cwd:
        return normalize_path(cwd)
    for token in (
            list(command) if not isinstance(command, str) else [command]):
        clean = str(token or "").strip("\"'")
        low = clean.casefold()
        marker = low.find("\\node_modules\\")
        if marker < 0:
            marker = low.find("/node_modules/")
        if marker > 2:
            return normalize_path(clean[:marker])
        if re.match(r"(?i)^[a-z]:[\\/].+\.(py|js|mjs|cjs|jar|dll)$", clean):
            return normalize_path(os.path.dirname(clean))
    return ""


def _current_username() -> str:
    try:
        return getpass.getuser().casefold()
    except Exception:
        return ""


def _username_matches_current(username: str) -> bool:
    value = str(username or "").replace("/", "\\").casefold()
    current = _current_username()
    return bool(value and current and value.split("\\")[-1] == current)


def _process_session_id(pid: int) -> Optional[int]:
    if not _IS_WIN:
        return None
    value = wintypes.DWORD()
    try:
        ok = ctypes.windll.kernel32.ProcessIdToSessionId(
            wintypes.DWORD(int(pid)), ctypes.byref(value))
        return int(value.value) if ok else None
    except Exception:
        return None


def _window_state() -> tuple[set[int], set[int], str]:
    if not _IS_WIN:
        return set(), set(), ""
    visible: set[int] = set()
    foreground: set[int] = set()
    try:
        user32 = ctypes.windll.user32
        callback_type = ctypes.WINFUNCTYPE(
            wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def callback(hwnd, _lparam):
            if user32.IsWindowVisible(hwnd):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value:
                    visible.add(int(pid.value))
            return True

        callback_ref = callback_type(callback)
        if not user32.EnumWindows(callback_ref, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        hwnd = user32.GetForegroundWindow()
        if hwnd:
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                foreground.add(int(pid.value))
    except Exception as exc:
        return set(), set(), (
            f"window enumeration failed: {type(exc).__name__}")
    return visible, foreground, ""


def _service_pids() -> tuple[set[int], str]:
    if psutil is None or not _IS_WIN:
        return set(), ""
    pids: set[int] = set()
    partial = False
    try:
        for service in psutil.win_service_iter():
            try:
                # Only the PID is required. as_dict() also queries optional
                # description/configuration fields and can fail for protected
                # services even when their running PID is readable.
                pid = int(service.pid() or 0)
                if pid:
                    pids.add(pid)
            except FileNotFoundError:
                # Service was removed between enumeration and query.
                continue
            except Exception:
                partial = True
                continue
    except Exception as exc:
        return set(), f"service enumeration failed: {type(exc).__name__}"
    if partial:
        return pids, "one or more Windows services could not be inspected"
    return pids, ""


def _connection_map() -> tuple[dict[int, list[ConnectionRecord]], str]:
    result: dict[int, list[ConnectionRecord]] = {}
    if psutil is None:
        return result, "psutil unavailable"
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        return result, (
            f"network connection enumeration failed: {type(exc).__name__}")
    for item in connections:
        pid = int(getattr(item, "pid", 0) or 0)
        if not pid:
            continue
        laddr = getattr(item, "laddr", None)
        raddr = getattr(item, "raddr", None)
        local_ip = str(getattr(laddr, "ip", "") or (
            laddr[0] if isinstance(laddr, tuple) and laddr else ""))
        local_port = int(getattr(laddr, "port", 0) or (
            laddr[1] if isinstance(laddr, tuple) and len(laddr) > 1 else 0))
        remote_ip = str(getattr(raddr, "ip", "") or (
            raddr[0] if isinstance(raddr, tuple) and raddr else ""))
        remote_port = int(getattr(raddr, "port", 0) or (
            raddr[1] if isinstance(raddr, tuple) and len(raddr) > 1 else 0))
        result.setdefault(pid, []).append(ConnectionRecord(
            str(getattr(item, "status", "") or ""),
            local_ip, local_port, remote_ip, remote_port))
    return result, ""


def _own_process_tree_pids() -> tuple[set[int], str]:
    if psutil is None:
        return {os.getpid()}, "psutil unavailable"
    own = {os.getpid()}
    try:
        proc = psutil.Process(os.getpid())
        own.update(parent.pid for parent in proc.parents())
        own.update(child.pid for child in proc.children(recursive=True))
    except Exception as exc:
        return own, (
            f"RCM process tree enumeration failed: {type(exc).__name__}")
    return own, ""


def _protected_reason(record: ProcessRecord, own_pids: set[int],
                      current_session: Optional[int]) -> str:
    name = record.name.casefold()
    cmd = _joined_command(record.cmdline).casefold()
    path = normalize_path(record.exe_path)
    if record.pid in (0, 4):
        return "Windows kernel process"
    if record.pid in own_pids:
        return "RCM process tree"
    if name in _CRITICAL_NAMES:
        return "Windows critical or shell process"
    if name in _RCM_RAY_NAMES or "\\ray\\session_" in cmd or "/ray/session_" in cmd:
        return "managed by RCM/Ray"
    if name in _REMOTE_CONTROL_NAMES:
        return "remote management process"
    if record.service:
        return "Windows service"
    if record.visible_window or record.foreground:
        return "visible or foreground application"
    if not record.accessible or not path or not record.command_fingerprint:
        return "process identity unavailable"
    if _IS_WIN and (current_session is None or record.session_id is None):
        return "Windows session identity unavailable"
    if not _username_matches_current(record.username):
        return "different user or SYSTEM process"
    if (current_session is not None and record.session_id is not None
            and record.session_id != current_session):
        return "different Windows session"
    windows_dir = normalize_path(os.environ.get("WINDIR", r"C:\Windows"))
    # Command shells are user-workload wrappers even when they live under
    # Windows.  Protecting every cmd/PowerShell wrapper would hide the root of
    # practically every detached development tree.  Critical OS processes and
    # service-owned PIDs are already protected above.
    if (windows_dir and path.startswith(windows_dir + os.sep)
            and name not in {"cmd.exe", "powershell.exe", "pwsh.exe",
                             "conhost.exe"}):
        return "Windows component"
    return ""


def _snapshot_once() -> tuple[dict[int, ProcessRecord], list[str]]:
    if psutil is None:
        return {}, ["psutil unavailable"]
    errors: list[str] = []
    visible, foreground, window_error = _window_state()
    service_pids, service_error = _service_pids()
    connections, connection_error = _connection_map()
    own_pids, own_tree_error = _own_process_tree_pids()
    current_session = _process_session_id(os.getpid())
    errors.extend(error for error in (
        window_error, service_error, connection_error, own_tree_error)
                  if error)
    if _IS_WIN and current_session is None:
        errors.append("current Windows session identity unavailable")
    records: dict[int, ProcessRecord] = {}
    attrs = [
        "pid", "ppid", "name", "exe", "cmdline", "username",
        "create_time", "cpu_times", "memory_info",
    ]
    for proc in psutil.process_iter(attrs=attrs, ad_value=None):
        info = proc.info
        pid = int(info.get("pid") or 0)
        if not pid:
            continue
        accessible = True
        cmdline = tuple(str(value) for value in (info.get("cmdline") or ()))
        exe_path = str(info.get("exe") or "")
        create_time = float(info.get("create_time") or 0.0)
        if not exe_path or not create_time:
            accessible = False
        cpu_times = info.get("cpu_times")
        cpu_time = float(
            (getattr(cpu_times, "user", 0.0) or 0.0)
            + (getattr(cpu_times, "system", 0.0) or 0.0))
        mem = info.get("memory_info")
        memory_bytes = int(getattr(mem, "rss", 0) or 0)
        cwd = ""
        try:
            cwd = str(proc.cwd() or "")
        except Exception:
            pass
        rec = ProcessRecord(
            pid=pid,
            ppid=int(info.get("ppid") or 0),
            create_time=create_time,
            name=str(info.get("name") or ""),
            exe_path=exe_path,
            cmdline=cmdline,
            safe_command=redact_command_line(cmdline),
            command_fingerprint=command_fingerprint(cmdline),
            username=str(info.get("username") or ""),
            session_id=_process_session_id(pid),
            cwd=cwd,
            cpu_time=cpu_time,
            memory_bytes=memory_bytes,
            visible_window=pid in visible,
            foreground=pid in foreground,
            service=pid in service_pids,
            connections=tuple(connections.get(pid, ())),
            accessible=accessible,
        )
        rec.workload = recognize_workload(rec.cmdline, rec.name)
        rec.project_root = _extract_project_root(rec.cmdline, rec.cwd)
        rec.protected_reason = _protected_reason(
            rec, own_pids, current_session)
        records[pid] = rec
    return records, errors


def _same_identity(first: ProcessRecord, second: ProcessRecord) -> bool:
    return (
        first.pid == second.pid
        and abs(first.create_time - second.create_time) < 0.001
        and normalize_path(first.exe_path) == normalize_path(second.exe_path)
        and first.command_fingerprint == second.command_fingerprint
    )


def _valid_parent(record: ProcessRecord,
                  records: dict[int, ProcessRecord]) -> Optional[ProcessRecord]:
    parent = records.get(record.ppid)
    if parent is None:
        return None
    # A parent created after its child means the PPID has been reused.
    if parent.create_time > record.create_time + 0.5:
        return None
    return parent


def _children_map(records: dict[int, ProcessRecord]) -> dict[int, list[int]]:
    children: dict[int, list[int]] = {}
    for rec in records.values():
        if _valid_parent(rec, records) is not None:
            children.setdefault(rec.ppid, []).append(rec.pid)
    return children


def _descendants(root_pid: int, children: dict[int, list[int]]) -> list[int]:
    result: list[int] = []
    stack = list(children.get(root_pid, ()))
    seen = {root_pid}
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        result.append(pid)
        stack.extend(children.get(pid, ()))
    return result


def _candidate_root(anchor: ProcessRecord,
                    records: dict[int, ProcessRecord]) -> ProcessRecord:
    current = anchor
    while True:
        parent = _valid_parent(current, records)
        if parent is None or parent.protected_reason:
            return current
        parent_known = parent.workload.recognized
        # Name and start-time proximity do not prove ownership.  An
        # interactive shell/runtime can have unrelated sibling processes.
        # Only climb through a parent whose command is itself recognized.
        if not parent_known:
            return current
        current = parent


def _has_active_connection(records: Iterable[ProcessRecord]) -> bool:
    return any(conn.established for rec in records for conn in rec.connections)


def _has_external_listener(records: Iterable[ProcessRecord]) -> bool:
    return any(
        conn.listening and not conn.loopback_listener
        for rec in records for conn in rec.connections)


def _listener_ports(records: Iterable[ProcessRecord]) -> tuple[int, ...]:
    ports = {
        conn.local_port for rec in records for conn in rec.connections
        if conn.listening and conn.local_port
    }
    return tuple(sorted(ports))


def _has_loopback_listener(records: Iterable[ProcessRecord]) -> bool:
    return any(
        conn.loopback_listener
        for rec in records for conn in rec.connections)


def _group_project(records: Iterable[ProcessRecord]) -> str:
    projects = [
        rec.project_root for rec in records
        if rec.project_root and rec.workload.recognized
    ]
    return min(projects, key=len) if projects else ""


def _group_workload(records: Iterable[ProcessRecord]) -> WorkloadMatch:
    matches = [rec.workload for rec in records if rec.workload.recognized]
    if not matches:
        return WorkloadMatch()
    matches.sort(key=lambda item: (item.recommendable, item.kind != "generic-js-dev"),
                 reverse=True)
    return matches[0]


def evaluate_records(records: dict[int, ProcessRecord], policy: CleanupPolicy,
                     *, now_epoch: Optional[float] = None,
                     scanned_monotonic: Optional[float] = None
                     ) -> list[CleanupCandidate]:
    """Pure-ish grouping/scoring entry point used by adversarial tests."""
    clock = time.time() if now_epoch is None else float(now_epoch)
    scan_clock = (
        time.monotonic() if scanned_monotonic is None
        else float(scanned_monotonic))
    children = _children_map(records)
    roots: dict[int, list[int]] = {}
    for rec in records.values():
        if rec.protected_reason:
            continue
        structural_orphan = rec.ppid > 0 and _valid_parent(rec, records) is None
        heavy = (
            rec.cpu_pct >= policy.heavy_cpu_pct
            or rec.memory_bytes >= policy.heavy_memory_bytes)
        if not rec.workload.recognized and not (structural_orphan and heavy):
            continue
        root = _candidate_root(rec, records)
        roots.setdefault(root.pid, [])

    # A heavy unknown orphan may contain a recognized development child.
    # Keep the ancestor-most authorized tree once so candidates never overlap.
    root_pids = set(roots)
    for root_pid in tuple(root_pids):
        current = records.get(root_pid)
        seen: set[int] = set()
        while current is not None and current.pid not in seen:
            seen.add(current.pid)
            parent = _valid_parent(current, records)
            if parent is None:
                break
            if parent.pid in root_pids:
                roots.pop(root_pid, None)
                break
            current = parent

    raw: list[dict] = []
    for root_pid in roots:
        member_pids = [root_pid] + _descendants(root_pid, children)
        members = [records[pid] for pid in member_pids if pid in records]
        if not members:
            continue
        protected = next(
            (rec.protected_reason for rec in members if rec.protected_reason), "")
        workload = _group_workload(members)
        recognized_kinds = {
            rec.workload.kind for rec in members if rec.workload.recognized}
        concrete_kinds = {
            kind for kind in recognized_kinds if kind != "generic-js-dev"}
        mixed_workloads = len(concrete_kinds) > 1
        contains_review_only = any(
            rec.workload.recognized
            and not rec.workload.recommendable
            and rec.workload.kind != "generic-js-dev"
            for rec in members)
        project = _group_project(members)
        cpu_pct = sum(max(0.0, rec.cpu_pct) for rec in members)
        memory_bytes = sum(max(0, rec.memory_bytes) for rec in members)
        age_sec = max(0.0, clock - min(rec.create_time for rec in members))
        root = records[root_pid]
        orphan = root.ppid > 0 and _valid_parent(root, records) is None
        active = _has_active_connection(members)
        external_listener = _has_external_listener(members)
        loopback_listener = _has_loopback_listener(members)
        ports = _listener_ports(members)
        raw.append({
            "root": root, "members": members, "protected": protected,
            "workload": workload, "project": project, "cpu": cpu_pct,
            "memory": memory_bytes, "age": age_sec, "orphan": orphan,
            "active": active, "ports": ports,
            "external_listener": external_listener,
            "loopback_listener": loopback_listener,
            "mixed": mixed_workloads,
            "review_only": contains_review_only,
        })

    exact_counts: dict[tuple[str, str], int] = {}
    project_counts: dict[tuple[str, str], int] = {}
    for item in raw:
        workload = item["workload"]
        root = item["root"]
        exact_key = (workload.kind, root.command_fingerprint)
        if workload.kind and root.command_fingerprint:
            exact_counts[exact_key] = exact_counts.get(exact_key, 0) + 1
        if workload.kind and item["project"]:
            key = (workload.kind, item["project"])
            project_counts[key] = project_counts.get(key, 0) + 1

    candidates: list[CleanupCandidate] = []
    for item in raw:
        root: ProcessRecord = item["root"]
        members: list[ProcessRecord] = item["members"]
        workload: WorkloadMatch = item["workload"]
        reasons: list[str] = []
        score = 0
        if item["orphan"]:
            score += 35
            reasons.append("parent process is gone")
        if workload.recognized:
            score += 20
            reasons.append(workload.label)
        exact_key = (workload.kind, root.command_fingerprint)
        project_key = (workload.kind, item["project"])
        if exact_counts.get(exact_key, 0) > 1:
            score += 25
            reasons.append("exact duplicate workload")
        elif project_counts.get(project_key, 0) > 1:
            score += 15
            reasons.append("same project has another workload")
        if item["age"] >= 7 * 24 * 3600:
            score += 15
            reasons.append("running at least 7 days")
        elif item["age"] >= 24 * 3600:
            score += 10
            reasons.append("running at least 24 hours")
        if item["cpu"] >= policy.very_heavy_cpu_pct:
            score += 15
            reasons.append("sustained CPU impact")
        elif item["cpu"] >= policy.heavy_cpu_pct:
            score += 8
            reasons.append("measurable CPU impact")
        if item["memory"] >= policy.very_heavy_memory_bytes:
            score += 8
            reasons.append("large memory footprint")
        elif item["memory"] >= policy.heavy_memory_bytes:
            score += 3
            reasons.append("memory footprint")
        if item["loopback_listener"] and not item["active"]:
            score += 10
            reasons.append("idle localhost listener")
        if not any(rec.visible_window for rec in members):
            score += 5
            reasons.append("no visible window")
        if item["active"]:
            score -= 40
            reasons.append("active network connection")
        if item["external_listener"]:
            score -= 40
            reasons.append("non-local network listener")
        if item["mixed"]:
            reasons.append("mixed recognized workloads")
        if item["review_only"]:
            reasons.append("contains a review-only workload")
        if item["age"] < policy.min_age_sec:
            score -= 25
            reasons.append("recently started")
        score = max(0, min(100, score))

        protected = item["protected"]
        ignored = (
            root.command_fingerprint in policy.ignored_fingerprints
            or any(rec.command_fingerprint in policy.ignored_fingerprints
                   for rec in members))
        if ignored:
            protected = "ignored exact workload"
        if protected:
            classification = CLASS_PROTECTED
        elif (score >= policy.recommend_score and workload.recommendable
              and not item["active"]
              and not item["external_listener"]
              and item["age"] >= policy.min_age_sec
              and item["orphan"]
              and root.workload.recognized
              and not item["mixed"]
              and not item["review_only"]):
            classification = CLASS_RECOMMENDED
        elif (score >= policy.review_score
              or item["cpu"] >= policy.heavy_cpu_pct
              or item["memory"] >= policy.heavy_memory_bytes):
            classification = CLASS_REVIEW
        else:
            classification = CLASS_INFO
        label = workload.label or root.name or f"PID {root.pid}"
        identities = tuple(rec.identity for rec in members)
        group_hash = hashlib.sha256(
            "|".join(
                f"{ident.pid}:{ident.create_time:.6f}:{ident.command_fingerprint}"
                for ident in identities).encode("utf-8")).hexdigest()[:16]
        candidates.append(CleanupCandidate(
            group_id=group_hash,
            root=root.identity,
            members=identities,
            member_pids=tuple(rec.pid for rec in members),
            label=label,
            classification=classification,
            score=score,
            reasons=tuple(reasons),
            cpu_pct=round(item["cpu"], 2),
            memory_bytes=int(item["memory"]),
            age_sec=float(item["age"]),
            workload_kind=workload.kind,
            project_root=item["project"],
            ports=item["ports"],
            active_connection=bool(
                item["active"] or item["external_listener"]),
            protected_reason=protected,
            safe_command=root.safe_command,
            scanned_monotonic=scan_clock,
        ))
    rank = {
        CLASS_RECOMMENDED: 0, CLASS_REVIEW: 1,
        CLASS_INFO: 2, CLASS_PROTECTED: 3,
    }
    candidates.sort(key=lambda item: (
        rank.get(item.classification, 9), -item.score, -item.cpu_pct,
        -item.memory_bytes, item.label.casefold()))
    return candidates


def scan_processes(policy: Optional[CleanupPolicy] = None,
                   cancel_event: Optional[threading.Event] = None) -> ScanResult:
    policy = policy or CleanupPolicy()
    started = time.time()
    first, errors = _snapshot_once()
    sample_started = time.monotonic()
    sample_sec = max(0.05, float(policy.sample_sec))
    if cancel_event is None:
        time.sleep(sample_sec)
    elif cancel_event.wait(timeout=sample_sec):
        return ScanResult(
            [], len(first), sample_sec, started, time.time(),
            cancelled=True, errors=errors)
    second, errors2 = _snapshot_once()
    errors.extend(errors2)
    elapsed = max(0.001, time.monotonic() - sample_started)
    logical = max(1, os.cpu_count() or 1)
    for pid, current in second.items():
        previous = first.get(pid)
        if previous is None or not _same_identity(previous, current):
            continue
        delta = max(0.0, current.cpu_time - previous.cpu_time)
        current.cpu_pct = (delta / elapsed / logical) * 100.0
    scan_clock = time.monotonic()
    candidates = [] if errors else evaluate_records(
        second, policy, now_epoch=time.time(), scanned_monotonic=scan_clock)
    return ScanResult(
        candidates=candidates,
        process_count=len(second),
        sample_sec=elapsed,
        started_at=started,
        finished_at=time.time(),
        cancelled=False,
        errors=errors,
    )


def _identity_matches(identity: ProcessIdentity) -> bool:
    if psutil is None:
        return False
    try:
        proc = psutil.Process(identity.pid)
        cmd = tuple(proc.cmdline())
        return (
            abs(float(proc.create_time()) - identity.create_time) < 0.001
            and normalize_path(proc.exe()) == identity.exe_path
            and command_fingerprint(cmd) == identity.command_fingerprint
        )
    except Exception:
        return False


def _live_safety_block(candidate: CleanupCandidate) -> str:
    fresh, errors = _snapshot_once()
    if errors:
        return "could not complete the final safety snapshot"
    expected = {ident.pid: ident for ident in candidate.members}
    for pid, identity in expected.items():
        record = fresh.get(pid)
        if record is None:
            continue
        if record.identity != identity:
            return f"PID {pid} identity changed"
        if record.protected_reason:
            return f"PID {pid} became protected: {record.protected_reason}"
        if any(conn.established for conn in record.connections):
            return f"PID {pid} has an active network connection"
        if any(
                conn.listening and not conn.loopback_listener
                for conn in record.connections):
            return f"PID {pid} has a non-local network listener"
    # A process spawned after the scan is not an authorized termination
    # target.  Block the whole group, especially if that child is protected,
    # instead of behaving like taskkill /T and following a live tree.
    children = _children_map(fresh)
    live_expected = [pid for pid in expected if pid in fresh]
    newly_attached: set[int] = set()
    for pid in live_expected:
        newly_attached.update(_descendants(pid, children))
    newly_attached.difference_update(expected)
    if newly_attached:
        pid = min(newly_attached)
        record = fresh.get(pid)
        detail = (
            f": {record.protected_reason}" if record
            and record.protected_reason else "")
        return f"process tree changed; new child PID {pid}{detail}"
    return ""


def terminate_candidates(
        candidates: Sequence[CleanupCandidate],
        policy: Optional[CleanupPolicy] = None,
        cancel_event: Optional[threading.Event] = None,
        *, force: bool = False) -> TerminationReport:
    """End only identities captured by a fresh scan; never kill by image/tree."""
    policy = policy or CleanupPolicy()
    started = time.time()
    items: list[TerminationItem] = []
    was_cancelled = False
    for candidate in candidates:
        if cancel_event is not None and cancel_event.is_set():
            return TerminationReport(
                items, started, time.time(), cancelled=True)
        if candidate.classification == CLASS_PROTECTED:
            items.append(TerminationItem(
                candidate.group_id, candidate.label, "Skipped",
                candidate.protected_reason or "protected candidate"))
            continue
        if candidate.classification not in {
                CLASS_RECOMMENDED, CLASS_REVIEW}:
            items.append(TerminationItem(
                candidate.group_id, candidate.label, "Skipped",
                "only Recommended or Review candidates can be ended"))
            continue
        if time.monotonic() - candidate.scanned_monotonic > policy.result_max_age_sec:
            items.append(TerminationItem(
                candidate.group_id, candidate.label, "Skipped",
                "scan result is stale; rescan required"))
            continue
        changed = _live_safety_block(candidate)
        if changed:
            items.append(TerminationItem(
                candidate.group_id, candidate.label, "Skipped—changed", changed))
            continue
        identities = {ident.pid: ident for ident in candidate.members}
        if not all(_identity_matches(identity) for identity in identities.values()):
            items.append(TerminationItem(
                candidate.group_id, candidate.label, "Skipped—changed",
                "one or more process identities no longer match"))
            continue

        ended: list[int] = []
        errors: list[str] = []
        # Stop the launcher first to reduce respawn risk, then the deepest
        # captured descendants. No /T and no image-name termination are used.
        order = [candidate.root.pid] + [
            pid for pid in reversed(candidate.member_pids)
            if pid != candidate.root.pid]
        for pid in order:
            if cancel_event is not None and cancel_event.is_set():
                was_cancelled = True
                break
            identity = identities.get(pid)
            if identity is None or not _identity_matches(identity):
                continue
            try:
                proc = psutil.Process(pid)
                (proc.kill() if force else proc.terminate())
                ended.append(pid)
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied as exc:
                errors.append(f"PID {pid}: access denied ({exc})")
            except Exception as exc:
                errors.append(f"PID {pid}: {type(exc).__name__}: {exc}")
        deadline = time.monotonic() + max(0.1, float(policy.grace_sec))
        remaining = list(identities)
        while time.monotonic() < deadline:
            remaining = [
                pid for pid, identity in identities.items()
                if _identity_matches(identity)]
            if not remaining:
                break
            if cancel_event is not None and cancel_event.wait(timeout=0.1):
                was_cancelled = True
                break
            time.sleep(0.05)
        status = "Ended" if not remaining else (
            "Access denied" if errors else "Still running")
        message = "; ".join(errors)
        items.append(TerminationItem(
            candidate.group_id, candidate.label, status, message,
            tuple(sorted(set(ended))), tuple(sorted(remaining)),
            candidate.memory_bytes, candidate.cpu_pct))
    return TerminationReport(
        items, started, time.time(), cancelled=was_cancelled)


__all__ = [
    "CLASS_RECOMMENDED", "CLASS_REVIEW", "CLASS_INFO", "CLASS_PROTECTED",
    "WorkloadMatch", "ProcessIdentity", "ConnectionRecord", "ProcessRecord",
    "CleanupCandidate", "ScanResult", "TerminationItem", "TerminationReport",
    "CleanupPolicy", "normalize_path", "redact_command_line",
    "command_fingerprint", "recognize_workload", "evaluate_records",
    "scan_processes", "terminate_candidates",
]
