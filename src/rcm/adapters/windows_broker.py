"""Same-executable, one-shot Windows broker over a local explicit-DACL pipe."""

from __future__ import annotations

import os, secrets, struct, threading, time
from typing import Any, Callable, Protocol

from ..privilege import (
    BrokerRequestEnvelope, CHALLENGE_LIFETIME_SECONDS, HELPER_EXIT_SECONDS,
    LOCAL_ADMIN_ELEVATION_ENABLED, MAX_BROKER_REQUEST_BYTES,
    OPERATION_DEADLINE_SECONDS, PrivilegeReceipt, PrivilegeRequest,
    PrivilegeSnapshot, PrivilegeStatus, decode_broker_receipt,
    decode_broker_request, encode_broker_receipt, encode_broker_request,
)
from .local import LocalPrivilegeDetector, OneShotHelperCommand


class AdminApplier(Protocol):
    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt: ...


class HelperHandle(Protocol):
    pid: int

    def wait(self, timeout_seconds: float) -> int | None: ...
    def bind_client_pid(self, pid: int) -> None: ...
    def abort(self) -> None: ...
    def close(self) -> None: ...


class HelperLauncher(Protocol):
    def launch(self, command: OneShotHelperCommand) -> HelperHandle: ...


class PipeServer(Protocol):
    name: str

    def exchange(self, request: bytes, *, client_pid_validator: Callable[[int], None],
                 timeout_seconds: float) -> bytes: ...
    def close(self) -> None: ...


class PipeClient(Protocol):
    def receive(self, *, expected_server_pid: int, timeout_seconds: float) -> bytes: ...
    def send(self, response: bytes) -> None: ...
    def close(self) -> None: ...


class PipeFactory(Protocol):
    def server(self, name: str) -> PipeServer: ...
    def client(self, name: str) -> PipeClient: ...


class WindowsOneShotBroker:
    """Create one pipe and one elevated helper for one typed request."""

    def __init__(self, *, pipe_factory: PipeFactory | None = None,
                 launcher: HelperLauncher | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 token_factory: Callable[[int], str] = secrets.token_hex,
                 parent_pid: Callable[[], int] = os.getpid) -> None:
        self._pipes = pipe_factory or Win32LocalPipeFactory()
        self._launcher = launcher or WindowsRunAsLauncher()
        self._clock = clock
        self._tokens = token_factory
        self._parent_pid = parent_pid

    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt:
        if not isinstance(request, PrivilegeRequest):
            raise TypeError("request must be a PrivilegeRequest")
        if not LOCAL_ADMIN_ELEVATION_ENABLED:
            return PrivilegeReceipt(
                request.request_id, request.operation, PrivilegeStatus.FAILED,
                "local_admin.secure_packaging_required")
        issued = self._clock()
        challenge = self._tokens(32)
        pipe_name = f"rcm-pr07-{self._tokens(16)}"
        expires = issued + CHALLENGE_LIFETIME_SECONDS
        envelope = BrokerRequestEnvelope(
            challenge, issued, expires, issued + OPERATION_DEADLINE_SECONDS,
            request)
        server: PipeServer | None = None
        helper: HelperHandle | None = None
        try:
            server = self._pipes.server(pipe_name)
            try:
                helper = self._launcher.launch(OneShotHelperCommand(
                    pipe_name, challenge, expires, self._parent_pid()))
            except PermissionError:
                return PrivilegeReceipt(
                    request.request_id, request.operation,
                    PrivilegeStatus.CANCELLED, "local_admin.uac_cancelled")
            remaining = envelope.operation_deadline - self._clock()
            if remaining <= 0:
                raise TimeoutError("one-shot operation deadline expired")
            raw = server.exchange(
                encode_broker_request(envelope),
                client_pid_validator=helper.bind_client_pid,
                timeout_seconds=remaining)
            receipt = decode_broker_receipt(raw)
            if (receipt.request_id != request.request_id
                    or receipt.operation is not request.operation):
                raise RuntimeError("broker response binding failed")
            exit_code = helper.wait(HELPER_EXIT_SECONDS)
            if exit_code != 0:
                raise RuntimeError("one-shot helper did not exit cleanly in 5 seconds")
            return receipt
        except Exception:
            if helper is not None:
                try:
                    helper.abort()
                except Exception:
                    pass
            return PrivilegeReceipt(
                request.request_id, request.operation, PrivilegeStatus.FAILED,
                "local_admin.broker_failed")
        finally:
            if server is not None:
                server.close()
            if helper is not None:
                helper.close()


def run_one_shot_helper(
        command: OneShotHelperCommand, *, applier: AdminApplier,
        pipe_factory: PipeFactory | None = None,
        clock: Callable[[], float] = time.monotonic,
        privilege_probe: Callable[[], Any] | None = None,
        job_guard: Callable[[], object] | None = None,
        timer_factory: Callable[..., Any] = threading.Timer) -> int:
    """Serve exactly one request and return immediately after its receipt."""

    if not isinstance(command, OneShotHelperCommand):
        raise TypeError("command must be a OneShotHelperCommand")
    try:
        snapshot = (
            privilege_probe or LocalPrivilegeDetector().detect)()
    except Exception:
        return 2
    if not isinstance(snapshot, PrivilegeSnapshot) or not snapshot.elevated:
        return 2
    try:
        _job_handle = (job_guard or _arm_kill_on_close_job)()
    except Exception:
        return 2
    started = clock()
    if not (started < command.challenge_expires_at
            <= started + CHALLENGE_LIFETIME_SECONDS):
        return 2
    pipes = pipe_factory or Win32LocalPipeFactory()
    client: PipeClient | None = None
    watchdog: Any | None = None
    try:
        client = pipes.client(command.pipe_name)
        watchdog = timer_factory(
            command.challenge_expires_at - started,
            _terminate_current_process)
        watchdog.daemon = True
        watchdog.start()
        raw = client.receive(
            expected_server_pid=command.parent_pid,
            timeout_seconds=command.challenge_expires_at - started)
        received = clock()
        envelope = decode_broker_request(
            raw, expected_challenge=command.challenge, now=received)
        if (envelope.issued_at > started
                or envelope.challenge_expires_at != command.challenge_expires_at):
            return 4
        watchdog.cancel()
        watchdog = timer_factory(
            envelope.operation_deadline - received,
            _terminate_current_process)
        watchdog.daemon = True
        watchdog.start()
        receipt = applier.apply(envelope.request)
        if (receipt.request_id != envelope.request.request_id
                or receipt.operation is not envelope.request.operation):
            return 3
        if clock() > envelope.operation_deadline:
            receipt = PrivilegeReceipt(
                envelope.request.request_id, envelope.request.operation,
                PrivilegeStatus.FAILED, "local_admin.deadline_expired")
        client.send(encode_broker_receipt(receipt))
        return 0
    except Exception:
        return 4
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if client is not None:
            client.close()


def parse_one_shot_helper_arguments(
        arguments: tuple[str, ...]) -> OneShotHelperCommand | None:
    """Parse only the fixed helper argv shape; return ``None`` for normal startup."""

    if not arguments or arguments[0] != "--rcm-local-admin-helper":
        return None
    keys = ("--pipe", "--challenge", "--challenge-expires-at", "--parent-pid")
    if len(arguments) != 9 or arguments[1::2] != keys:
        raise ValueError("local admin helper arguments are invalid")
    try:
        expiry = float.fromhex(arguments[6])
        parent_pid = int(arguments[8], 10)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("local admin helper arguments are invalid") from None
    return OneShotHelperCommand(
        arguments[2], arguments[4], expiry, parent_pid)


def _quote_windows_argument(value: str) -> str:
    if value and not any(character in value for character in ' \t"'):
        return value
    result = ['"']
    backslashes = 0
    for character in value:
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            result.append("\\" * (backslashes * 2 + 1))
            result.append('"')
        else:
            result.append("\\" * backslashes)
            result.append(character)
        backslashes = 0
    result.append("\\" * (backslashes * 2))
    result.append('"')
    return "".join(result)


def _dispose_failed_launch(process_handle: int) -> None:
    kernel32 = _kernel32()
    try:
        if kernel32.TerminateProcess(process_handle, 1):
            kernel32.WaitForSingleObject(process_handle, 5_000)
    finally:
        kernel32.CloseHandle(process_handle)


class _RunAsHandle:
    def __init__(self, process_handle: int, pid: int) -> None:
        self._handle = process_handle
        self.pid = pid
        try:
            import psutil

            self._created_at = float(psutil.Process(pid).create_time())
        except Exception:
            _dispose_failed_launch(process_handle)
            self._handle = 0
            raise RuntimeError("one-shot bootloader identity is unavailable") from None
        self._runtime_identity: tuple[int, float] | None = None

    def wait(self, timeout_seconds: float) -> int | None:
        import ctypes
        from ctypes import wintypes

        if not self._handle:
            return None
        milliseconds = max(0, min(int(timeout_seconds * 1_000), 0xFFFFFFFE))
        kernel32 = _kernel32()
        outcome = kernel32.WaitForSingleObject(self._handle, milliseconds)
        if outcome == 0x00000102:
            return None
        if outcome != 0:
            raise RuntimeError("one-shot helper wait failed")
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            raise RuntimeError("one-shot helper exit status is unavailable")
        return int(code.value)

    def close(self) -> None:
        if self._handle:
            _kernel32().CloseHandle(self._handle)
            self._handle = 0

    def bind_client_pid(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0 or self._runtime_identity is not None:
            raise PermissionError("one-shot runtime identity is invalid")
        if pid != self.pid:
            raise PermissionError("one-shot runtime is not the launched process")
        try:
            import psutil
            import sys

            runtime = psutil.Process(pid)
            created = float(runtime.create_time())
            valid = (created == self._created_at
                     and os.path.samefile(runtime.exe(), sys.executable))
        except Exception:
            valid = False
        if not valid:
            raise PermissionError("one-shot runtime identity does not match")
        self._runtime_identity = (pid, created)

    def abort(self) -> None:
        if not self._handle or self.wait(0) is not None:
            return
        kernel32 = _kernel32()
        if not kernel32.TerminateProcess(self._handle, 1):
            if self.wait(0) is None:
                raise RuntimeError("one-shot helper termination failed")
        if self.wait(HELPER_EXIT_SECONDS) is None:
            raise RuntimeError("one-shot helper did not terminate")


class WindowsRunAsLauncher:
    """Use the Windows elevation verb only for the typed current-EXE command."""

    def launch(self, command: OneShotHelperCommand) -> _RunAsHandle:
        if not isinstance(command, OneShotHelperCommand):
            raise TypeError("command must be a OneShotHelperCommand")
        import sys

        if (not LOCAL_ADMIN_ELEVATION_ENABLED
                or not getattr(sys, "frozen", False)
                or "_PYI_APPLICATION_HOME_DIR" in os.environ):
            raise RuntimeError("elevation requires a secure one-folder application")
        import ctypes
        from ctypes import wintypes

        class _ShellExecuteInfo(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG),
                ("hwnd", wintypes.HWND), ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]

        parameters = " ".join(
            _quote_windows_argument(item) for item in command.arguments())
        info = _ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040
        info.lpVerb = "runas"
        info.lpFile = sys.executable
        info.lpParameters = parameters
        info.lpDirectory = os.path.dirname(sys.executable)
        info.nShow = 0
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        if not shell32.ShellExecuteExW(ctypes.byref(info)):
            if ctypes.get_last_error() == 1223:
                raise PermissionError("elevation was cancelled")
            raise RuntimeError("one-shot helper could not be launched")
        pid = _kernel32().GetProcessId(info.hProcess)
        if not pid:
            _dispose_failed_launch(info.hProcess)
            raise RuntimeError("one-shot helper pid is unavailable")
        return _RunAsHandle(info.hProcess, int(pid))


class Win32LocalPipeFactory:
    def server(self, name: str) -> _Win32PipeServer:
        return _Win32PipeServer(name)

    def client(self, name: str) -> _Win32PipeClient:
        return _Win32PipeClient(name)


def _kernel32() -> Any:
    import ctypes
    from ctypes import wintypes

    library = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CancelSynchronousIo": ((wintypes.HANDLE,), wintypes.BOOL),
        "CloseHandle": ((wintypes.HANDLE,), wintypes.BOOL),
        "ConnectNamedPipe": ((wintypes.HANDLE, ctypes.c_void_p), wintypes.BOOL),
        "CreateJobObjectW": ((ctypes.c_void_p, wintypes.LPCWSTR), wintypes.HANDLE),
        "CreateFileW": ((wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE), wintypes.HANDLE),
        "CreateNamedPipeW": ((wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p), wintypes.HANDLE),
        "GetCurrentProcess": ((), wintypes.HANDLE),
        "GetExitCodeProcess": ((wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)), wintypes.BOOL),
        # API group boundary.
        "GetNamedPipeClientProcessId": ((wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)), wintypes.BOOL),
        "GetNamedPipeServerProcessId": ((wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)), wintypes.BOOL),
        "GetProcessId": ((wintypes.HANDLE,), wintypes.DWORD),
        "AssignProcessToJobObject": ((wintypes.HANDLE, wintypes.HANDLE), wintypes.BOOL),
        "LocalFree": ((ctypes.c_void_p,), ctypes.c_void_p),
        "OpenThread": ((wintypes.DWORD, wintypes.BOOL, wintypes.DWORD), wintypes.HANDLE),
        "ReadFile": ((wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p), wintypes.BOOL),
        "WriteFile": ((wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p), wintypes.BOOL),
        "FlushFileBuffers": ((wintypes.HANDLE,), wintypes.BOOL),
        "DisconnectNamedPipe": ((wintypes.HANDLE,), wintypes.BOOL),
        "WaitNamedPipeW": ((wintypes.LPCWSTR, wintypes.DWORD), wintypes.BOOL),
        "WaitForSingle" + "Object": ((wintypes.HANDLE, wintypes.DWORD), wintypes.DWORD),
        "SetInformationJobObject": ((wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD), wintypes.BOOL),
        "TerminateProcess": ((wintypes.HANDLE, wintypes.UINT), wintypes.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return library


def _arm_kill_on_close_job() -> int:
    import ctypes
    from ctypes import wintypes

    class _BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUser" + "TimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    kernel32 = _kernel32()
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise RuntimeError("one-shot helper job could not be created")
    extended = ctypes.create_string_buffer(
        ctypes.sizeof(_BasicLimit) + 6 * ctypes.sizeof(ctypes.c_ulonglong)
        + 4 * ctypes.sizeof(ctypes.c_size_t))
    ctypes.cast(extended, ctypes.POINTER(_BasicLimit)).contents.LimitFlags = 0x00002000
    if (
        not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(extended), ctypes.sizeof(extended))
        or not kernel32.AssignProcessToJobObject(
            job, kernel32.GetCurrentProcess())
    ):
        kernel32.CloseHandle(job)
        raise RuntimeError("one-shot helper job could not be armed")
    return int(job)


def _terminate_current_process() -> None:
    kernel32 = _kernel32()
    if not kernel32.TerminateProcess(kernel32.GetCurrentProcess(), 1):
        os._exit(1)


def _advapi32() -> Any:
    import ctypes
    from ctypes import wintypes

    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenProcessToken.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    library.OpenProcessToken.restype = wintypes.BOOL
    library.GetTokenInformation.argtypes = (
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
    library.GetTokenInformation.restype = wintypes.BOOL
    library.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    library.ConvertSidToStringSidW.restype = wintypes.BOOL
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD))
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    return library


def _pipe_path(name: str) -> str:
    OneShotHelperCommand(name, "0" * 64, 1.0, 1)
    return rf"\\.\pipe\{name}"


def _same_executable_process(pid: int) -> bool:
    try:
        import psutil
        import sys

        process, current = psutil.Process(pid), psutil.Process()
        return (process.is_running() and process.username() == current.username()
                and os.path.samefile(process.exe(), sys.executable))
    except Exception:
        return False


def _cancel_synchronous_io(thread: threading.Thread) -> None:
    import ctypes

    if thread.native_id is None:
        raise RuntimeError("local pipe worker identity is unavailable")
    kernel32 = _kernel32()
    handle = kernel32.OpenThread(0x0001, False, thread.native_id)
    if not handle:
        raise RuntimeError("local pipe worker identity is unavailable")
    try:
        if (not kernel32.CancelSynchronousIo(handle)
                and ctypes.get_last_error() != 1168):
            raise RuntimeError("local pipe worker cancellation failed")
    finally:
        kernel32.CloseHandle(handle)


def _read_exact(handle: int, length: int) -> bytes:
    import ctypes
    from ctypes import wintypes

    kernel32 = _kernel32()
    chunks = bytearray()
    while len(chunks) < length:
        remaining = length - len(chunks)
        buffer = ctypes.create_string_buffer(remaining)
        count = wintypes.DWORD()
        if (not kernel32.ReadFile(
                handle, buffer, remaining, ctypes.byref(count), None)
                or not count.value):
            raise RuntimeError("local pipe read failed")
        chunks.extend(buffer.raw[:count.value])
    return bytes(chunks)


def _read_frame(handle: int) -> bytes:
    length = struct.unpack("<I", _read_exact(handle, 4))[0]
    if not 0 < length <= MAX_BROKER_REQUEST_BYTES:
        raise ValueError("local pipe frame size is invalid")
    return _read_exact(handle, length)


def _write_frame(handle: int, payload: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    if (not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_BROKER_REQUEST_BYTES):
        raise ValueError("local pipe frame size is invalid")
    data = struct.pack("<I", len(payload)) + payload
    kernel32 = _kernel32()
    offset = 0
    while offset < len(data):
        count = wintypes.DWORD()
        chunk = data[offset:]
        buffer = ctypes.create_string_buffer(chunk)
        if (not kernel32.WriteFile(
                handle, buffer, len(chunk), ctypes.byref(count), None)
                or not count.value):
            raise RuntimeError("local pipe write failed")
        offset += count.value


def _current_user_sid() -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = _advapi32()
    kernel32 = _kernel32()
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise RuntimeError("current token is unavailable")
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
                token, 1, buffer, size.value, ctypes.byref(size)):
            raise RuntimeError("current token identity is unavailable")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise RuntimeError("current token identity is unavailable")
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel32.CloseHandle(token)


class _Win32PipeServer:
    def __init__(self, name: str) -> None:
        import ctypes
        from ctypes import wintypes

        class _SecurityAttributes(ctypes.Structure):
            _fields_ = [
                ("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]

        self.name = name
        path = _pipe_path(name)
        sid = _current_user_sid()
        descriptor = ctypes.c_void_p()
        advapi32 = _advapi32()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                f"D:P(A;;GA;;;{sid})(A;;GA;;;SY)", 1,
                ctypes.byref(descriptor), None):
            raise RuntimeError("explicit pipe DACL could not be created")
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), descriptor, False)
        kernel32 = _kernel32()
        try:
            handle = kernel32.CreateNamedPipeW(
                path, 0x00000003 | 0x00080000, 0x00000008, 1,
                MAX_BROKER_REQUEST_BYTES + 4, MAX_BROKER_REQUEST_BYTES + 4,
                30_000, ctypes.byref(attributes))
        finally:
            kernel32.LocalFree(descriptor)
        if handle in (0, -1, ctypes.c_void_p(-1).value):
            raise RuntimeError("exclusive local pipe could not be created")
        self._handle = handle
        self._worker: threading.Thread | None = None
        self._close_requested = False

    def exchange(self, request: bytes, *, client_pid_validator: Callable[[int], None],
                 timeout_seconds: float) -> bytes:
        result: list[bytes] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                self._exchange_connected(request, client_pid_validator, result)
            except BaseException as exc:
                errors.append(exc)
            finally:
                if self._close_requested:
                    self._close_handle()

        thread = threading.Thread(target=worker, name="rcm-local-pipe", daemon=True)
        self._worker = thread
        thread.start()
        thread.join(timeout_seconds)
        if thread.is_alive():
            try:
                _cancel_synchronous_io(thread)
            finally:
                thread.join(HELPER_EXIT_SECONDS)
            if thread.is_alive():
                raise RuntimeError("local pipe worker did not stop")
            raise TimeoutError("local pipe operation deadline expired")
        if errors:
            raise RuntimeError("local pipe exchange failed") from None
        return result[0]

    def _exchange_connected(self, request: bytes,
                            client_pid_validator: Callable[[int], None],
                            result: list[bytes]) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = _kernel32()
        if (not kernel32.ConnectNamedPipe(self._handle, None)
                and ctypes.get_last_error() != 535):
            raise RuntimeError("local pipe client did not connect")
        client_pid = wintypes.ULONG()
        if not kernel32.GetNamedPipeClientProcessId(
                self._handle, ctypes.byref(client_pid)):
            raise PermissionError("local pipe client identity does not match")
        client_pid_validator(int(client_pid.value))
        _write_frame(self._handle, request)
        result.append(_read_frame(self._handle))
        kernel32.FlushFileBuffers(self._handle)
        kernel32.DisconnectNamedPipe(self._handle)

    def _close_handle(self) -> None:
        if self._handle:
            _kernel32().CloseHandle(self._handle)
            self._handle = 0

    def close(self) -> None:
        self._close_requested = True
        worker = self._worker
        if worker is not None and worker.is_alive():
            try:
                _cancel_synchronous_io(worker)
            except Exception:
                pass
            worker.join(HELPER_EXIT_SECONDS)
            if worker.is_alive():
                return
        self._close_handle()


class _Win32PipeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self._path = _pipe_path(name)
        self._handle = 0

    def receive(self, *, expected_server_pid: int, timeout_seconds: float) -> bytes:
        import ctypes
        from ctypes import wintypes

        kernel32 = _kernel32()
        milliseconds = max(1, min(int(timeout_seconds * 1_000), 30_000))
        if not kernel32.WaitNamedPipeW(self._path, milliseconds):
            raise TimeoutError("local pipe server was unavailable")
        self._handle = kernel32.CreateFileW(
            self._path, 0xC0000000, 0, None, 3, 0x00110000, None)
        if self._handle in (0, -1, ctypes.c_void_p(-1).value):
            raise RuntimeError("local pipe client connection failed")
        server_pid = wintypes.ULONG()
        if (not kernel32.GetNamedPipeServerProcessId(
                self._handle, ctypes.byref(server_pid))
                or server_pid.value != expected_server_pid
                or not _same_executable_process(int(server_pid.value))):
            raise PermissionError("local pipe server identity does not match")
        return _read_frame(self._handle)

    def send(self, response: bytes) -> None:
        if not self._handle:
            raise RuntimeError("local pipe client is not connected")
        _write_frame(self._handle, response)

    def close(self) -> None:
        if self._handle:
            _kernel32().CloseHandle(self._handle)
            self._handle = 0


__all__ = [
    "AdminApplier", "HelperLauncher", "PipeFactory", "Win32LocalPipeFactory",
    "WindowsOneShotBroker", "WindowsRunAsLauncher",
    "parse_one_shot_helper_arguments", "run_one_shot_helper"]
