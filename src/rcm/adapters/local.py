"""Local token detection and a fixed same-executable helper launcher."""

from __future__ import annotations

from dataclasses import dataclass, field
import math, re
from typing import Any, Callable

from ..privilege import IntegrityLevel, PrivilegeSnapshot


_PIPE_NAME = re.compile(r"^rcm-pr07-[a-f0-9]{32}$")


@dataclass(frozen=True, slots=True, repr=False)
class OneShotHelperCommand:
    pipe_name: str
    challenge: str = field(repr=False)
    challenge_expires_at: float
    parent_pid: int

    def __post_init__(self) -> None:
        if (not isinstance(self.pipe_name, str)
                or not _PIPE_NAME.fullmatch(self.pipe_name)):
            raise ValueError("helper pipe name is invalid")
        if (not isinstance(self.challenge, str)
                or not re.fullmatch(r"[a-f0-9]{64}", self.challenge)):
            raise ValueError("helper challenge is invalid")
        expiry = self.challenge_expires_at
        if (isinstance(expiry, bool) or not isinstance(expiry, (int, float))
                or not math.isfinite(float(expiry)) or expiry < 0):
            raise ValueError("helper challenge expiry is invalid")
        if (isinstance(self.parent_pid, bool)
                or not isinstance(self.parent_pid, int) or self.parent_pid <= 0):
            raise ValueError("helper parent pid is invalid")
        object.__setattr__(self, "challenge_expires_at", float(expiry))

    def arguments(self) -> tuple[str, ...]:
        return (
            "--rcm-local-admin-helper", "--pipe", self.pipe_name,
            "--challenge", self.challenge, "--challenge-expires-at",
            self.challenge_expires_at.hex(), "--parent-pid", str(self.parent_pid))


class LocalPrivilegeDetector:
    """Read current token facts without changing privilege or starting a process."""

    def __init__(self, *,
                 probe: Callable[[], PrivilegeSnapshot] | None = None) -> None:
        self._probe = probe

    def detect(self) -> PrivilegeSnapshot:
        if self._probe is not None:
            result = self._probe()
        else:
            import sys

            result = (self._windows_snapshot() if sys.platform == "win32"
                      else PrivilegeSnapshot(IntegrityLevel.UNKNOWN))
        if not isinstance(result, PrivilegeSnapshot):
            raise TypeError("privilege probe returned an invalid snapshot")
        return result

    @staticmethod
    def _windows_snapshot() -> PrivilegeSnapshot:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        advapi32.OpenProcessToken.argtypes = (
            wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        advapi32.GetTokenInformation.argtypes = (
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD))
        advapi32.GetSidSubAuthorityCount.argtypes = (ctypes.c_void_p,)
        advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
        advapi32.GetSidSubAuthority.argtypes = (ctypes.c_void_p, wintypes.DWORD)
        advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
                kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return PrivilegeSnapshot(IntegrityLevel.UNKNOWN)
        try:
            elevated = LocalPrivilegeDetector._token_elevated(
                advapi32, token, ctypes, wintypes)
            integrity = LocalPrivilegeDetector._token_integrity(
                advapi32, token, ctypes, wintypes)
            elevation_type = wintypes.DWORD()
            size = wintypes.DWORD()
            limited = bool(
                advapi32.GetTokenInformation(
                    token, 18, ctypes.byref(elevation_type),
                    ctypes.sizeof(elevation_type), ctypes.byref(size))
                and elevation_type.value == 3)
            return PrivilegeSnapshot(
                integrity, administrator_member=limited or elevated,
                elevated=elevated)
        finally:
            kernel32.CloseHandle(token)

    @staticmethod
    def _token_elevated(advapi32: Any, token: Any, ctypes: Any,
                        wintypes: Any) -> bool:
        value = wintypes.DWORD()
        returned = wintypes.DWORD()
        return bool(
            advapi32.GetTokenInformation(
                token, 20, ctypes.byref(value), ctypes.sizeof(value),
                ctypes.byref(returned))
            and value.value)

    @staticmethod
    def _token_integrity(advapi32: Any, token: Any, ctypes: Any,
                         wintypes: Any) -> IntegrityLevel:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
        if not size.value:
            return IntegrityLevel.UNKNOWN
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
                token, 25, buffer, size.value, ctypes.byref(size)):
            return IntegrityLevel.UNKNOWN
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        count = advapi32.GetSidSubAuthorityCount(sid)
        if not count:
            return IntegrityLevel.UNKNOWN
        last = count.contents.value - 1
        authority = advapi32.GetSidSubAuthority(sid, last)
        if not authority:
            return IntegrityLevel.UNKNOWN
        rid = authority.contents.value
        if rid < 0x2000:
            return IntegrityLevel.LOW
        if rid < 0x3000:
            return IntegrityLevel.MEDIUM
        if rid < 0x4000:
            return IntegrityLevel.HIGH
        return IntegrityLevel.SYSTEM


__all__ = ["LocalPrivilegeDetector", "OneShotHelperCommand"]
