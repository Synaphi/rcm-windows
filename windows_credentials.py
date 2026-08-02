"""Small, testable Windows account and RDP credential helpers.

The public functions deliberately expose only operations, never credential
contents.  Native calls are kept behind injectable API objects so regression
tests do not touch the real local account database or Credential Manager.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import ipaddress
import os
import re
import secrets
import socket
import string
from typing import Protocol


_NERR_SUCCESS = 0
_CRED_TYPE_DOMAIN_PASSWORD = 2
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_MAX_CREDENTIAL_BLOB_BYTES = 512

_INVALID_LOCAL_USER_CHARS = re.compile(r'["/\\\[\]:;|=,+*?<>@]')
_PASSWORD_SYMBOLS = "!#$%+-.:=?@_~"


class WindowsSecurityError(RuntimeError):
    """Base error for a failed native Windows security operation."""


class AccountValidationError(ValueError):
    """Raised when an account is not an unambiguous local account."""


class CredentialValidationError(ValueError):
    """Raised for an invalid RDP target, username, or password shape."""


@dataclass(frozen=True)
class LocalAccount:
    """A validated local account, normalized to the current computer."""

    computer: str
    username: str

    @property
    def qualified_name(self) -> str:
        return f"{self.computer}\\{self.username}"


class LocalPasswordChangeApi(Protocol):
    def change_password(
        self, computer: str, username: str,
        old_password: str, new_password: str,
    ) -> None: ...


class CredentialStoreApi(Protocol):
    def write_credential(self, target: str, username: str, password: str) -> None: ...

    def credential_exists(self, target: str) -> bool: ...

    def credential_matches_username(self, target: str, username: str) -> bool: ...

    def delete_credential(self, target: str) -> bool: ...


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_PCREDENTIALW = ctypes.POINTER(_CREDENTIALW)


def _require_windows() -> None:
    if os.name != "nt":
        raise OSError("Windows security APIs are available only on Windows")


def _local_computer_name(explicit_name: str | None) -> str:
    name = explicit_name or os.environ.get("COMPUTERNAME") or socket.gethostname()
    name = str(name).strip()
    if not name or any(char in name for char in "\\/@\x00"):
        raise AccountValidationError("local computer name is unavailable or invalid")
    return name


def normalize_local_account(
    account_spec: str,
    *,
    local_computer: str | None = None,
) -> LocalAccount:
    """Validate an account spec and normalize it to ``COMPUTER\\user``.

    Accepted forms are ``user``, ``.\\user`` and the current computer's
    qualified form.  Microsoft, Entra/Azure AD, email-shaped, and foreign
    machine accounts are rejected before any native API is called.
    """

    if not isinstance(account_spec, str):
        raise AccountValidationError("account must be text")
    raw = account_spec.strip()
    if not raw or "\x00" in raw or "/" in raw:
        raise AccountValidationError("account format is invalid")

    parts = raw.split("\\")
    if len(parts) == 1:
        qualifier = "."
        username = parts[0].strip()
    elif len(parts) == 2:
        qualifier, username = (part.strip() for part in parts)
    else:
        raise AccountValidationError("account must contain at most one qualifier")

    computer = _local_computer_name(local_computer)
    qualifier_key = qualifier.casefold()
    if qualifier_key in {"microsoftaccount", "azuread", "entra", "entraid"}:
        raise AccountValidationError("cloud accounts cannot be changed as local accounts")
    if qualifier_key not in {".", "localhost", computer.casefold()}:
        raise AccountValidationError("account belongs to a different computer")

    if not username or len(username) > 20:
        raise AccountValidationError("local username must contain 1 to 20 characters")
    if username in {".", ".."} or username.endswith((" ", ".")):
        raise AccountValidationError("local username is invalid")
    if _INVALID_LOCAL_USER_CHARS.search(username):
        raise AccountValidationError("local username contains an invalid character")
    if any(ord(char) < 32 for char in username):
        raise AccountValidationError("local username contains a control character")

    return LocalAccount(computer=computer, username=username)


def _validate_password(password: str, *, credential_blob: bool = False) -> None:
    if not isinstance(password, str):
        raise CredentialValidationError("password must be text")
    if not password or "\x00" in password:
        raise CredentialValidationError("password cannot be empty or contain a null character")
    if credential_blob and len(password.encode("utf-16-le")) > _MAX_CREDENTIAL_BLOB_BYTES:
        raise CredentialValidationError("password is too long for Windows Credential Manager")


def generate_strong_password(length: int = 24) -> str:
    """Generate a practical ASCII password with all four character classes."""

    if isinstance(length, bool) or not isinstance(length, int) or not 16 <= length <= 128:
        raise ValueError("password length must be an integer from 16 to 128")

    groups = (string.ascii_uppercase, string.ascii_lowercase, string.digits, _PASSWORD_SYMBOLS)
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class Win32LocalPasswordChangeApi:
    """Normal local password change using the current password.

    This is the only account-password operation shipped by RCM.  Supplying the
    current password lets Windows update password-protected user material.
    """

    def __init__(self, net_user_change_password=None):
        if net_user_change_password is None:
            _require_windows()
            netapi32 = ctypes.WinDLL("Netapi32.dll")
            net_user_change_password = netapi32.NetUserChangePassword
            net_user_change_password.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
            ]
            net_user_change_password.restype = wintypes.DWORD
        self._net_user_change_password = net_user_change_password

    def change_password(
        self, computer: str, username: str,
        old_password: str, new_password: str,
    ) -> None:
        _validate_password(old_password)
        _validate_password(new_password)
        old_buffer = ctypes.create_unicode_buffer(old_password)
        new_buffer = ctypes.create_unicode_buffer(new_password)
        server = "\\\\" + computer.lstrip("\\")
        try:
            status = int(self._net_user_change_password(
                server, username,
                ctypes.cast(old_buffer, wintypes.LPWSTR),
                ctypes.cast(new_buffer, wintypes.LPWSTR),
            ))
        finally:
            ctypes.memset(ctypes.addressof(old_buffer), 0, ctypes.sizeof(old_buffer))
            ctypes.memset(ctypes.addressof(new_buffer), 0, ctypes.sizeof(new_buffer))
        if status != _NERR_SUCCESS:
            raise WindowsSecurityError(
                f"local password change failed (status={status})")


class Win32CredentialStoreApi:
    """Credential Manager boundary for ``TERMSRV/<ip>`` entries."""

    def __init__(
        self,
        *,
        cred_write=None,
        cred_read=None,
        cred_delete=None,
        cred_free=None,
        get_last_error=None,
    ):
        supplied = (cred_write, cred_read, cred_delete, cred_free, get_last_error)
        if all(item is None for item in supplied):
            _require_windows()
            advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
            cred_write = advapi32.CredWriteW
            cred_read = advapi32.CredReadW
            cred_delete = advapi32.CredDeleteW
            cred_free = advapi32.CredFree
            get_last_error = ctypes.get_last_error

            cred_write.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
            cred_write.restype = wintypes.BOOL
            cred_read.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(_PCREDENTIALW),
            ]
            cred_read.restype = wintypes.BOOL
            cred_delete.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
            cred_delete.restype = wintypes.BOOL
            cred_free.argtypes = [ctypes.c_void_p]
            cred_free.restype = None
        elif any(item is None for item in supplied):
            raise ValueError("all native credential callables must be supplied together")

        self._cred_write = cred_write
        self._cred_read = cred_read
        self._cred_delete = cred_delete
        self._cred_free = cred_free
        self._get_last_error = get_last_error

    def write_credential(self, target: str, username: str, password: str) -> None:
        _validate_password(password, credential_blob=True)
        password_buffer = ctypes.create_unicode_buffer(password)
        credential = _CREDENTIALW()
        credential.Type = _CRED_TYPE_DOMAIN_PASSWORD
        credential.TargetName = target
        credential.CredentialBlobSize = (len(password_buffer) - 1) * ctypes.sizeof(ctypes.c_wchar)
        credential.CredentialBlob = ctypes.cast(
            password_buffer, ctypes.POINTER(ctypes.c_ubyte)
        )
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.UserName = username
        try:
            ok = bool(self._cred_write(ctypes.byref(credential), 0))
            error_code = 0 if ok else int(self._get_last_error())
        finally:
            ctypes.memset(ctypes.addressof(password_buffer), 0, ctypes.sizeof(password_buffer))
        if not ok:
            raise WindowsSecurityError(f"credential write failed (winerror={error_code})")

    def credential_exists(self, target: str) -> bool:
        credential_pointer = _PCREDENTIALW()
        ok = bool(
            self._cred_read(
                target,
                _CRED_TYPE_DOMAIN_PASSWORD,
                0,
                ctypes.byref(credential_pointer),
            )
        )
        if ok:
            if credential_pointer:
                self._cred_free(credential_pointer)
            return True
        error_code = int(self._get_last_error())
        if error_code == _ERROR_NOT_FOUND:
            return False
        raise WindowsSecurityError(f"credential read failed (winerror={error_code})")

    def credential_matches_username(self, target: str, username: str) -> bool:
        """Match only non-secret credential metadata and always free it."""
        credential_pointer = _PCREDENTIALW()
        ok = bool(
            self._cred_read(
                target,
                _CRED_TYPE_DOMAIN_PASSWORD,
                0,
                ctypes.byref(credential_pointer),
            )
        )
        if ok:
            try:
                stored = ""
                if credential_pointer:
                    stored = str(
                        credential_pointer.contents.UserName or "").strip()
                return stored.casefold() == str(username or "").strip().casefold()
            finally:
                if credential_pointer:
                    self._cred_free(credential_pointer)
        error_code = int(self._get_last_error())
        if error_code == _ERROR_NOT_FOUND:
            return False
        raise WindowsSecurityError(f"credential read failed (winerror={error_code})")

    def delete_credential(self, target: str) -> bool:
        ok = bool(self._cred_delete(target, _CRED_TYPE_DOMAIN_PASSWORD, 0))
        if ok:
            return True
        error_code = int(self._get_last_error())
        if error_code == _ERROR_NOT_FOUND:
            return False
        raise WindowsSecurityError(f"credential delete failed (winerror={error_code})")


def change_local_account_password(
    account_spec: str,
    old_password: str,
    new_password: str,
    *,
    local_computer: str | None = None,
    api: LocalPasswordChangeApi | None = None,
) -> None:
    """Change a local account password using its current password."""

    account = normalize_local_account(account_spec, local_computer=local_computer)
    _validate_password(old_password)
    _validate_password(new_password)
    (api or Win32LocalPasswordChangeApi()).change_password(
        account.computer, account.username, old_password, new_password)


def normalize_rdp_target(ip: str) -> str:
    """Return the canonical Credential Manager target for an IP address."""

    if not isinstance(ip, str):
        raise CredentialValidationError("RDP target IP must be text")
    value = ip.strip()
    if value.casefold().startswith("termsrv/"):
        value = value[len("TERMSRV/") :]
    try:
        canonical_ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CredentialValidationError("RDP target must be an IPv4 or IPv6 address") from exc
    return f"TERMSRV/{canonical_ip}"


def _validate_credential_username(username: str) -> str:
    if not isinstance(username, str):
        raise CredentialValidationError("credential username must be text")
    normalized = username.strip()
    if not normalized or "\x00" in normalized or len(normalized) > 513:
        raise CredentialValidationError("credential username is invalid")
    return normalized


def write_rdp_credential(
    ip: str,
    username: str,
    password: str,
    *,
    api: CredentialStoreApi | None = None,
) -> None:
    """Store an RDP credential; no credential contents are returned."""

    target = normalize_rdp_target(ip)
    normalized_username = _validate_credential_username(username)
    _validate_password(password, credential_blob=True)
    (api or Win32CredentialStoreApi()).write_credential(
        target, normalized_username, password
    )


def rdp_credential_exists(
    ip: str,
    *,
    api: CredentialStoreApi | None = None,
) -> bool:
    """Check for an RDP credential without reading or exposing its secret."""

    target = normalize_rdp_target(ip)
    return (api or Win32CredentialStoreApi()).credential_exists(target)


def rdp_credential_matches(
    ip: str,
    username: str,
    *,
    api: CredentialStoreApi | None = None,
) -> bool:
    """Return whether the saved target belongs to the configured username.

    Password/blob contents are never returned. A stale credential for another
    account must not silently override the username in an RCM-generated .rdp
    file.
    """

    target = normalize_rdp_target(ip)
    normalized_username = _validate_credential_username(username)
    return (api or Win32CredentialStoreApi()).credential_matches_username(
        target, normalized_username)


def delete_rdp_credential(
    ip: str,
    *,
    api: CredentialStoreApi | None = None,
) -> bool:
    """Delete an RDP credential, returning whether an entry existed."""

    target = normalize_rdp_target(ip)
    return (api or Win32CredentialStoreApi()).delete_credential(target)


__all__ = [
    "AccountValidationError",
    "CredentialValidationError",
    "LocalAccount",
    "Win32CredentialStoreApi",
    "Win32LocalPasswordChangeApi",
    "WindowsSecurityError",
    "change_local_account_password",
    "delete_rdp_credential",
    "generate_strong_password",
    "normalize_local_account",
    "normalize_rdp_target",
    "rdp_credential_matches",
    "rdp_credential_exists",
    "write_rdp_credential",
]
