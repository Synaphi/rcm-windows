"""Native Remote Desktop service with no secret-bearing input."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
from typing import Protocol

from .core import Capability, RejectedError, UnavailableError
from .ports import CredentialReference, CredentialStore


_HOST_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _address(value: str) -> tuple[str, bool]:
    if (
        type(value) is not str
        or not value
        or len(value) > 253
        or "%" in value
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError("RDP address is invalid")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        labels = value.split(".")
        if (
            any(not label or _HOST_LABEL.fullmatch(label) is None for label in labels)
            or len(value) > 253
        ):
            raise ValueError("RDP address is invalid") from None
        return value.casefold(), False
    return parsed.compressed, parsed.version == 6


def _port(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 65_535:
        raise ValueError("RDP port must be between 1 and 65535")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RdpRequest:
    address: str = field(repr=False)
    principal: str = field(repr=False)
    port: int = 3_389
    credential_reference: CredentialReference | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        normalized, _is_ipv6 = _address(self.address)
        object.__setattr__(self, "address", normalized)
        _port(self.port)
        if (
            type(self.principal) is not str
            or not self.principal
            or len(self.principal) > 256
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.principal
            )
        ):
            raise ValueError("RDP principal must be safe and non-empty")
        if (
            self.credential_reference is not None
            and not isinstance(self.credential_reference, CredentialReference)
        ):
            raise TypeError(
                "credential_reference must be a CredentialReference or None"
            )

    @property
    def target(self) -> str:
        normalized, is_ipv6 = _address(self.address)
        host = f"[{normalized}]" if is_ipv6 else normalized
        return f"{host}:{self.port}"

    @property
    def credential_target(self) -> str:
        normalized, _is_ipv6 = _address(self.address)
        return f"TERMSRV/{normalized}"


@dataclass(frozen=True, slots=True, repr=False)
class RdpLaunchPlan:
    target: str = field(repr=False)
    credential_reference: CredentialReference | None = field(repr=False)
    credential_target: str = field(repr=False)
    principal: str = field(repr=False)
    file_name: str
    file_bytes: bytes = field(repr=False)

    def __post_init__(self) -> None:
        address, canonical_target = _parse_target(self.target)
        if self.target != canonical_target:
            raise ValueError("RDP launch target must be canonical")
        if (
            self.credential_reference is not None
            and not isinstance(self.credential_reference, CredentialReference)
        ):
            raise TypeError(
                "credential_reference must be a CredentialReference or None"
            )
        if self.credential_target != f"TERMSRV/{address}":
            raise ValueError("credential_target must match the native RDP target")
        if (
            type(self.principal) is not str
            or not self.principal
            or len(self.principal) > 256
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.principal
            )
        ):
            raise ValueError("RDP principal must be safe and non-empty")
        if (
            type(self.file_name) is not str
            or re.fullmatch(r"rdp_[A-Za-z0-9_]+\.rdp", self.file_name) is None
            or self.file_name != _file_name(address)
        ):
            raise ValueError("RDP file name is invalid")
        if self.file_bytes != _rdp_bytes(self.target, self.principal):
            raise ValueError("RDP file does not match its typed launch plan")


@dataclass(frozen=True, slots=True, repr=False)
class RdpLaunchReceipt:
    process_id: int | None
    artifact_path: str = field(repr=False)

    def __post_init__(self) -> None:
        if self.process_id is not None and (
            type(self.process_id) is not int or self.process_id <= 0
        ):
            raise ValueError("process_id must be a positive integer or None")
        if type(self.artifact_path) is not str or not self.artifact_path:
            raise ValueError("artifact_path must be non-empty")


class RdpLauncher(Protocol):
    def capability(self) -> Capability: ...

    def launch(self, plan: RdpLaunchPlan) -> RdpLaunchReceipt: ...

    def cleanup(self, receipt: RdpLaunchReceipt) -> None: ...

    def cleanup_all(self) -> None: ...


class RdpService:
    def __init__(
        self,
        *,
        credentials: CredentialStore,
        launcher: RdpLauncher,
    ) -> None:
        self._credentials = credentials
        self._launcher = launcher

    def capability(self) -> Capability:
        return self._launcher.capability()

    def plan(self, request: RdpRequest) -> RdpLaunchPlan:
        if not isinstance(request, RdpRequest):
            raise TypeError("request must be an RdpRequest")
        reference = request.credential_reference
        if reference is not None:
            try:
                available = self._credentials.contains(reference)
                binding = (
                    self._credentials.resolve(reference)
                    if available
                    else None
                )
            except Exception:
                raise UnavailableError(
                    "the requested RDP credential reference is unavailable"
                ) from None
            if binding is None:
                raise UnavailableError(
                    "the requested RDP credential reference is unavailable"
                )
            if (
                binding.reference != reference
                or binding.target.casefold()
                != request.credential_target.casefold()
                or binding.principal.casefold() != request.principal.casefold()
            ):
                raise RejectedError(
                    "the RDP credential reference binding does not match the request"
                )
        return RdpLaunchPlan(
            target=request.target,
            credential_reference=reference,
            credential_target=request.credential_target,
            principal=request.principal,
            file_name=_file_name(request.address),
            file_bytes=_rdp_bytes(request.target, request.principal),
        )

    def launch(self, request: RdpRequest) -> RdpLaunchReceipt:
        return self._launcher.launch(self.plan(request))

    def cleanup(self, receipt: RdpLaunchReceipt) -> None:
        if not isinstance(receipt, RdpLaunchReceipt):
            raise TypeError("receipt must be an RdpLaunchReceipt")
        self._launcher.cleanup(receipt)

    def cleanup_all(self) -> None:
        self._launcher.cleanup_all()


def _file_name(address: str) -> str:
    token = re.sub(r"[^A-Za-z0-9]", "_", address)
    if len(token) > 180:
        suffix = hashlib.sha256(address.encode("ascii")).hexdigest()[:16]
        token = f"{token[:180]}_{suffix}"
    return f"rdp_{token}.rdp"


def _parse_target(value: str) -> tuple[str, str]:
    if type(value) is not str:
        raise ValueError("RDP launch target is invalid")
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or value[closing + 1 : closing + 2] != ":":
            raise ValueError("RDP launch target is invalid")
        raw_address = value[1:closing]
        raw_port = value[closing + 2 :]
    else:
        try:
            raw_address, raw_port = value.rsplit(":", 1)
        except ValueError:
            raise ValueError("RDP launch target is invalid") from None
    try:
        port = int(raw_port)
    except ValueError:
        raise ValueError("RDP launch target is invalid") from None
    if str(port) != raw_port:
        raise ValueError("RDP launch target is invalid")
    address, is_ipv6 = _address(raw_address)
    _port(port)
    host = f"[{address}]" if is_ipv6 else address
    return address, f"{host}:{port}"


def _rdp_bytes(target: str, principal: str) -> bytes:
    lines = (
        "screen mode id:i:2",
        "use multimon:i:0",
        # Keep Windows key combinations on the local desktop.  In a
        # full-screen session mstsc's default routes combinations such as
        # Ctrl+Win+Arrow to the remote PC and can strand the operator on a
        # different remote virtual desktop.
        "keyboardhook:i:0",
        "desktopwidth:i:1280",
        "desktopheight:i:720",
        "session bpp:i:32",
        f"full address:s:{target}",
        "prompt for credentials:i:1",
        "authentication level:i:2",
        "enablecredsspsupport:i:1",
        f"username:s:{principal}",
    )
    return b"\xff\xfe" + ("\r\n".join(lines) + "\r\n").encode("utf-16-le")


__all__ = [
    "RdpLaunchPlan",
    "RdpLaunchReceipt",
    "RdpLauncher",
    "RdpRequest",
    "RdpService",
]
