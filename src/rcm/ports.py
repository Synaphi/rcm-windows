"""Side-effect-free protocol and value contracts for host adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import math
import re
from typing import Protocol

from .core import ActionResult, MetricSnapshot, Node


_CREDENTIAL_REFERENCE = re.compile(
    r"^credential://[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126})"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}))*$"
)


def _finite_seconds(value: object, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    minimum = 0.0 if not positive else 0.0
    if not math.isfinite(result) or result < minimum or (positive and result == 0):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{name} must be finite and {qualifier}")
    return result


def _safe_text(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if (not value and not allow_empty) or len(value) > 4_096:
        raise ValueError(f"{name} has an invalid length")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


class CancellationToken(Protocol):
    @property
    def cancelled(self) -> bool: ...

    def raise_if_cancelled(self) -> None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def monotonic_ns(self) -> int: ...

    def sleep(self, seconds: int | float) -> None: ...


class FileKind(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"
    OTHER = "other"


@dataclass(frozen=True, slots=True, repr=False)
class FileStat:
    path: str = field(repr=False)
    kind: FileKind
    size: int
    modified_ns: int
    identity: str = field(repr=False)

    def __post_init__(self) -> None:
        _safe_text(self.path, "file path")
        if not isinstance(self.kind, FileKind):
            raise TypeError("file kind must be a FileKind")
        for name, value in (("file size", self.size), ("modified_ns", self.modified_ns)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        _safe_text(self.identity, "file identity", allow_empty=True)


class Filesystem(Protocol):
    def stat(self, path: str) -> FileStat: ...

    def read_bytes(self, path: str, *, limit: int) -> bytes: ...

    def write_bytes(self, path: str, data: bytes) -> None: ...

    def replace(self, source: str, destination: str) -> None: ...

    def unlink(self, path: str, *, missing_ok: bool = False) -> None: ...

    def listdir(self, path: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True, repr=False)
class ProcessRequest:
    argv: tuple[str, ...] = field(repr=False)
    timeout_seconds: float = 60.0
    max_output_bytes: int = 65_536
    cwd: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        argv = tuple(self.argv)
        if not argv:
            raise ValueError("process argv must not be empty")
        for index, argument in enumerate(argv):
            _safe_text(
                argument,
                f"process argv[{index}]",
                allow_empty=index != 0,
            )
        timeout = _finite_seconds(
            self.timeout_seconds,
            "process timeout",
            positive=True,
        )
        if (
            isinstance(self.max_output_bytes, bool)
            or not isinstance(self.max_output_bytes, int)
            or not 1 <= self.max_output_bytes <= 16_777_216
        ):
            raise ValueError("max_output_bytes must be between 1 and 16777216")
        if self.cwd is not None:
            _safe_text(self.cwd, "process cwd")
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "timeout_seconds", timeout)


@dataclass(frozen=True, slots=True, repr=False)
class ProcessResult:
    exit_code: int | None
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)
    duration_seconds: float = 0.0
    timed_out: bool = False
    cancelled: bool = False

    def __post_init__(self) -> None:
        if (
            self.exit_code is not None
            and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int))
        ):
            raise TypeError("process exit_code must be an integer or None")
        if not isinstance(self.stdout, str) or not isinstance(self.stderr, str):
            raise TypeError("process output must be text")
        duration = _finite_seconds(self.duration_seconds, "process duration")
        if type(self.timed_out) is not bool or type(self.cancelled) is not bool:
            raise TypeError("process terminal flags must be bool values")
        if self.timed_out and self.cancelled:
            raise ValueError("a process result cannot be both timed out and cancelled")
        object.__setattr__(self, "duration_seconds", duration)

    @property
    def ok(self) -> bool:
        return (
            self.exit_code == 0
            and not self.timed_out
            and not self.cancelled
        )


class ProcessRunner(Protocol):
    def run(
        self,
        request: ProcessRequest,
        *,
        cancellation: CancellationToken | None = None,
    ) -> ProcessResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class CredentialReference:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not _CREDENTIAL_REFERENCE.fullmatch(
            self.value
        ):
            raise ValueError("credential reference has an invalid format")

@dataclass(frozen=True, slots=True, repr=False)
class CredentialTarget:
    reference: CredentialReference
    target: str = field(repr=False)
    principal: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.reference, CredentialReference):
            raise TypeError("credential target reference must be a CredentialReference")
        _safe_text(self.target, "credential target")
        _safe_text(
            self.principal,
            "credential principal",
            allow_empty=True,
        )


class CredentialStore(Protocol):
    def contains(self, reference: CredentialReference) -> bool: ...

    def resolve(self, reference: CredentialReference) -> CredentialTarget: ...


class Sensor(Protocol):
    def sample(self, node_id: str) -> MetricSnapshot: ...


class RayAdapter(Protocol):
    def preflight(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...

    def stop(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...

    def push_manifest(
        self,
        node: Node,
        manifest_digest: str,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...

    def start_head(
        self,
        node: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...

    def join_worker(
        self,
        node: Node,
        head: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...

    def verify(
        self,
        nodes: tuple[Node, ...],
        head: Node,
        *,
        epoch: int,
        cancellation: CancellationToken | None = None,
    ) -> ActionResult: ...


@dataclass(frozen=True, slots=True, repr=False)
class TransportRequest:
    method: str
    route: str
    timeout_seconds: float = 15.0
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        method = _safe_text(self.method, "transport method")
        if not method.isascii() or not method.isalpha():
            raise ValueError("transport method must contain ASCII letters only")
        if not isinstance(self.route, str) or not self.route.startswith("/"):
            raise ValueError("transport route must be an absolute route")
        _safe_text(self.route, "transport route")
        if self.route.startswith("//") or "#" in self.route:
            raise ValueError("transport route must not contain an authority or fragment")
        timeout = _finite_seconds(
            self.timeout_seconds,
            "transport timeout",
            positive=True,
        )
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1 <= self.max_response_bytes <= 16_777_216
        ):
            raise ValueError("max_response_bytes must be between 1 and 16777216")
        object.__setattr__(self, "method", method.upper())
        object.__setattr__(self, "timeout_seconds", timeout)


@dataclass(frozen=True, slots=True, repr=False)
class TransportResponse:
    status: int
    body: bytes = field(default=b"", repr=False)
    headers: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status, bool)
            or not isinstance(self.status, int)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("transport status must be between 100 and 599")
        if type(self.body) is not bytes:
            raise TypeError("transport response body must be bytes")
        headers = tuple(self.headers)
        for item in headers:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not isinstance(item[1], str)
            ):
                raise TypeError("transport response headers must contain string pairs")
            _safe_text(item[0], "transport response header name")
            _safe_text(
                item[1],
                "transport response header value",
                allow_empty=True,
            )
        object.__setattr__(self, "headers", headers)


class Transport(Protocol):
    def send(
        self,
        request: TransportRequest,
        *,
        cancellation: CancellationToken | None = None,
    ) -> TransportResponse: ...
