"""Local-only process cleanup policy and execution facade.

The facade never selects a process by image name alone.  A candidate must
match an explicitly configured image name and a SHA-256 command fingerprint,
belong to the configured local owner and session, and survive exact identity
revalidation before each destructive step.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
import re
from typing import Protocol, Sequence

from .core import ConflictError, RejectedError
from .ports import Clock


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _positive_integer(value: int, field: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")


def _duration(value: float, field: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{field} must be a finite non-negative number")


@dataclass(frozen=True, slots=True, repr=False)
class ProcessIdentity:
    """Fields that must remain exact across scan and termination."""

    pid: int
    create_time: float
    image_name: str
    owner_token: str
    session_id: int

    def __post_init__(self) -> None:
        _positive_integer(self.pid, "pid")
        if (
            isinstance(self.create_time, bool)
            or not isinstance(self.create_time, (int, float))
            or not math.isfinite(self.create_time)
            or self.create_time <= 0
        ):
            raise ValueError("create_time must be a finite positive number")
        if (
            type(self.image_name) is not str
            or not self.image_name
            or len(self.image_name) > 255
            or any(character in self.image_name for character in ("/", "\\", "\0"))
            or any(ord(character) < 32 for character in self.image_name)
        ):
            raise ValueError("image_name must be one safe basename")
        if type(self.owner_token) is not str or not _DIGEST.fullmatch(
            self.owner_token
        ):
            raise ValueError("owner_token must be a lowercase SHA-256 digest")
        if type(self.session_id) is not int or self.session_id < 0:
            raise ValueError("session_id must be a non-negative integer")


@dataclass(frozen=True, slots=True, repr=False)
class ProcessObservation:
    identity: ProcessIdentity
    command_fingerprint: str
    connection_count: int = 0

    def __post_init__(self) -> None:
        if type(self.command_fingerprint) is not str or not _DIGEST.fullmatch(
            self.command_fingerprint
        ):
            raise ValueError(
                "command_fingerprint must be a lowercase SHA-256 digest"
            )
        if type(self.connection_count) is not int or self.connection_count < 0:
            raise ValueError("connection_count must be a non-negative integer")


@dataclass(frozen=True, slots=True, repr=False)
class CleanupRule:
    rule_id: str
    image_names: tuple[str, ...]
    command_fingerprints: tuple[str, ...]
    minimum_age_seconds: float = 0.0
    allow_connections: bool = False
    image_case_sensitive: bool = True

    def __post_init__(self) -> None:
        if type(self.rule_id) is not str or not _SAFE_ID.fullmatch(self.rule_id):
            raise ValueError("rule_id must be one safe identifier")
        if (
            type(self.image_names) is not tuple
            or not self.image_names
            or any(
                type(name) is not str
                or not name
                or len(name) > 255
                or any(character in name for character in ("/", "\\", "\0"))
                for name in self.image_names
            )
        ):
            raise ValueError("image_names must be safe basenames")
        if type(self.image_case_sensitive) is not bool:
            raise ValueError("image_case_sensitive must be a boolean")
        normalized_names = tuple(
            name if self.image_case_sensitive else name.casefold()
            for name in self.image_names
        )
        if len(normalized_names) != len(set(normalized_names)):
            raise ValueError("image_names must be unique")
        if (
            type(self.command_fingerprints) is not tuple
            or not self.command_fingerprints
            or any(
                type(value) is not str or not _DIGEST.fullmatch(value)
                for value in self.command_fingerprints
            )
            or len(self.command_fingerprints)
            != len(set(self.command_fingerprints))
        ):
            raise ValueError(
                "command_fingerprints must be unique SHA-256 digests"
            )
        _duration(self.minimum_age_seconds, "minimum_age_seconds")
        if type(self.allow_connections) is not bool:
            raise ValueError("allow_connections must be a boolean")

    def matches(
        self,
        observation: ProcessObservation,
        *,
        age_seconds: float,
    ) -> bool:
        return (
            (
                observation.identity.image_name
                if self.image_case_sensitive
                else observation.identity.image_name.casefold()
            )
            in {
                name if self.image_case_sensitive else name.casefold()
                for name in self.image_names
            }
            and observation.command_fingerprint in self.command_fingerprints
            and age_seconds >= self.minimum_age_seconds
            and (self.allow_connections or observation.connection_count == 0)
        )


@dataclass(frozen=True, slots=True, repr=False)
class CleanupPolicy:
    owner_token: str
    session_id: int
    rules: tuple[CleanupRule, ...]
    max_processes: int = 256
    result_max_age_seconds: float = 30.0
    graceful_timeout_seconds: float = 10.0
    force_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if type(self.owner_token) is not str or not _DIGEST.fullmatch(
            self.owner_token
        ):
            raise ValueError("owner_token must be a lowercase SHA-256 digest")
        if type(self.session_id) is not int or self.session_id < 0:
            raise ValueError("session_id must be a non-negative integer")
        if type(self.rules) is not tuple or not self.rules:
            raise ValueError("rules must be a non-empty tuple")
        identifiers = tuple(rule.rule_id for rule in self.rules)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("rule identifiers must be unique")
        _positive_integer(self.max_processes, "max_processes")
        _duration(self.result_max_age_seconds, "result_max_age_seconds")
        _duration(self.graceful_timeout_seconds, "graceful_timeout_seconds")
        _duration(self.force_timeout_seconds, "force_timeout_seconds")
        if self.force_timeout_seconds < self.graceful_timeout_seconds:
            raise ValueError(
                "force_timeout_seconds must be at least graceful_timeout_seconds"
            )


@dataclass(frozen=True, slots=True, repr=False)
class CleanupCandidate:
    """Opaque, one-use evidence issued by :class:`CleanupFacade`."""

    ticket: int
    identity: ProcessIdentity
    command_fingerprint: str
    rule_id: str
    scanned_monotonic: float


@dataclass(frozen=True, slots=True, repr=False)
class CleanupScan:
    candidates: tuple[CleanupCandidate, ...]
    inspected_count: int
    scanned_monotonic: float


class CleanupOutcome(StrEnum):
    GRACEFUL = "graceful"
    FORCED = "forced"
    EXITED = "already_exited"
    SKIPPED_STALE = "skipped_stale"
    SKIPPED_CHANGED = "skipped_changed"
    FAILED = "failed"
    FORCE_TIMEOUT = "force_timeout"


@dataclass(frozen=True, slots=True, repr=False)
class CleanupItemResult:
    pid: int
    outcome: CleanupOutcome
    message: str


@dataclass(frozen=True, slots=True, repr=False)
class CleanupReport:
    items: tuple[CleanupItemResult, ...]

    @property
    def successful(self) -> bool:
        return all(
            item.outcome
            in {
                CleanupOutcome.GRACEFUL,
                CleanupOutcome.FORCED,
                CleanupOutcome.EXITED,
            }
            for item in self.items
        )


class CleanupBackend(Protocol):
    """Narrow local process boundary; every mutation is PID-specific."""

    def scan(self, limit: int) -> tuple[ProcessObservation, ...]: ...

    def inspect(self, pid: int) -> ProcessIdentity | None: ...

    def request_graceful(self, expected: ProcessIdentity) -> bool: ...

    def wait(self, pid: int, timeout_seconds: float) -> bool: ...

    def force(self, expected: ProcessIdentity) -> bool: ...


class CleanupFacade:
    def __init__(
        self,
        *,
        clock: Clock,
        backend: CleanupBackend,
        policy: CleanupPolicy,
    ) -> None:
        self._clock = clock
        self._backend = backend
        self._policy = policy
        self._next_ticket = 1
        self._issued: dict[int, CleanupCandidate] = {}

    def scan(self) -> CleanupScan:
        self._issued.clear()
        observed = self._backend.scan(self._policy.max_processes + 1)
        if len(observed) > self._policy.max_processes:
            raise RejectedError("cleanup scan exceeded its configured limit")
        pids = tuple(item.identity.pid for item in observed)
        if len(pids) != len(set(pids)):
            raise RejectedError("cleanup scan returned duplicate process ids")

        scanned_monotonic = self._clock.monotonic()
        wall_now = self._clock.now()
        if wall_now.tzinfo is None or wall_now.utcoffset() is None:
            self._issued.clear()
            raise RejectedError("cleanup clock must be timezone-aware")
        scanned_epoch = wall_now.timestamp()
        candidates: list[CleanupCandidate] = []
        for observation in observed:
            identity = observation.identity
            if (
                identity.owner_token != self._policy.owner_token
                or identity.session_id != self._policy.session_id
            ):
                continue
            age_seconds = max(0.0, scanned_epoch - identity.create_time)
            rule = next(
                (
                    rule
                    for rule in self._policy.rules
                    if rule.matches(observation, age_seconds=age_seconds)
                ),
                None,
            )
            if rule is None:
                continue
            candidate = CleanupCandidate(
                ticket=self._next_ticket,
                identity=identity,
                command_fingerprint=observation.command_fingerprint,
                rule_id=rule.rule_id,
                scanned_monotonic=scanned_monotonic,
            )
            self._next_ticket += 1
            self._issued[candidate.ticket] = candidate
            candidates.append(candidate)
        return CleanupScan(
            candidates=tuple(candidates),
            inspected_count=len(observed),
            scanned_monotonic=scanned_monotonic,
        )

    def execute(
        self,
        candidates: Sequence[CleanupCandidate],
    ) -> CleanupReport:
        selected = tuple(candidates)
        if any(not isinstance(item, CleanupCandidate) for item in selected):
            raise TypeError("candidates must contain CleanupCandidate values")
        if len(selected) > self._policy.max_processes:
            raise RejectedError("too many cleanup candidates")
        if len({candidate.identity.pid for candidate in selected}) != len(
            selected
        ):
            raise RejectedError("duplicate cleanup candidate")
        for candidate in selected:
            if self._issued.get(candidate.ticket) is not candidate:
                raise RejectedError("cleanup evidence was not issued or was reused")

        results: list[CleanupItemResult] = []
        for candidate in selected:
            self._issued.pop(candidate.ticket)
            results.append(self._execute_one(candidate))
        return CleanupReport(tuple(results))

    def _execute_one(self, candidate: CleanupCandidate) -> CleanupItemResult:
        pid = candidate.identity.pid
        age = self._clock.monotonic() - candidate.scanned_monotonic
        if age < 0 or age > self._policy.result_max_age_seconds:
            return CleanupItemResult(
                pid,
                CleanupOutcome.SKIPPED_STALE,
                "scan evidence is stale; rescan required",
            )
        try:
            current = self._backend.inspect(pid)
            if current is None:
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.EXITED,
                    "process is no longer running",
                )
            if current != candidate.identity:
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.SKIPPED_CHANGED,
                    "process identity changed; rescan required",
                )
            if not self._backend.request_graceful(candidate.identity):
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.EXITED,
                    "process exited before graceful request",
                )
            if self._backend.wait(
                pid,
                self._policy.graceful_timeout_seconds,
            ):
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.GRACEFUL,
                    "process ended after graceful request",
                )
            current = self._backend.inspect(pid)
            if current is None:
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.EXITED,
                    "process exited before force request",
                )
            if current != candidate.identity:
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.SKIPPED_CHANGED,
                    "process identity changed; force was refused",
                )
            if not self._backend.force(candidate.identity):
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.EXITED,
                    "process exited before force request",
                )
            if self._backend.wait(pid, self._policy.force_timeout_seconds):
                return CleanupItemResult(
                    pid,
                    CleanupOutcome.FORCED,
                    "process ended after force request",
                )
            return CleanupItemResult(
                pid,
                CleanupOutcome.FORCE_TIMEOUT,
                "process remained after bounded force wait",
            )
        except ConflictError:
            return CleanupItemResult(
                pid,
                CleanupOutcome.SKIPPED_CHANGED,
                "process identity changed; operation was refused",
            )
        except Exception:
            return CleanupItemResult(
                pid,
                CleanupOutcome.FAILED,
                "cleanup backend rejected the process operation",
            )


__all__ = [
    "CleanupBackend",
    "CleanupCandidate",
    "CleanupFacade",
    "CleanupItemResult",
    "CleanupOutcome",
    "CleanupPolicy",
    "CleanupReport",
    "CleanupRule",
    "CleanupScan",
    "ProcessIdentity",
    "ProcessObservation",
]
