"""PR-07 planning seam for replacement work deferred to PR-09."""

from __future__ import annotations

from dataclasses import dataclass
import re


_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value.upper()


@dataclass(frozen=True, slots=True)
class ReplacementPlan:
    current_sha256: str
    candidate_sha256: str
    deferred_to: str = "pr-09"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "current_sha256",
            _digest(self.current_sha256, "current_sha256"),
        )
        object.__setattr__(
            self,
            "candidate_sha256",
            _digest(self.candidate_sha256, "candidate_sha256"),
        )
        if self.deferred_to != "pr-09":
            raise ValueError("replacement execution is deferred exactly to PR-09")

    @property
    def differs(self) -> bool:
        return self.current_sha256 != self.candidate_sha256

    def to_dict(self) -> dict[str, object]:
        return {
            "differs": self.differs,
            "deferred_to": self.deferred_to,
            "privileged_operation_count": 0,
        }


def plan_replacement(
    current_sha256: str,
    candidate_sha256: str,
) -> ReplacementPlan:
    """Compare identities only; this seam cannot execute or mutate a file."""

    return ReplacementPlan(current_sha256, candidate_sha256)


__all__ = ["ReplacementPlan", "plan_replacement"]
