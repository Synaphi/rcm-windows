"""Pure release-identity policy for RCM 2.x."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
import re


PRODUCT_MAJOR = 2
SEOUL_TIMEZONE = timezone(timedelta(hours=9), "KST")
MAX_SIGNED_SEQUENCE = (1 << 63) - 1
_DISPLAY = re.compile(
    r"^2\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])([a-z])$"
)
_COMMIT = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


class ReleaseKind(str, Enum):
    FORMAL = "formal"
    COMMIT_SNAPSHOT = "commit_snapshot"


def _revision_number(revision: object) -> int:
    if (
        not isinstance(revision, str)
        or len(revision) != 1
        or not "a" <= revision <= "z"
    ):
        raise ValueError("release revision must be one lowercase letter from a to z")
    return ord(revision) - ord("a") + 1


def _signed_sequence(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_SIGNED_SEQUENCE
    ):
        raise ValueError("release sequence must be a positive signed 64-bit integer")
    return value


def compare_signed_sequence(left: int, right: int) -> int:
    """Compare authenticated release sequences without parsing display text."""

    first = _signed_sequence(left)
    second = _signed_sequence(right)
    return (first > second) - (first < second)


def release_date_for(value: date | datetime) -> date:
    """Return the KST calendar date for an explicit build timestamp."""

    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("release timestamps must be timezone-aware")
        return value.astimezone(SEOUL_TIMEZONE).date()
    if isinstance(value, date):
        return value
    raise TypeError("release date must be a date or aware datetime")


def _display(released: date, revision: str) -> str:
    return f"{PRODUCT_MAJOR}.{released.month:02d}.{released.day:02d}{revision}"


def _sequence(released: date, revision_number: int) -> int:
    # YYYYMMDDrr is chronological, year-aware, readable, and comfortably
    # inside the signed 64-bit range used by signed update metadata.
    value = (
        released.year * 1_000_000
        + released.month * 10_000
        + released.day * 100
        + revision_number
    )
    return _signed_sequence(value)


@dataclass(frozen=True, slots=True, repr=False)
class ReleaseIdentity:
    kind: ReleaseKind
    display_version: str
    release_date: date
    revision: str
    release_id: str
    tag: str | None
    sequence: int | None
    windows_version: str
    windows_tuple: tuple[int, int, int, int]
    commit_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ReleaseKind):
            raise TypeError("release kind must be a ReleaseKind")
        if not isinstance(self.release_date, date) or isinstance(
            self.release_date,
            datetime,
        ):
            raise TypeError("release_date must be a date")
        revision_number = _revision_number(self.revision)
        if self.display_version != _display(self.release_date, self.revision):
            raise ValueError("display version does not match release date and revision")
        match = _DISPLAY.fullmatch(self.display_version)
        if match is None:
            raise ValueError("display version must match 2.MM.DD<letter>")
        try:
            date(
                self.release_date.year,
                int(match.group(1)),
                int(match.group(2)),
            )
        except ValueError:
            raise ValueError("display version contains an invalid calendar date") from None

        expected_windows = (
            PRODUCT_MAJOR,
            self.release_date.year,
            self.release_date.month * 100 + self.release_date.day,
            revision_number if self.kind is ReleaseKind.FORMAL else 0,
        )
        if self.windows_tuple != expected_windows:
            raise ValueError("Windows version tuple does not match release identity")
        if any(not 0 <= component <= 65_535 for component in self.windows_tuple):
            raise ValueError("Windows version component is outside the supported range")
        if self.windows_version != ".".join(map(str, self.windows_tuple)):
            raise ValueError("Windows version text does not match its tuple")

        date_token = self.release_date.isoformat()
        if self.kind is ReleaseKind.FORMAL:
            expected_id = f"rcm-{PRODUCT_MAJOR}-{date_token}-{self.revision}"
            expected_tag = (
                f"v{PRODUCT_MAJOR}.{self.release_date.year:04d}."
                f"{self.release_date.month:02d}.{self.release_date.day:02d}"
                f"{self.revision}"
            )
            if self.release_id != expected_id or self.tag != expected_tag:
                raise ValueError("formal release ID or tag is not canonical")
            if self.sequence != _sequence(self.release_date, revision_number):
                raise ValueError("formal release sequence is not canonical")
            if self.commit_id is not None:
                raise ValueError("formal release identity must not contain a commit ID")
        else:
            if not isinstance(self.commit_id, str) or not _COMMIT.fullmatch(
                self.commit_id
            ):
                raise ValueError("commit snapshot requires a full hexadecimal commit ID")
            if self.commit_id != self.commit_id.lower():
                raise ValueError("commit snapshot ID must be lowercase")
            expected_id = (
                f"rcm-{PRODUCT_MAJOR}-snapshot-{date_token}-"
                f"{self.revision}-{self.commit_id}"
            )
            if self.release_id != expected_id:
                raise ValueError("commit snapshot ID is not canonical")
            if self.tag is not None or self.sequence is not None:
                raise ValueError("commit snapshots must not claim a release tag or sequence")

    @property
    def formal(self) -> bool:
        return self.kind is ReleaseKind.FORMAL

    def compare(self, other: ReleaseIdentity) -> int:
        """Compare two formal identities using only their signed sequences."""

        if not isinstance(other, ReleaseIdentity):
            raise TypeError("other must be a ReleaseIdentity")
        if self.sequence is None or other.sequence is None:
            raise ValueError("commit snapshots are not release-ordering values")
        return compare_signed_sequence(self.sequence, other.sequence)

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "display_version": self.display_version,
            "release_date": self.release_date.isoformat(),
            "revision": self.revision,
            "sequence": self.sequence,
            "windows_version": self.windows_version,
            "windows_tuple": list(self.windows_tuple),
        }


class ReleaseIdentityService:
    """Construct canonical identities from caller-supplied temporal facts."""

    def create(
        self,
        released_at: date | datetime,
        revision: str,
        *,
        kind: ReleaseKind = ReleaseKind.FORMAL,
        commit_id: str | None = None,
    ) -> ReleaseIdentity:
        if not isinstance(kind, ReleaseKind):
            raise TypeError("release kind must be a ReleaseKind")
        released = release_date_for(released_at)
        revision_number = _revision_number(revision)
        display = _display(released, revision)
        windows_tuple = (
            PRODUCT_MAJOR,
            released.year,
            released.month * 100 + released.day,
            revision_number if kind is ReleaseKind.FORMAL else 0,
        )
        if kind is ReleaseKind.FORMAL:
            if commit_id is not None:
                raise ValueError("formal releases must not provide a commit ID")
            release_id = (
                f"rcm-{PRODUCT_MAJOR}-{released.isoformat()}-{revision}"
            )
            tag = (
                f"v{PRODUCT_MAJOR}.{released.year:04d}.{released.month:02d}."
                f"{released.day:02d}{revision}"
            )
            sequence: int | None = _sequence(released, revision_number)
            normalized_commit = None
        else:
            if not isinstance(commit_id, str) or not _COMMIT.fullmatch(commit_id):
                raise ValueError("commit snapshot requires a full hexadecimal commit ID")
            normalized_commit = commit_id.lower()
            release_id = (
                f"rcm-{PRODUCT_MAJOR}-snapshot-{released.isoformat()}-"
                f"{revision}-{normalized_commit}"
            )
            tag = None
            sequence = None
        return ReleaseIdentity(
            kind=kind,
            display_version=display,
            release_date=released,
            revision=revision,
            release_id=release_id,
            tag=tag,
            sequence=sequence,
            windows_version=".".join(map(str, windows_tuple)),
            windows_tuple=windows_tuple,
            commit_id=normalized_commit,
        )

    def from_display(
        self,
        display_version: str,
        *,
        year: int,
        kind: ReleaseKind = ReleaseKind.FORMAL,
        commit_id: str | None = None,
    ) -> ReleaseIdentity:
        if isinstance(year, bool) or not isinstance(year, int):
            raise TypeError("release year must be an integer")
        match = _DISPLAY.fullmatch(display_version)
        if match is None:
            raise ValueError("display version must match 2.MM.DD<letter>")
        try:
            released = date(year, int(match.group(1)), int(match.group(2)))
        except ValueError:
            raise ValueError("display version contains an invalid calendar date") from None
        return self.create(
            released,
            match.group(3),
            kind=kind,
            commit_id=commit_id,
        )

    def next_formal(
        self,
        previous: ReleaseIdentity,
        released_at: date | datetime,
    ) -> ReleaseIdentity:
        """Allocate the next collision-free formal date/revision identity."""

        if not isinstance(previous, ReleaseIdentity) or not previous.formal:
            raise ValueError("previous identity must be a formal release")
        released = release_date_for(released_at)
        if released < previous.release_date:
            raise ValueError("next release date must not move backwards")
        if released == previous.release_date:
            if previous.revision == "z":
                raise ValueError("same-day release revisions are exhausted")
            revision = chr(ord(previous.revision) + 1)
        else:
            revision = "a"
        result = self.create(released, revision)
        if result.sequence is None or previous.sequence is None:
            raise AssertionError("formal release is missing a sequence")
        if compare_signed_sequence(result.sequence, previous.sequence) <= 0:
            raise ValueError("next release sequence must increase")
        return result
