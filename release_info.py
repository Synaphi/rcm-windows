"""Canonical release metadata for Ray Cluster Manager.

The user-facing version intentionally encodes month/day plus a same-day
revision (for example ``1.07.11a``).  Windows resources cannot use letters,
so their four-part numeric version is derived as
``1.<year>.<MMDD>.<revision>`` where ``a`` is 1, ``b`` is 2, and so on.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import date


_DISPLAY_RE = re.compile(r"^1\.(\d{2})\.(\d{2})([a-z])$")
_TAG_RE = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclass(frozen=True)
class ReleaseInfo:
    display_version: str
    build_date: str
    build_tag: str
    windows_version: str
    windows_tuple: tuple[int, int, int, int]
    slug: str
    final_dir: str
    icon_short_badge: str

    @classmethod
    def create(cls, display_version: str, build_date: str,
               build_tag: str) -> "ReleaseInfo":
        match = _DISPLAY_RE.fullmatch(display_version)
        if not match:
            raise ValueError(
                "display_version must match 1.MM.DD<revision>, e.g. 1.07.11a"
            )
        month, day, suffix = match.groups()
        try:
            built = date.fromisoformat(build_date)
        except ValueError as exc:
            raise ValueError("build_date must be a valid ISO date") from exc
        if (int(month), int(day)) != (built.month, built.day):
            raise ValueError(
                "display_version month/day must match build_date month/day"
            )
        if not _TAG_RE.fullmatch(build_tag):
            raise ValueError(
                "build_tag must start with a lowercase letter and contain "
                "only lowercase letters, digits, or hyphens"
            )

        revision = ord(suffix) - ord("a") + 1
        windows_tuple = (1, built.year, built.month * 100 + built.day, revision)
        if any(not 0 <= component <= 65535 for component in windows_tuple):
            raise ValueError("derived Windows version component is out of range")

        slug = display_version.replace(".", "")
        windows_version = ".".join(str(value) for value in windows_tuple)
        return cls(
            display_version=display_version,
            build_date=build_date,
            build_tag=build_tag,
            windows_version=windows_version,
            windows_tuple=windows_tuple,
            slug=slug,
            final_dir=f"dist_v{slug}_final",
            icon_short_badge=f"{int(month)}{day}{suffix}",
        )

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["windows_tuple"] = list(self.windows_tuple)
        return data


RELEASE = ReleaseInfo.create("1.07.27b", "2026-07-27", "compact-ui")

DISPLAY_VERSION = RELEASE.display_version
BUILD_DATE = RELEASE.build_date
BUILD_TAG = RELEASE.build_tag
WINDOWS_VERSION = RELEASE.windows_version
WINDOWS_VERSION_TUPLE = RELEASE.windows_tuple
RELEASE_SLUG = RELEASE.slug
FINAL_DIR = RELEASE.final_dir
ICON_SHORT_BADGE = RELEASE.icon_short_badge


def main() -> int:
    parser = argparse.ArgumentParser(description="Print canonical RCM release metadata")
    parser.add_argument("--json", action="store_true", help="print metadata as JSON")
    args = parser.parse_args()
    if args.json:
        print(json.dumps(RELEASE.to_dict(), ensure_ascii=False))
    else:
        print(DISPLAY_VERSION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
