"""Typed resource help loaded only through an explicit reader."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Callable


@dataclass(frozen=True, slots=True)
class HelpSection:
    section_id: str
    title: str
    body: str


@dataclass(frozen=True, slots=True)
class HelpDocument:
    title: str
    sections: tuple[HelpSection, ...]

    def section(self, section_id: str) -> HelpSection:
        for section in self.sections:
            if section.section_id == section_id:
                return section
        raise KeyError(section_id)


def parse_help(raw: bytes, *, maximum_bytes: int = 131_072) -> HelpDocument:
    if type(raw) is not bytes:
        raise TypeError("help resource must be bytes")
    if not raw or len(raw) > maximum_bytes:
        raise ValueError("help resource size is invalid")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("help resource is not strict UTF-8 JSON") from None
    if not isinstance(payload, dict) or set(payload) != {"title", "sections"}:
        raise ValueError("help resource has an invalid root")
    title = payload["title"]
    rows = payload["sections"]
    if not isinstance(title, str) or not title or not isinstance(rows, list):
        raise ValueError("help resource has invalid values")
    sections: list[HelpSection] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "title", "body"}:
            raise ValueError("help section has an invalid shape")
        if any(not isinstance(row[key], str) or not row[key] for key in row):
            raise ValueError("help section values must be non-empty text")
        sections.append(HelpSection(row["id"], row["title"], row["body"]))
    identifiers = tuple(section.section_id for section in sections)
    if not sections or len(identifiers) != len(set(identifiers)):
        raise ValueError("help section identifiers must be non-empty and unique")
    return HelpDocument(title, tuple(sections))


def load_help(reader: Callable[[], bytes]) -> HelpDocument:
    if not callable(reader):
        raise TypeError("reader must be callable")
    return parse_help(reader())
