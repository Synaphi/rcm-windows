"""Presentation models for the bounded local cleanup facade."""

from __future__ import annotations

from dataclasses import dataclass

from ..cleanup import CleanupReport, CleanupScan


@dataclass(frozen=True, slots=True)
class CleanupRow:
    ticket: int
    pid: int
    image_name: str
    rule_id: str
    selected: bool = False


@dataclass(frozen=True, slots=True)
class CleanupDialogModel:
    rows: tuple[CleanupRow, ...]
    inspected_count: int
    busy: bool = False
    message: str = ""


def render_scan(
    scan: CleanupScan,
    *,
    selected_tickets: tuple[int, ...] = (),
) -> CleanupDialogModel:
    if not isinstance(scan, CleanupScan):
        raise TypeError("scan must be a CleanupScan")
    selected = set(selected_tickets)
    if len(selected) != len(selected_tickets):
        raise ValueError("selected tickets must be unique")
    rows = tuple(
        CleanupRow(
            candidate.ticket,
            candidate.identity.pid,
            candidate.identity.image_name,
            candidate.rule_id,
            candidate.ticket in selected,
        )
        for candidate in scan.candidates
    )
    return CleanupDialogModel(rows, scan.inspected_count)


def report_message(report: CleanupReport) -> str:
    if not isinstance(report, CleanupReport):
        raise TypeError("report must be a CleanupReport")
    succeeded = sum(
        item.outcome.value in {"graceful", "forced", "already_exited"}
        for item in report.items
    )
    return f"Cleanup complete: {succeeded}/{len(report.items)}"
