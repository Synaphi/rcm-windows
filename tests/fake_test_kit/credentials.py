from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FakeCredential:
    principal: str
    value: str


class FakeCredentialStore:
    def __init__(self) -> None:
        self._records: dict[str, FakeCredential] = {}
        self._references: dict[str, str] = {}
        self._next_reference = 1
        self._events: list[tuple[str, str | None]] = []

    @staticmethod
    def _validate_target(target: str) -> None:
        if not isinstance(target, str) or not target:
            raise ValueError("target must be a non-empty string")

    def _reference(self, target: str) -> str:
        reference = self._references.get(target)
        if reference is None:
            reference = f"credential-{self._next_reference:03d}"
            self._next_reference += 1
            self._references[target] = reference
        return reference

    def set(
        self,
        target: str,
        principal: str,
        value: str,
        *,
        overwrite: bool = False,
    ) -> None:
        if (
            not isinstance(principal, str)
            or not isinstance(value, str)
            or not principal
            or not value
        ):
            raise ValueError("principal and value must be non-empty strings")
        self._validate_target(target)
        if not isinstance(overwrite, bool):
            raise ValueError("overwrite must be a boolean")
        if target in self._records and not overwrite:
            raise ValueError("fake credential target already exists")
        reference = self._reference(target)
        self._records[target] = FakeCredential(principal, value)
        self._events.append(("overwrite" if overwrite else "set", reference))

    def get(self, target: str) -> FakeCredential | None:
        self._validate_target(target)
        record = self._records.get(target)
        reference = self._references.get(target) if record is not None else None
        self._events.append(("get" if record is not None else "get-miss", reference))
        return record

    def delete(self, target: str) -> bool:
        self._validate_target(target)
        removed = self._records.pop(target, None) is not None
        reference = self._references.pop(target, None) if removed else None
        self._events.append(("delete" if removed else "delete-miss", reference))
        return removed

    def clear(self) -> None:
        self._records.clear()
        self._references.clear()
        self._next_reference = 1
        self._events.clear()

    def snapshot(self) -> dict[str, object]:
        records = sorted(
            self._references[target] for target in self._records
        )
        return {
            "record_references": records,
            "record_count": len(records),
            "events": [list(event) for event in self._events],
        }

    def resource_count(self) -> int:
        return len(self._records)
