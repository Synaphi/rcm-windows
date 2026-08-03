"""Credential Manager metadata adapter; secret values never cross this API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from ..ports import CredentialReference, CredentialTarget


@dataclass(frozen=True, slots=True, repr=False)
class CredentialMetadata:
    reference: CredentialReference
    present: bool
    principal_matches: bool


class WindowsCredentialStore:
    """Resolve opaque configured bindings using only native target/user metadata."""

    def __init__(
        self,
        bindings: Iterable[CredentialTarget],
        *,
        principal_probe: Callable[[str], str | None] | None = None,
    ) -> None:
        records: dict[CredentialReference, CredentialTarget] = {}
        targets: set[str] = set()
        for binding in bindings:
            if not isinstance(binding, CredentialTarget):
                raise TypeError("credential bindings must contain CredentialTarget values")
            folded = binding.target.casefold()
            if binding.reference in records or folded in targets:
                raise ValueError("credential bindings must be unique")
            records[binding.reference] = binding
            targets.add(folded)
        self._bindings = records
        self._principal_probe = principal_probe or self._read_principal

    def _probe(
        self,
        reference: CredentialReference,
    ) -> tuple[CredentialTarget | None, str | None]:
        if not isinstance(reference, CredentialReference):
            raise TypeError("reference must be a CredentialReference")
        binding = self._bindings.get(reference)
        if binding is None:
            return None, None
        try:
            principal = self._principal_probe(binding.target)
        except Exception:
            raise RuntimeError("credential metadata is unavailable") from None
        if principal is not None and (
            not isinstance(principal, str)
            or not principal
            or any(ord(character) < 0x20 for character in principal)
        ):
            raise RuntimeError("credential metadata is invalid")
        return binding, principal

    def metadata(self, reference: CredentialReference) -> CredentialMetadata:
        binding, principal = self._probe(reference)
        present = binding is not None and principal is not None
        matches = bool(
            present
            and binding is not None
            and (
                not binding.principal
                or binding.principal.casefold() == principal.casefold()
            )
        )
        return CredentialMetadata(reference, present, matches)

    def contains(self, reference: CredentialReference) -> bool:
        metadata = self.metadata(reference)
        return metadata.present and metadata.principal_matches

    def resolve(self, reference: CredentialReference) -> CredentialTarget:
        binding, principal = self._probe(reference)
        if binding is None or principal is None:
            raise LookupError("credential reference is unavailable")
        if binding.principal and binding.principal.casefold() != principal.casefold():
            raise LookupError("credential reference binding does not match")
        return CredentialTarget(
            binding.reference,
            binding.target,
            binding.principal or principal,
        )

    @staticmethod
    def _read_principal(target: str) -> str | None:
        import ctypes
        from ctypes import wintypes

        class _Credential(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.CredReadW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_Credential)),
        )
        advapi32.CredReadW.restype = wintypes.BOOL
        advapi32.CredFree.argtypes = (ctypes.c_void_p,)
        pointer = ctypes.POINTER(_Credential)()
        # RDP uses the Windows authentication packages, whose credential type
        # is CRED_TYPE_DOMAIN_PASSWORD rather than CRED_TYPE_GENERIC.
        if not advapi32.CredReadW(target, 2, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == 1168:
                return None
            raise RuntimeError("credential metadata query failed")
        try:
            principal = pointer.contents.UserName
            return str(principal) if principal else None
        finally:
            advapi32.CredFree(pointer)


__all__ = ["CredentialMetadata", "WindowsCredentialStore"]
