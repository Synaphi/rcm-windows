"""Remote Desktop dialog model; password input is intentionally absent."""

from __future__ import annotations

from dataclasses import dataclass

from ..ports import CredentialReference
from ..rdp import RdpRequest


@dataclass(frozen=True, slots=True, repr=False)
class RdpDraft:
    address: str
    principal: str
    port: int = 3_389
    credential_reference: str = ""

    def __post_init__(self) -> None:
        reference = (
            CredentialReference(self.credential_reference)
            if self.credential_reference
            else None
        )
        # The PR-06 request owns canonical validation.
        RdpRequest(self.address, self.principal, self.port, reference)

    def to_request(self) -> RdpRequest:
        reference = (
            CredentialReference(self.credential_reference)
            if self.credential_reference
            else None
        )
        return RdpRequest(
            address=self.address,
            principal=self.principal,
            port=self.port,
            credential_reference=reference,
        )


def rdp_fields() -> tuple[str, ...]:
    return ("address", "principal", "port", "credential_reference")
