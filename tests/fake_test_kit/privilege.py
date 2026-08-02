from __future__ import annotations

from rcm.local_admin import PrivateFirewallState, RdpHostState
from rcm.privilege import (
    FirewallRuleState,
    IntegrityLevel,
    PrivateFirewallApply,
    PrivilegeReceipt,
    PrivilegeRequest,
    PrivilegeSnapshot,
    PrivilegeStatus,
    PrivilegedOperation,
    RdpHostApply,
)


class FakePrivilegeBoundary:
    """Deterministic observer/broker with no token, process, pipe, or OS access."""

    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self.snapshot = PrivilegeSnapshot(IntegrityLevel.MEDIUM)
        self.rdp = RdpHostState(False, True)
        self.firewall = PrivateFirewallState(
            (FirewallRuleState.ABSENT,) * 3
        )
        self.events: list[tuple[str, str, str]] = []
        self._next_failure: tuple[PrivilegeStatus, str] | None = None

    def fail_next(
        self,
        code: str = "local_admin.synthetic_failure",
        *,
        cancelled: bool = False,
    ) -> None:
        self._next_failure = (
            PrivilegeStatus.CANCELLED if cancelled else PrivilegeStatus.FAILED,
            code,
        )

    def rdp_host_state(self) -> RdpHostState:
        return self.rdp

    def private_firewall_state(self) -> PrivateFirewallState:
        return self.firewall

    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt:
        if not isinstance(request, PrivilegeRequest):
            raise TypeError("request must be a PrivilegeRequest")
        if self._next_failure is not None:
            status, code = self._next_failure
            self._next_failure = None
            self.events.append(
                (request.request_id, request.operation.value, status.value)
            )
            return PrivilegeReceipt(
                request.request_id,
                request.operation,
                status,
                code,
            )
        if request.operation is PrivilegedOperation.RDP_HOST_APPLY:
            assert isinstance(request.arguments, RdpHostApply)
            before = self.rdp
            self.rdp = RdpHostState(
                request.arguments.enabled,
                request.arguments.require_nla,
            )
            changed = before != self.rdp
        else:
            assert isinstance(request.arguments, PrivateFirewallApply)
            before_firewall = self.firewall
            self.firewall = PrivateFirewallState(request.arguments.rules)
            changed = before_firewall != self.firewall
        self.events.append(
            (
                request.request_id,
                request.operation.value,
                PrivilegeStatus.SUCCEEDED.value,
            )
        )
        return PrivilegeReceipt(
            request.request_id,
            request.operation,
            PrivilegeStatus.SUCCEEDED,
            "local_admin.applied",
            changed=changed,
            verified=True,
        )

    def safe_snapshot(self) -> dict[str, object]:
        return {
            "integrity": self.snapshot.integrity.value,
            "administrator_member": self.snapshot.administrator_member,
            "elevated": self.snapshot.elevated,
            "rdp_enabled": self.rdp.enabled,
            "rdp_nla": self.rdp.require_nla,
            "firewall_rules": [item.value for item in self.firewall.rules],
            "events": [list(event) for event in self.events],
        }

    def resource_count(self) -> int:
        return 0


__all__ = ["FakePrivilegeBoundary"]
