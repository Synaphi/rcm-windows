"""Non-UI Plan/Apply/Verify/Rollback orchestration for local administration."""

from __future__ import annotations

from dataclasses import dataclass, field
import secrets
from typing import Callable, Protocol

from .privilege import (
    FirewallRuleState, PrivateFirewallApply, PrivilegeArguments,
    PrivilegeBroker, PrivilegeReceipt, PrivilegeRequest, PrivilegeStatus,
    PrivilegedOperation, RdpHostApply,
)


@dataclass(frozen=True, slots=True)
class RdpHostState:
    enabled: bool
    require_nla: bool

    def __post_init__(self) -> None:
        RdpHostApply(self.enabled, self.require_nla)

    def as_apply(self) -> RdpHostApply:
        return RdpHostApply(self.enabled, self.require_nla)


@dataclass(frozen=True, slots=True)
class PrivateFirewallState:
    rules: tuple[FirewallRuleState, ...]

    def __post_init__(self) -> None:
        validated = PrivateFirewallApply(self.rules)
        object.__setattr__(self, "rules", validated.rules)

    def as_apply(self) -> PrivateFirewallApply:
        return PrivateFirewallApply(self.rules)


LocalAdminState = RdpHostState | PrivateFirewallState


class LocalAdminObserver(Protocol):
    def rdp_host_state(self) -> RdpHostState: ...

    def private_firewall_state(self) -> PrivateFirewallState: ...


@dataclass(frozen=True, slots=True, repr=False)
class LocalAdminPlan:
    operation: PrivilegedOperation
    before: LocalAdminState = field(repr=False)
    desired: LocalAdminState = field(repr=False)
    apply_request_id: str
    rollback_request_id: str

    def __post_init__(self) -> None:
        expected = {
            PrivilegedOperation.RDP_HOST_APPLY: RdpHostState,
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY: PrivateFirewallState,
        }.get(self.operation)
        if expected is None:
            raise ValueError("local admin plan operation is not supported")
        if (not isinstance(self.before, expected)
                or not isinstance(self.desired, expected)):
            raise TypeError("local admin plan states do not match its operation")
        if self.apply_request_id == self.rollback_request_id:
            raise ValueError("apply and rollback requests must be distinct")
        self.apply_request()
        self.rollback_request()

    @property
    def changed(self) -> bool:
        return self.before != self.desired

    @staticmethod
    def _arguments(state: LocalAdminState) -> PrivilegeArguments:
        return state.as_apply()

    def apply_request(self) -> PrivilegeRequest:
        return PrivilegeRequest(
            self.apply_request_id, self.operation, self._arguments(self.desired))

    def rollback_request(self) -> PrivilegeRequest:
        return PrivilegeRequest(
            self.rollback_request_id, self.operation, self._arguments(self.before))


class LocalAdminService:
    """Explicit local admin boundary; construction never prompts or elevates."""

    def __init__(self, *, observer: LocalAdminObserver,
                 broker: PrivilegeBroker,
                 request_id_factory: Callable[[], str] | None = None) -> None:
        self._observer = observer
        self._broker = broker
        self._request_id_factory = request_id_factory or (
            lambda: secrets.token_hex(16))

    def _ids(self) -> tuple[str, str]:
        first = self._request_id_factory()
        second = self._request_id_factory()
        if first == second:
            raise RuntimeError("request id factory returned a duplicate")
        return first, second

    def plan_rdp_host(self, enabled: bool, *,
                      require_nla: bool = True) -> LocalAdminPlan:
        before = self._observer.rdp_host_state()
        desired_apply = RdpHostApply(enabled, require_nla)
        desired = RdpHostState(
            desired_apply.enabled, desired_apply.require_nla)
        apply_id, rollback_id = self._ids()
        return LocalAdminPlan(
            PrivilegedOperation.RDP_HOST_APPLY, before, desired,
            apply_id, rollback_id)

    def plan_private_firewall(self, enabled: bool) -> LocalAdminPlan:
        if type(enabled) is not bool:
            raise TypeError("private firewall enabled must be a bool")
        before = self._observer.private_firewall_state()
        desired_apply = (
            PrivateFirewallApply.enabled() if enabled
            else PrivateFirewallApply.absent())
        desired = PrivateFirewallState(desired_apply.rules)
        apply_id, rollback_id = self._ids()
        return LocalAdminPlan(
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY, before, desired,
            apply_id, rollback_id)

    @staticmethod
    def _local_receipt(plan: LocalAdminPlan, *, rollback: bool) -> PrivilegeReceipt:
        request = plan.rollback_request() if rollback else plan.apply_request()
        return PrivilegeReceipt(
            request.request_id, request.operation, PrivilegeStatus.SUCCEEDED,
            "local_admin.no_change", changed=False, verified=True)

    @staticmethod
    def _bind_receipt(request: PrivilegeRequest,
                      receipt: PrivilegeReceipt) -> PrivilegeReceipt:
        if not isinstance(receipt, PrivilegeReceipt):
            raise TypeError("privilege broker returned an invalid receipt")
        if (receipt.request_id != request.request_id
                or receipt.operation is not request.operation):
            raise RuntimeError("privilege broker receipt binding failed")
        return receipt

    def apply(self, plan: LocalAdminPlan) -> PrivilegeReceipt:
        if not isinstance(plan, LocalAdminPlan):
            raise TypeError("plan must be a LocalAdminPlan")
        if not plan.changed:
            return self._local_receipt(plan, rollback=False)
        request = plan.apply_request()
        return self._bind_receipt(request, self._broker.apply(request))

    def verify(self, plan: LocalAdminPlan, *, rolled_back: bool = False) -> bool:
        if not isinstance(plan, LocalAdminPlan):
            raise TypeError("plan must be a LocalAdminPlan")
        expected = plan.before if rolled_back else plan.desired
        if plan.operation is PrivilegedOperation.RDP_HOST_APPLY:
            observed: LocalAdminState = self._observer.rdp_host_state()
        else:
            observed = self._observer.private_firewall_state()
        return observed == expected

    def rollback(self, plan: LocalAdminPlan) -> PrivilegeReceipt:
        if not isinstance(plan, LocalAdminPlan):
            raise TypeError("plan must be a LocalAdminPlan")
        if not plan.changed:
            return self._local_receipt(plan, rollback=True)
        request = plan.rollback_request()
        return self._bind_receipt(request, self._broker.apply(request))


__all__ = [
    "LocalAdminObserver",
    "LocalAdminPlan",
    "LocalAdminService",
    "PrivateFirewallState",
    "RdpHostState",
]
