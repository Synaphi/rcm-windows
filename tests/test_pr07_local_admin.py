from __future__ import annotations

import json
import inspect
import unittest

from fake_test_kit.desktop import (
    FakeDesktopHost,
    FakeShutdownFallback,
    FakeSingleton,
)
from fake_test_kit.privilege import FakePrivilegeBoundary
from rcm.adapters.windows_admin import (
    WindowsAdminApplier,
    _WindowsPrivateFirewallPolicy,
)
from rcm.adapters.windows_credentials import WindowsCredentialStore
from rcm.local_admin import (
    LocalAdminService,
    PrivateFirewallState,
    RdpHostState,
)
from rcm.ports import CredentialReference, CredentialTarget
from rcm.privilege import (
    FirewallRuleState,
    PrivateFirewallApply,
    PrivilegeRequest,
    PrivilegeStatus,
    PrivilegedOperation,
    RdpHostApply,
)
from rcm.replacement import plan_replacement


class _Ids:
    def __init__(self) -> None:
        self.value = 1

    def __call__(self) -> str:
        result = f"{self.value:032x}"
        self.value += 1
        return result


class _MemoryRdp:
    def __init__(self) -> None:
        self.state = RdpHostState(False, True)
        self.writes: list[RdpHostApply] = []
        self.fail_after_write = False

    def read(self) -> RdpHostState:
        return self.state

    def write(self, desired: RdpHostApply) -> None:
        self.writes.append(desired)
        self.state = RdpHostState(desired.enabled, desired.require_nla)
        if self.fail_after_write:
            self.fail_after_write = False
            raise RuntimeError("SYNTHETIC_PRIVATE_FAILURE")


class _MemoryFirewall:
    def __init__(self) -> None:
        self.state = PrivateFirewallState(
            (FirewallRuleState.ABSENT,) * 3
        )
        self.writes: list[PrivateFirewallApply] = []
        self.fail_after_write = False

    def read(self) -> PrivateFirewallState:
        return self.state

    def write(self, desired: PrivateFirewallApply) -> None:
        self.writes.append(desired)
        self.state = PrivateFirewallState(desired.rules)
        if self.fail_after_write:
            self.fail_after_write = False
            raise RuntimeError("SYNTHETIC_PRIVATE_FAILURE")


class LocalAdminServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.boundary = FakePrivilegeBoundary()
        self.service = LocalAdminService(
            observer=self.boundary,
            broker=self.boundary,
            request_id_factory=_Ids(),
        )

    def test_rdp_plan_apply_verify_and_rollback_use_one_semantic_type(self) -> None:
        plan = self.service.plan_rdp_host(True)
        self.assertEqual(
            PrivilegedOperation.RDP_HOST_APPLY,
            plan.operation,
        )
        self.assertEqual(RdpHostState(False, True), plan.before)
        self.assertEqual(RdpHostState(True, True), plan.desired)

        applied = self.service.apply(plan)
        self.assertTrue(applied.ok)
        self.assertTrue(self.service.verify(plan))
        rolled_back = self.service.rollback(plan)
        self.assertTrue(rolled_back.ok)
        self.assertTrue(self.service.verify(plan, rolled_back=True))
        self.assertEqual(
            ["rdp_host_apply", "rdp_host_apply"],
            [event[1] for event in self.boundary.events],
        )

    def test_private_firewall_owns_exactly_three_fixed_rule_states(self) -> None:
        plan = self.service.plan_private_firewall(True)
        self.assertEqual(
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY,
            plan.operation,
        )
        self.assertEqual(
            (FirewallRuleState.ENABLED,) * 3,
            plan.desired.rules,
        )
        self.assertTrue(self.service.apply(plan).ok)
        self.assertTrue(self.service.verify(plan))
        self.assertTrue(self.service.rollback(plan).ok)
        self.assertEqual(
            (FirewallRuleState.ABSENT,) * 3,
            self.boundary.firewall.rules,
        )

    def test_private_firewall_rejects_foreign_same_name_rules(self) -> None:
        read = _WindowsPrivateFirewallPolicy._read_script()
        write = _WindowsPrivateFirewallPolicy._write_script(
            PrivateFirewallApply.enabled()
        )
        for marker in (
            "RayClusterManager-Private-Inbound-v1",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallServiceFilter",
            "DisplayName",
            "LocalAddress",
            "RemotePort",
            "InterfaceType",
            "EdgeTraversalPolicy",
        ):
            self.assertIn(marker, read)
            self.assertIn(marker, write)
        self.assertEqual(3, write.count("fixed rule ownership conflict"))
        self.assertEqual(3, write.count("-Group "))
        self.assertLess(
            write.index("fixed rule ownership conflict"),
            write.index("Remove-NetFirewallRule"),
        )

    def test_no_change_does_not_start_a_privileged_action(self) -> None:
        plan = self.service.plan_rdp_host(False)
        receipt = self.service.apply(plan)
        self.assertTrue(receipt.ok)
        self.assertFalse(receipt.changed)
        self.assertEqual([], self.boundary.events)

    def test_cancelled_apply_is_bound_and_does_not_change_state(self) -> None:
        plan = self.service.plan_rdp_host(True)
        self.boundary.fail_next(cancelled=True)
        receipt = self.service.apply(plan)
        self.assertEqual(PrivilegeStatus.CANCELLED, receipt.status)
        self.assertFalse(receipt.ok)
        self.assertEqual(RdpHostState(False, True), self.boundary.rdp)

    def test_windows_applier_rolls_back_partial_rdp_failure(self) -> None:
        rdp = _MemoryRdp()
        firewall = _MemoryFirewall()
        applier = WindowsAdminApplier(rdp=rdp, firewall=firewall)
        rdp.fail_after_write = True
        request = PrivilegeRequest(
            "a" * 32,
            PrivilegedOperation.RDP_HOST_APPLY,
            RdpHostApply(True, True),
        )

        receipt = applier.apply(request)

        self.assertEqual(PrivilegeStatus.FAILED, receipt.status)
        self.assertEqual("local_admin.apply_failed", receipt.code)
        self.assertFalse(receipt.changed)
        self.assertEqual(RdpHostState(False, True), rdp.state)
        self.assertEqual(2, len(rdp.writes))
        self.assertEqual([], firewall.writes)

    def test_windows_applier_rolls_back_partial_firewall_failure(self) -> None:
        rdp = _MemoryRdp()
        firewall = _MemoryFirewall()
        applier = WindowsAdminApplier(rdp=rdp, firewall=firewall)
        firewall.fail_after_write = True
        request = PrivilegeRequest(
            "b" * 32,
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY,
            PrivateFirewallApply.enabled(),
        )

        receipt = applier.apply(request)

        self.assertEqual(PrivilegeStatus.FAILED, receipt.status)
        self.assertFalse(receipt.changed)
        self.assertEqual(
            (FirewallRuleState.ABSENT,) * 3,
            firewall.state.rules,
        )
        self.assertEqual(2, len(firewall.writes))
        self.assertEqual([], rdp.writes)

    def test_credential_adapter_returns_only_bound_metadata(self) -> None:
        reference = CredentialReference("credential://rdp/synthetic-node")
        binding = CredentialTarget(
            reference,
            "TERMSRV/synthetic-node",
            "SYNTHETIC\\operator",
        )
        raw_value = "SYNTHETIC_SECRET_VALUE"
        store = WindowsCredentialStore(
            (binding,),
            principal_probe=lambda _target: "SYNTHETIC\\operator",
        )

        metadata = store.metadata(reference)
        resolved = store.resolve(reference)
        rendered = json.dumps(
            {
                "present": metadata.present,
                "principal_matches": metadata.principal_matches,
                "target_repr": repr(resolved),
                "store_repr": repr(store),
            },
            sort_keys=True,
        )

        self.assertTrue(store.contains(reference))
        self.assertTrue(metadata.present)
        self.assertNotIn(raw_value, rendered)
        self.assertNotIn("synthetic-node", repr(resolved).lower())
        self.assertNotIn("operator", repr(resolved).lower())

        def explode(_target: str) -> str:
            raise RuntimeError(raw_value)

        failing = WindowsCredentialStore((binding,), principal_probe=explode)
        with self.assertRaisesRegex(
            RuntimeError,
            "^credential metadata is unavailable$",
        ) as caught:
            failing.contains(reference)
        self.assertNotIn(raw_value, str(caught.exception))

    def test_rdp_metadata_uses_domain_password_credential_type(self) -> None:
        source = inspect.getsource(WindowsCredentialStore._read_principal)
        self.assertIn("CredReadW(target, 2, 0", source)
        self.assertNotIn("CredReadW(target, 1, 0", source)

    def test_replacement_is_identity_planning_only_and_has_zero_privilege(self) -> None:
        first = "1" * 64
        second = "2" * 64
        plan = plan_replacement(first, second)
        self.assertTrue(plan.differs)
        self.assertEqual("pr-09", plan.deferred_to)
        self.assertEqual(0, plan.to_dict()["privileged_operation_count"])
        self.assertFalse(hasattr(plan, "apply"))
        self.assertFalse(hasattr(plan, "execute"))

    def test_desktop_fakes_have_no_runtime_resources_after_dispose(self) -> None:
        host = FakeDesktopHost()
        observed: list[str] = []
        host.call_later(10, lambda: observed.append("later"))
        host.call_later(0, lambda: observed.append("now"))
        self.assertTrue(host.run_next())
        self.assertEqual(["now"], observed)
        self.assertEqual(1, host.pending_count)
        host.dispose()
        self.assertEqual(0, host.resource_count())

        singleton = FakeSingleton()
        lease = singleton.acquire("synthetic-dev")
        self.assertIsNotNone(lease)
        self.assertIsNone(singleton.acquire("synthetic-dev"))
        assert lease is not None
        lease.release()
        self.assertEqual(0, singleton.resource_count())

        fallback = FakeShutdownFallback()
        fallback(("synthetic-owned-component",), 5.0)
        self.assertEqual(1, len(fallback.calls))


if __name__ == "__main__":
    unittest.main()
