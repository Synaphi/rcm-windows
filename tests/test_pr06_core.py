from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from rcm.core import (
    ActionResult,
    ActionStatus,
    BusyError,
    BusyState,
    Capability,
    CapabilityState,
    ConflictError,
    MetricSnapshot,
    MetricState,
    Node,
    NodeRole,
    PermissionDeniedError,
    Plan,
    PlanStep,
    RejectedError,
    StaleError,
    UnavailableError,
    UnsupportedError,
    error_from_state,
)
from rcm.ports import (
    CredentialReference,
    CredentialTarget,
    FileKind,
    FileStat,
    ProcessRequest,
    ProcessResult,
    TransportRequest,
    TransportResponse,
)


ROOT = Path(__file__).resolve().parents[1]


class CoreModelTests(unittest.TestCase):
    def test_node_capability_equality_immutability_and_serialization(self) -> None:
        capability = Capability("rdp", CapabilityState.AVAILABLE)
        node = Node(
            "node-001",
            "synthetic-node-001",
            NodeRole.HEAD,
            capabilities=(capability,),
        )
        same = Node(
            "node-001",
            "synthetic-node-001",
            NodeRole.HEAD,
            capabilities=(capability,),
        )

        self.assertEqual(node, same)
        self.assertTrue(capability.available)
        self.assertNotIn("synthetic-node-001", repr(node))
        self.assertEqual(
            {
                "role": "head",
                "enabled": True,
                "capability_count": 1,
                "available_capability_count": 1,
            },
            node.to_dict(),
        )
        with self.assertRaises(FrozenInstanceError):
            node.address = "changed"  # type: ignore[misc]

    def test_node_rejects_weak_types_controls_and_duplicate_capabilities(
        self,
    ) -> None:
        available = Capability("sensor", CapabilityState.AVAILABLE)
        unavailable = Capability("sensor", CapabilityState.UNAVAILABLE)
        cases = (
            lambda: Node("", "host"),
            lambda: Node("node\none", "host"),
            lambda: Node("node", "host", "worker"),  # type: ignore[arg-type]
            lambda: Node("node", "host", enabled=1),  # type: ignore[arg-type]
            lambda: Node(
                "node",
                "host",
                capabilities=(available, unavailable),
            ),
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises((TypeError, ValueError)):
                    case()

    def test_metric_snapshot_is_typed_bounded_and_serializable(self) -> None:
        snapshot = MetricSnapshot(
            "node-001",
            1_000_000_000,
            sequence=7,
            cpu_percent=12,
            memory_percent=34.5,
            temperature_celsius=56,
        )
        self.assertEqual(12.0, snapshot.cpu_percent)
        self.assertEqual("ok", snapshot.to_dict()["state"])
        self.assertEqual(snapshot, MetricSnapshot(**{
            "node_id": "node-001",
            "observed_at_ns": 1_000_000_000,
            "sequence": 7,
            "cpu_percent": 12,
            "memory_percent": 34.5,
            "temperature_celsius": 56,
        }))

        unavailable = MetricSnapshot(
            "node-001",
            2_000_000_000,
            state=MetricState.UNAVAILABLE,
            detail_code="sensor_missing",
        )
        self.assertIsNone(unavailable.temperature_celsius)

        invalid = (
            lambda: MetricSnapshot("node", 0),
            lambda: MetricSnapshot("node", 0, cpu_percent=True),
            lambda: MetricSnapshot("node", 0, cpu_percent=float("nan")),
            lambda: MetricSnapshot("node", 0, cpu_percent=101),
            lambda: MetricSnapshot(
                "node",
                0,
                state=MetricState.STALE,
                cpu_percent=1,
            ),
        )
        for case in invalid:
            with self.subTest(case=case):
                with self.assertRaises((TypeError, ValueError)):
                    case()

    def test_busy_state_requires_explicit_idle_evidence(self) -> None:
        self.assertTrue(BusyState.IDLE.allows_reconfiguration)
        for state in (
            BusyState.BUSY,
            BusyState.UNKNOWN,
            BusyState.MAINTENANCE,
        ):
            with self.subTest(state=state):
                self.assertFalse(state.allows_reconfiguration)

    def test_action_result_and_typed_errors_preserve_safe_structure(self) -> None:
        result = ActionResult.success(
            "started",
            details=(("node", "node-001"),),
        )
        self.assertTrue(result.ok)
        self.assertEqual(
            {"status": "succeeded", "code": "started", "retryable": False},
            result.to_dict(),
        )
        with self.assertRaises(ValueError):
            ActionResult(
                ActionStatus.SUCCEEDED,
                "ok",
                retryable=True,
            )
        with self.assertRaises(ValueError):
            ActionResult(
                ActionStatus.FAILED,
                "failed",
                details=(("node", "one"), ("node", "two")),
            )
        with self.assertRaises(ValueError):
            ActionResult(ActionStatus.FAILED, "PRIVATE_CANARY")

        typed_errors = (
            (UnavailableError, "unavailable", True),
            (UnsupportedError, "unsupported", False),
            (PermissionDeniedError, "permission_denied", False),
            (StaleError, "stale", True),
            (BusyError, "busy", True),
            (ConflictError, "conflict", True),
            (RejectedError, "rejected", False),
        )
        for error_type, code, retryable in typed_errors:
            with self.subTest(error_type=error_type):
                error = error_type(context=(("operation", "synthetic"),))
                result = error.to_result()
                self.assertEqual(code, result.code)
                self.assertEqual(retryable, result.retryable)
                self.assertEqual("", result.message)
                self.assertEqual((), result.details)

    def test_capability_state_maps_to_exact_typed_error(self) -> None:
        mapping = {
            CapabilityState.UNAVAILABLE: UnavailableError,
            CapabilityState.UNSUPPORTED: UnsupportedError,
            CapabilityState.PERMISSION_DENIED: PermissionDeniedError,
        }
        for state, expected in mapping.items():
            with self.subTest(state=state):
                self.assertIsInstance(error_from_state(state), expected)
        with self.assertRaises(ValueError):
            error_from_state(CapabilityState.AVAILABLE)


class PlanTests(unittest.TestCase):
    def test_plan_uses_stable_dependency_order_and_ready_frontier(self) -> None:
        plan = Plan(
            "replace-head",
            9,
            (
                PlanStep("verify", "verify", depends_on=("start",)),
                PlanStep("preflight", "preflight"),
                PlanStep(
                    "stop",
                    "stop",
                    depends_on=("preflight",),
                    disruptive=True,
                ),
                PlanStep("start", "start_head", depends_on=("stop",)),
            ),
        )
        self.assertEqual(
            ("preflight", "stop", "start", "verify"),
            tuple(step.step_id for step in plan.ordered_steps()),
        )
        self.assertEqual(("preflight",), tuple(
            step.step_id for step in plan.ready_steps(())
        ))
        self.assertEqual(("stop",), tuple(
            step.step_id for step in plan.ready_steps(("preflight",))
        ))
        self.assertEqual(9, plan.to_dict()["epoch"])

    def test_public_serialization_omits_topology_and_message_canaries(self) -> None:
        canary = "PRIVATE_CANARY_VALUE"
        values = (
            Node(canary, f"{canary}.example", NodeRole.WORKER).to_dict(),
            MetricSnapshot(canary, 1, cpu_percent=1).to_dict(),
            ActionResult(
                ActionStatus.FAILED, "failed", canary,
                details=(("path", canary),),
            ).to_dict(),
            Plan(
                canary, 1, (PlanStep(canary, "check", node_id=canary),),
            ).to_dict(),
        )
        self.assertNotIn(canary, json.dumps(values, sort_keys=True))

    def test_plan_rejects_duplicate_unknown_self_and_cyclic_dependencies(
        self,
    ) -> None:
        cases = (
            lambda: Plan(
                "duplicate",
                1,
                (PlanStep("one", "a"), PlanStep("one", "b")),
            ),
            lambda: Plan(
                "unknown",
                1,
                (PlanStep("one", "a", depends_on=("missing",)),),
            ),
            lambda: PlanStep("one", "a", depends_on=("one",)),
            lambda: Plan(
                "cycle",
                1,
                (
                    PlanStep("one", "a", depends_on=("two",)),
                    PlanStep("two", "b", depends_on=("one",)),
                ),
            ),
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(ValueError):
                    case()


class PortValueTests(unittest.TestCase):
    def test_process_values_are_immutable_and_fail_closed(self) -> None:
        request = ProcessRequest(
            ("synthetic-tool", "--check"),
            timeout_seconds=5,
        )
        result = ProcessResult(0, "synthetic-output", duration_seconds=0.25)
        self.assertEqual(("synthetic-tool", "--check"), request.argv)
        self.assertTrue(result.ok)
        self.assertNotIn("synthetic-tool", repr(request))
        self.assertNotIn("synthetic-output", repr(result))
        with self.assertRaises(FrozenInstanceError):
            request.argv = ("other",)  # type: ignore[misc]

        invalid = (
            lambda: ProcessRequest(()),
            lambda: ProcessRequest(("",)),
            lambda: ProcessRequest(("tool\nname",)),
            lambda: ProcessRequest(("tool",), timeout_seconds=0),
            lambda: ProcessResult(0, timed_out=True, cancelled=True),
        )
        for case in invalid:
            with self.subTest(case=case):
                with self.assertRaises((TypeError, ValueError)):
                    case()

    def test_credential_contract_exposes_reference_not_secret_value(self) -> None:
        reference = CredentialReference("credential://rdp/node-001")
        target = CredentialTarget(
            reference,
            "TERMSRV/synthetic-node-001",
            "synthetic-account",
        )
        self.assertEqual(reference, target.reference)
        self.assertFalse(hasattr(target, "password"))
        self.assertNotIn("synthetic-account", repr(target))
        self.assertNotIn("synthetic-node-001", repr(target))
        for value in (
            "",
            "node-001",
            "credential://",
            "credential://rdp/node one",
            "credential://rdp/node\none",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CredentialReference(value)

    def test_file_and_transport_values_validate_boundaries(self) -> None:
        stat = FileStat("/synthetic/item", FileKind.FILE, 10, 20, "file-1")
        request = TransportRequest("get", "/health", max_response_bytes=100)
        response = TransportResponse(200, b"{}")
        self.assertEqual(10, stat.size)
        self.assertEqual("GET", request.method)
        self.assertEqual(200, response.status)
        with self.assertRaises(ValueError):
            TransportRequest("GET", "//synthetic/health")
        with self.assertRaises(ValueError):
            TransportResponse(99)

    def test_core_and_port_modules_have_only_stdlib_and_local_imports(self) -> None:
        forbidden = {"tkinter", "requests", "subprocess", "ray"}
        for relative in ("src/rcm/core.py", "src/rcm/ports.py"):
            path = ROOT / relative
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    if node.module:
                        imported.add(node.module.split(".", 1)[0])
            self.assertEqual(set(), imported & forbidden, relative)


if __name__ == "__main__":
    unittest.main()
