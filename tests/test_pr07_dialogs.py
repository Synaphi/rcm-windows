from __future__ import annotations

import unittest

from rcm.cleanup import (
    CleanupCandidate,
    CleanupItemResult,
    CleanupOutcome,
    CleanupReport,
    CleanupScan,
    ProcessIdentity,
)
from rcm.config.schema import Node
from rcm.ui.cleanup_dialog import render_scan, report_message
from rcm.ui.node_dialog import NodeDraft
from rcm.ui.rdp_dialog import RdpDraft


class DialogTests(unittest.TestCase):
    def test_node_draft_converts_to_typed_config_node(self) -> None:
        draft = NodeDraft("node-a", "192.0.2.10", "head", True, 8)
        node = draft.to_node()
        self.assertEqual(Node("node-a", "192.0.2.10", "head", True, 8), node)
        self.assertEqual(draft, NodeDraft.from_node(node))

    def test_node_draft_rejects_remote_or_malformed_addresses(self) -> None:
        for address in (
            "",
            "host name",
            "fe80" + ":" * 2 + "1%7",
            "\\" * 2 + r"host\share",
        ):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    NodeDraft("node-a", address)

    def test_rdp_draft_uses_only_opaque_reference(self) -> None:
        draft = RdpDraft(
            "192.0.2.44",
            r"SYNTHETIC\operator",
            3390,
            "credential://synthetic/rdp",
        )
        request = draft.to_request()
        self.assertEqual("192.0.2.44:3390", request.target)
        self.assertEqual(
            "credential://synthetic/rdp",
            request.credential_reference.value,
        )
        self.assertNotIn("password", RdpDraft.__dataclass_fields__)

    def test_cleanup_rows_keep_scan_ticket_and_exact_identity(self) -> None:
        identity = ProcessIdentity(41001, 1.0, "synthetic.exe", "a" * 64, 2)
        candidate = CleanupCandidate(7, identity, "b" * 64, "rule-a", 3.0)
        scan = CleanupScan((candidate,), 4, 3.0)
        model = render_scan(scan, selected_tickets=(7,))
        self.assertEqual(41001, model.rows[0].pid)
        self.assertTrue(model.rows[0].selected)
        self.assertEqual(4, model.inspected_count)

    def test_cleanup_report_message_is_summary_only(self) -> None:
        report = CleanupReport(
            (
                CleanupItemResult(1, CleanupOutcome.GRACEFUL, "closed"),
                CleanupItemResult(2, CleanupOutcome.FAILED, "failed"),
            )
        )
        self.assertEqual("Cleanup complete: 1/2", report_message(report))


if __name__ == "__main__":
    unittest.main()
