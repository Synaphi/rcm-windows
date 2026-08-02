from __future__ import annotations

import unittest

from rcm.resources import read_help_bytes
from rcm.ui.help import load_help, parse_help
from rcm.ui.main_window import MainWindowView
from rcm.ui.state import (
    NodeRenderState,
    RenderState,
    ResultStatus,
    CommandResult,
)
from rcm.ui.status_board import StatusBoardView
from rcm.ui.status_content import cluster_summary, node_status_line


class ViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = (
            NodeRenderState("head", "HEAD", "head", "running", 10, 20, 45),
            NodeRenderState("worker", "WORKER", "worker", "unavailable"),
        )
        self.state = RenderState(nodes=self.nodes, selected_node_id="head")

    def test_main_window_contains_compact_parity_actions(self) -> None:
        model = MainWindowView().render(self.state)
        labels = tuple(action.label for action in model.actions)
        self.assertEqual(
            (
                "Start",
                "Stop",
                "Restart",
                "Status",
                "Settings",
                "Node",
                "Remote Desktop",
                "Cleanup",
                "Help",
            ),
            labels,
        )
        self.assertEqual(2, len(model.node_lines))

    def test_status_content_is_bounded_and_stable(self) -> None:
        self.assertEqual("Nodes 1/2 available", cluster_summary(self.nodes))
        line = node_status_line(self.nodes[0])
        self.assertIn("CPU  10.0%", line)
        self.assertIn("TEMP  45.0 C", line)
        board = StatusBoardView(maximum_lines=1).render(self.state)
        self.assertEqual(1, len(board.lines))

    def test_failed_result_sets_board_severity(self) -> None:
        state = self.state.evolve(
            last_result=CommandResult(
                1, ResultStatus.FAILED, "synthetic_failure", "Failed"
            )
        )
        self.assertEqual("error", StatusBoardView().render(state).severity)

    def test_packaged_help_has_all_parity_sections(self) -> None:
        document = load_help(read_help_bytes)
        self.assertEqual(
            {"overview", "nodes", "rdp", "cleanup", "exit"},
            {section.section_id for section in document.sections},
        )
        self.assertIn("never asks for", document.section("rdp").body)

    def test_help_parser_rejects_duplicate_and_extra_shapes(self) -> None:
        with self.assertRaises(ValueError):
            parse_help(b'{"title":"x","sections":[],"extra":true}')
        with self.assertRaises(ValueError):
            parse_help(
                b'{"title":"x","sections":['
                b'{"id":"a","title":"A","body":"B"},'
                b'{"id":"a","title":"C","body":"D"}]}'
            )


if __name__ == "__main__":
    unittest.main()
