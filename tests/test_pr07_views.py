from __future__ import annotations

import os
import unittest
from dataclasses import replace
from unittest import mock

from rcm.adapters.windows import compose_local_ray
from rcm.config.schema import Node, NodesSection, RaySection, default_config
from rcm.core import ActionResult, ActionStatus
from rcm.resources import read_help_bytes
from rcm.ui.help import load_help, parse_help
from rcm.ui.main_window import MainWindowView
from rcm.ui.app import LocalRayCommandHandler
from rcm.ui.state import (
    CommandKind,
    NodeRenderState,
    RenderState,
    ResultStatus,
    CommandResult,
    UiCommand,
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
                "Start local Ray",
                "Stop local Ray",
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

    def test_disabled_ray_composition_is_inert_and_does_not_probe_path(self) -> None:
        fallbacks: list[UiCommand] = []
        with mock.patch(
            "rcm.adapters.ray_cli.LocalRayProcessRunner",
            side_effect=AssertionError("disabled composition touched Ray"),
        ):
            handler = compose_local_ray(
                default_config(),
                lambda command: fallbacks.append(command),
            )
        result = handler(UiCommand(1, CommandKind.START))
        self.assertEqual("ray_disabled", result.code)
        handler(UiCommand(2, CommandKind.OPEN_RDP))
        self.assertEqual([CommandKind.OPEN_RDP], [item.kind for item in fallbacks])

    def test_enabled_ray_composition_uses_local_full_user_temp_path(self) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (Node("local-worker", "192.0.2.20", "worker", True, 1),),
                "local-worker",
            ),
            ray=RaySection(
                True,
                r"C:\Synthetic\Python312\Scripts\ray.exe",
                "192.0.2.10",
            ),
        )
        adapter = mock.Mock()
        with mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": r"C:\Synthetic Standard\AppData\Local"},
        ), mock.patch(
            "rcm.adapters.ray_cli.LocalRayProcessRunner"
        ), mock.patch(
            "rcm.adapters.ray_cli.RayCliAdapter", return_value=adapter
        ) as adapter_type:
            handler = compose_local_ray(config, lambda _command: None)
        settings = adapter_type.call_args.args[0]
        self.assertEqual(
            r"C:\Synthetic Standard\AppData\Local\Temp\RayClusterManager\ray",
            settings.temp_dir,
        )
        self.assertIsInstance(handler, LocalRayCommandHandler)

    def test_enabled_ray_composition_fails_closed_without_safe_local_appdata(
        self,
    ) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (Node("local-head", "192.0.2.10", "head", True, 1),),
                "local-head",
            ),
            ray=RaySection(
                True,
                r"C:\Synthetic\Python312\Scripts\ray.exe",
                "192.0.2.10",
            ),
        )
        unc_path = "\\" * 2 + r"synthetic.invalid\share"
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": unc_path}), \
                mock.patch(
                    "rcm.adapters.ray_cli.LocalRayProcessRunner",
                    side_effect=AssertionError("unsafe temp path reached Ray"),
                ):
            handler = compose_local_ray(config, lambda _command: None)
        result = handler(UiCommand(1, CommandKind.START))
        self.assertEqual("ray_config_invalid", result.code)

    def test_local_head_start_verifies_and_rolls_back_on_failure(self) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (Node("local-head", "192.0.2.10", "head", True, 4),),
                "local-head",
            ),
            ray=RaySection(
                True,
                r"C:\Synthetic\Python312\Scripts\ray.exe",
                "192.0.2.10",
            ),
        )
        adapter = mock.Mock()
        adapter.preflight.return_value = ActionResult.success("ray.preflight_ready")
        adapter.start_head.return_value = ActionResult.success("ray.head_started")
        adapter.verify.return_value = ActionResult(
            ActionStatus.FAILED, "ray.exit_nonzero"
        )
        adapter.stop.return_value = ActionResult.success("ray.stopped")
        handler = LocalRayCommandHandler(
            config, adapter, fallback=lambda _command: None
        )
        result = handler(UiCommand(1, CommandKind.START))
        self.assertEqual("ray_start_rolled_back", result.code)
        adapter.preflight.assert_called_once()
        adapter.start_head.assert_called_once()
        adapter.verify.assert_called_once()
        adapter.stop.assert_called_once()

    def test_local_worker_joins_configured_head_and_stop_is_local(self) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (Node("local-worker", "192.0.2.20", "worker", True, 4),),
                "local-worker",
            ),
            ray=RaySection(
                True,
                r"C:\Synthetic\Python312\Scripts\ray.exe",
                "192.0.2.10",
            ),
        )
        adapter = mock.Mock()
        adapter.preflight.return_value = ActionResult.success("ray.preflight_ready")
        adapter.join_worker.return_value = ActionResult.success("ray.worker_joined")
        adapter.stop.return_value = ActionResult.success("ray.stopped")
        handler = LocalRayCommandHandler(
            config, adapter, fallback=lambda _command: None
        )
        joined = handler(UiCommand(1, CommandKind.START))
        stopped = handler(UiCommand(2, CommandKind.STOP))
        self.assertEqual("ray_worker_joined", joined.code)
        self.assertEqual("ray_stopped", stopped.code)
        worker, head = adapter.join_worker.call_args.args
        self.assertEqual("local-worker", worker.node_id)
        self.assertEqual("configured-head", head.node_id)
        self.assertEqual("192.0.2.10", head.address)
        self.assertEqual("local-worker", adapter.stop.call_args.args[0].node_id)

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
            {
                "overview", "nodes", "rdp", "ray", "cleanup", "exit",
                "preview-limits",
            },
            {section.section_id for section in document.sections},
        )
        rdp_help = document.section("rdp").body
        self.assertIn("never accepted or stored", rdp_help)
        self.assertIn("Windows Pro", rdp_help)
        ray_help = document.section("ray").body
        self.assertIn("Exactly Ray 2.55.1", ray_help)
        self.assertIn("does not search PATH", ray_help)
        self.assertIn(
            "published v2.08.03b preview composes personal outbound Remote Desktop",
            document.section("preview-limits").body,
        )

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
