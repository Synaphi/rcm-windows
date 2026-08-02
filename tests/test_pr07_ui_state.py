from __future__ import annotations

from dataclasses import FrozenInstanceError
import unittest

from rcm.desktop import UiThreadGuard
from rcm.ui.state import (
    CommandKind,
    CommandResult,
    NodeRenderState,
    RenderState,
    ResultEvent,
    ResultStatus,
    SnapshotEvent,
    UiCommand,
    reduce_event,
)


class UiStateTests(unittest.TestCase):
    def test_render_state_is_immutable_and_revisioned(self) -> None:
        state = RenderState()
        evolved = state.evolve(status_message="Running")
        self.assertEqual(0, state.revision)
        self.assertEqual(1, evolved.revision)
        with self.assertRaises(FrozenInstanceError):
            evolved.busy = True  # type: ignore[misc]

    def test_typed_command_rejects_secret_fields(self) -> None:
        command = UiCommand(
            7,
            CommandKind.OPEN_RDP,
            (("credential_reference", "credential://synthetic/rdp"),),
        )
        self.assertEqual(
            "credential://synthetic/rdp",
            command.field("credential_reference"),
        )
        for key in ("password", "remote_password", "secret", "credential_value"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    UiCommand(8, CommandKind.OPEN_RDP, ((key, "forbidden"),))

    def test_result_reducer_updates_only_presentation_state(self) -> None:
        state = RenderState(busy=True)
        result = CommandResult(
            3,
            ResultStatus.SUCCEEDED,
            "operation_complete",
            "Complete",
        )
        rendered = reduce_event(state, ResultEvent(result))
        self.assertFalse(rendered.busy)
        self.assertEqual(result, rendered.last_result)
        self.assertEqual("Complete", rendered.status_message)

    def test_stale_snapshot_does_not_replace_newer_state(self) -> None:
        current = RenderState(revision=8, status_message="Current")
        stale = RenderState(revision=7, status_message="Stale")
        self.assertIs(current, reduce_event(current, SnapshotEvent(stale)))

    def test_node_identity_and_selection_are_exact(self) -> None:
        node = NodeRenderState("node-a", "NODE_A", "worker", "ready")
        state = RenderState(nodes=(node,), selected_node_id="node-a")
        self.assertEqual("node-a", state.selected_node_id)
        with self.assertRaises(ValueError):
            RenderState(nodes=(node,), selected_node_id="missing")
        with self.assertRaises(ValueError):
            RenderState(nodes=(node, node))

    def test_ui_thread_guard_fails_closed(self) -> None:
        guard = UiThreadGuard(identity=-1)
        with self.assertRaisesRegex(RuntimeError, "UI thread"):
            guard.assert_current()


if __name__ == "__main__":
    unittest.main()
