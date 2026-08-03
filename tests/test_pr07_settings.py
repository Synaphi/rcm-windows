from __future__ import annotations

from dataclasses import replace
import unittest

from rcm.config.schema import Config, Node, NodesSection, default_config
from rcm.ui.rdp_dialog import rdp_fields
from rcm.ui.settings import SettingsDraft, settings_sections


class SettingsTests(unittest.TestCase):
    def test_draft_round_trip_changes_only_owned_sections(self) -> None:
        original = replace(
            default_config(),
            nodes=NodesSection((Node("node-a", "192.0.2.10"),), "node-a"),
        )
        draft = SettingsDraft(
            "dark",
            150,
            True,
            "en-US",
            True,
            "warning",
            True,
            2_000,
            True,
        )
        updated = draft.apply(original)
        self.assertEqual("dark", updated.ui.theme)
        self.assertEqual(150, updated.ui.scale_percent)
        self.assertTrue(updated.app.start_minimized)
        self.assertEqual(2_000, updated.monitoring.interval_ms)
        self.assertIs(original.nodes, updated.nodes)
        self.assertIs(original.rdp, updated.rdp)
        self.assertIs(original.cleanup, updated.cleanup)

    def test_config_to_draft_keeps_autostart_outside_schema(self) -> None:
        config = default_config()
        draft = SettingsDraft.from_config(config, autostart=True)
        self.assertTrue(draft.autostart)
        self.assertEqual(config, draft.apply(config))

    def test_sections_are_small_and_do_not_offer_remote_password(self) -> None:
        self.assertEqual(
            ("Appearance", "Monitoring", "Startup"),
            settings_sections(),
        )
        fields = rdp_fields()
        self.assertNotIn("password", fields)
        self.assertEqual(
            (
                "address", "principal", "port", "credential_reference",
                "redirect_clipboard",
            ),
            fields,
        )

    def test_invalid_draft_is_rejected_without_coercion(self) -> None:
        baseline = SettingsDraft.from_config(Config())
        for change in (
            {"theme": "unknown"},
            {"scale_percent": 301},
            {"compact_view": 1},
            {"monitoring_interval_ms": 0},
        ):
            with self.subTest(change=change):
                with self.assertRaises((TypeError, ValueError)):
                    replace(baseline, **change)


if __name__ == "__main__":
    unittest.main()
