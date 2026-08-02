"""Static and import-level integration checks for the RCM cleanup surface."""
from __future__ import annotations

import inspect
from pathlib import Path
import unittest

import process_cleanup
import process_cleanup_ui
import ray_monitor


ROOT = Path(__file__).resolve().parent


class ProcessCleanupIntegrationTests(unittest.TestCase):
    def test_feature_is_importable_and_packaged(self) -> None:
        self.assertTrue(ray_monitor._HAS_PROCESS_CLEANUP)
        spec = (ROOT / "RayClusterManager.spec").read_text(encoding="utf-8")
        self.assertIn("'process_cleanup'", spec)
        self.assertIn("'process_cleanup_ui'", spec)

    def test_schema_and_defaults_are_complete(self) -> None:
        self.assertEqual(ray_monitor.DEFAULT_CONFIG["schema_version"], 15)
        values = ray_monitor.DEFAULT_CONFIG["process_cleanup"]
        self.assertEqual(values["sample_sec"], 8.0)
        self.assertEqual(values["grace_sec"], 3.0)
        self.assertEqual(values["result_max_age_sec"], 60.0)
        self.assertEqual(values["ignored_fingerprints"], [])

    def test_main_window_tray_logs_and_shutdown_are_wired(self) -> None:
        build = inspect.getsource(ray_monitor.RayApp._build_ui)
        tray = inspect.getsource(ray_monitor.RayApp._build_tray)
        opener = inspect.getsource(
            ray_monitor.RayApp._open_process_cleanup)
        quit_source = inspect.getsource(ray_monitor.RayApp._quit)
        self.assertIn("Cleanup...", build)
        self.assertIn("Process Cleanup", tray)
        self.assertIn("CleanupPolicy(", opener)
        self.assertIn("ProcessCleanupDialog(", opener)
        self.assertIn("cancel_and_close", quit_source)
        self.assertTrue(hasattr(
            ray_monitor.LogViewerDialog, "show_cleanup_log"))

    def test_ui_exposes_only_review_and_recommended_for_termination(self) -> None:
        toggle = inspect.getsource(
            process_cleanup_ui.ProcessCleanupDialog._toggle_candidate)
        confirm = inspect.getsource(
            process_cleanup_ui.ProcessCleanupDialog._confirm_termination)
        self.assertIn("CLASS_RECOMMENDED", toggle)
        self.assertIn("CLASS_REVIEW", toggle)
        self.assertIn("CLASS_RECOMMENDED", confirm)
        self.assertIn("CLASS_REVIEW", confirm)
        self.assertNotIn("force=True", inspect.getsource(process_cleanup_ui))

    def test_engine_refuses_non_actionable_classifications(self) -> None:
        source = inspect.getsource(process_cleanup.terminate_candidates)
        self.assertIn("CLASS_RECOMMENDED, CLASS_REVIEW", source)
        self.assertNotIn("taskkill", source.casefold())


if __name__ == "__main__":
    unittest.main(verbosity=2)
