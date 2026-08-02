from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from ray_monitor import _append_log_record, _newer_legacy_log


class LogRecoveryTests(unittest.TestCase):
    def test_rename_active_log_then_next_write_reopens_canonical_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ray_monitor.log"
            old_path = Path(str(path) + ".old")

            _append_log_record(str(path), "first\n")
            os.replace(path, old_path)
            _append_log_record(str(path), "second\n")

            self.assertEqual(path.read_text(encoding="utf-8"), "second\n")
            self.assertEqual(old_path.read_text(encoding="utf-8"), "first\n")

    def test_newer_old_log_is_selected_when_active_log_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trouble_log.log"
            old_path = Path(str(path) + ".old")
            path.write_text("stale\n", encoding="utf-8")
            old_path.write_text("newer\n", encoding="utf-8")
            os.utime(path, (100.0, 100.0))
            os.utime(old_path, (200.0, 200.0))

            selected, warning = _newer_legacy_log(
                str(path), now=500.0, stale_after_sec=60.0)

            self.assertEqual(selected, str(old_path))
            self.assertIn("stale", warning)

    def test_fresh_active_log_wins_even_if_old_mtime_is_slightly_newer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ray_monitor.log"
            old_path = Path(str(path) + ".old")
            path.write_text("active\n", encoding="utf-8")
            old_path.write_text("legacy\n", encoding="utf-8")
            os.utime(path, (490.0, 490.0))
            os.utime(old_path, (495.0, 495.0))

            selected, warning = _newer_legacy_log(
                str(path), now=500.0, stale_after_sec=60.0)

            self.assertEqual(selected, str(path))
            self.assertEqual(warning, "")


if __name__ == "__main__":
    unittest.main()
