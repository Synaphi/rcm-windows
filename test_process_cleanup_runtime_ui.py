"""Headed Tk smoke tests for the Process Cleanup dialog."""
from __future__ import annotations

from dataclasses import replace
import inspect
import time
import tkinter as tk
import unittest
from unittest import mock

import process_cleanup as pc
import process_cleanup_ui as ui


def candidate(pid: int, classification: str) -> pc.CleanupCandidate:
    identity = pc.ProcessIdentity(
        pid, 1_900_000_000.0, rf"c:\synthetic\sample-{pid}.exe",
        pc.command_fingerprint(("sample", str(pid))))
    return pc.CleanupCandidate(
        group_id=f"group-{pid}",
        root=identity,
        members=(identity,),
        member_pids=(pid,),
        label=f"Sample {pid}",
        classification=classification,
        score=90 if classification == pc.CLASS_RECOMMENDED else 55,
        reasons=("synthetic UI smoke candidate",),
        cpu_pct=5.0,
        memory_bytes=256 * 1024 * 1024,
        age_sec=86_400.0,
        safe_command="sample <redacted>",
        scanned_monotonic=time.monotonic(),
    )


class ProcessCleanupRuntimeUiTests(unittest.TestCase):
    def test_selection_defaults_and_stale_gate(self) -> None:
        root = tk.Tk()
        root.withdraw()
        items = [
            candidate(8101, pc.CLASS_RECOMMENDED),
            candidate(8102, pc.CLASS_REVIEW),
            candidate(8103, pc.CLASS_INFO),
            candidate(8104, pc.CLASS_PROTECTED),
        ]
        result = pc.ScanResult(
            items, 100, 0.05, time.time(), time.time())
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(
                        sample_sec=0.05, result_max_age_sec=60))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind != "" or not dialog._candidates:
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("cleanup dialog scan did not finish")
                    time.sleep(0.01)

            self.assertEqual(dialog._selected_ids, {"group-8101"})
            dialog._toggle_candidate("group-8102")
            self.assertIn("group-8102", dialog._selected_ids)
            dialog._toggle_candidate("group-8103")
            dialog._toggle_candidate("group-8104")
            self.assertNotIn("group-8103", dialog._selected_ids)
            self.assertNotIn("group-8104", dialog._selected_ids)

            dialog._scan_stamp = time.monotonic() - 120
            dialog._refresh_freshness()
            self.assertEqual(str(dialog._end_button.cget("state")), "disabled")
            self.assertIn("Stale", dialog._ttl_var.get())
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
            root.update_idletasks()
            root.destroy()

    def test_incomplete_scan_is_non_actionable(self) -> None:
        root = tk.Tk()
        root.withdraw()
        result = pc.ScanResult(
            [], 100, 0.05, time.time(), time.time(),
            errors=["network connection enumeration failed"])
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(sample_sec=0.05))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind != "" or (
                        dialog._status_var.get() == "Preparing scan..."):
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("cleanup dialog error scan did not finish")
                    time.sleep(0.01)
            self.assertTrue(dialog._scan_invalid)
            self.assertEqual(str(dialog._end_button.cget("state")), "disabled")
            self.assertIn("incomplete", dialog._status_var.get().casefold())
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
            root.update_idletasks()
            root.destroy()

    def test_compact_layout_live_dpi_and_idle_resource_contract(self) -> None:
        root = tk.Tk()
        root.geometry("1x1+0+0")
        root.tk.call("tk", "scaling", 1.333333)
        items = [
            candidate(8201, pc.CLASS_RECOMMENDED),
            candidate(8202, pc.CLASS_REVIEW),
            candidate(8203, pc.CLASS_INFO),
            candidate(8204, pc.CLASS_PROTECTED),
        ]
        result = pc.ScanResult(
            items, 120, 0.05, time.time(), time.time())
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(
                        sample_sec=0.05, result_max_age_sec=600))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind or not dialog._candidates:
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("cleanup compact scan did not finish")
                    time.sleep(0.01)
            dialog.update()
            dialog._fit_columns()
            dialog.update()
            columns = tuple(dialog._tree["columns"])
            self.assertLessEqual(
                sum(dialog._tree.column(col, "width") for col in columns),
                dialog._tree.winfo_width())
            self.assertEqual(
                dialog._tree.heading("selected", "text"), "End?")
            self.assertIn(
                "selected to end", dialog._selection_legend.cget("text"))
            self.assertIn(
                "strong evidence",
                dialog._class_legend.cget("text"))
            self.assertFalse(dialog._details_expanded)
            self.assertFalse(dialog._detail_frame.winfo_ismapped())
            self.assertFalse(dialog._tree_yscroll.winfo_ismapped())

            collapsed_height = dialog.winfo_height()
            dialog._set_details_expanded(True)
            dialog.update()
            self.assertGreater(dialog.winfo_height(), collapsed_height)
            self.assertTrue(dialog._detail_frame.winfo_ismapped())
            dialog._set_details_expanded(False)
            dialog.update()
            self.assertEqual(dialog.winfo_height(), collapsed_height)

            # The default compact viewport must end between complete rows,
            # never halfway through visible text.
            root.tk.call("tk", "scaling", 2.667)
            dialog._refresh_live_scale()
            dialog.geometry("820x520")
            dialog.update()
            for item in dialog._tree.get_children():
                bbox = dialog._tree.bbox(item)
                if bbox:
                    self.assertLessEqual(
                        bbox[1] + bbox[3],
                        dialog._tree.winfo_height())

            # Simulate a live RDP/per-monitor DPI transition.
            root.tk.call("tk", "scaling", 3.0)
            deadline = time.monotonic() + 1.2
            while time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            dialog._fit_columns()
            dialog.update()
            self.assertAlmostEqual(dialog._scale, 3.0, places=1)
            dialog.geometry("680x420")
            dialog.update()
            self.assertGreater(dialog.winfo_height(), 420)
            self.assertLessEqual(
                sum(dialog._tree.column(col, "width") for col in columns),
                dialog._tree.winfo_width())
            first_item = dialog._tree.get_children()[0]
            bbox = dialog._tree.bbox(first_item)
            self.assertTrue(bbox)
            self.assertLessEqual(
                bbox[1] + bbox[3], dialog._tree.winfo_height())
            for button in (
                    dialog._recommended_button, dialog._clear_button,
                    dialog._scan_button, dialog._cancel_button,
                    dialog._end_button, dialog._close_button):
                self.assertGreaterEqual(
                    button.winfo_width(), button.winfo_reqwidth(),
                    button.cget("text"))

            source = inspect.getsource(ui.ProcessCleanupDialog)
            self.assertNotIn("_progress.start", source)
            self.assertNotIn("ttk.Progressbar(", source)
            self.assertGreaterEqual(dialog._POLL_IDLE_MS, 500)
            self.assertGreaterEqual(dialog._CLOCK_MS, 1000)
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
                self.assertFalse(dialog._after_ids)
            root.update_idletasks()
            root.destroy()

    def test_candidate_scrollbar_is_demand_driven(self) -> None:
        root = tk.Tk()
        root.geometry("1x1+0+0")
        items = [
            candidate(9000 + index, pc.CLASS_REVIEW)
            for index in range(50)
        ]
        result = pc.ScanResult(
            items, 200, 0.05, time.time(), time.time())
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(sample_sec=0.05))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind or not dialog._candidates:
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("cleanup scrollbar scan did not finish")
                    time.sleep(0.01)
            dialog.update()
            dialog._refresh_tree_scrollbar()
            dialog.update()
            self.assertTrue(dialog._tree_yscroll.winfo_ismapped())
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
            root.update_idletasks()
            root.destroy()

    def test_dpi_row_gutter_details_scroll_and_rescan_timer_contract(self):
        root = tk.Tk()
        root.geometry("1x1+0+0")
        root.tk.call("tk", "scaling", 1.333333)
        result = pc.ScanResult(
            [candidate(9301, pc.CLASS_RECOMMENDED)],
            120, 0.05, time.time(), time.time())
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(
                        sample_sec=0.05, result_max_age_sec=600))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind or not dialog._candidates:
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("cleanup contract scan did not finish")
                    time.sleep(0.01)

                # Rescans must reuse the single poll and clock chains.
                for _index in range(3):
                    dialog.scan()
                    deadline = time.monotonic() + 3.0
                    while dialog._busy_kind:
                        root.update()
                        if time.monotonic() > deadline:
                            self.fail("cleanup rescan did not finish")
                        time.sleep(0.01)
                    for _tick in range(5):
                        root.update()
                        time.sleep(0.01)
                    self.assertEqual(len(dialog._after_ids), 2)

            dialog._set_details_expanded(True)
            dialog._details_text("line one\nline two\nline three")
            for _tick in range(5):
                root.update()
            dialog._refresh_details_scrollbar()
            root.update()
            self.assertFalse(dialog._details_yscroll.winfo_ismapped())

            dialog._details_text("\n".join(
                f"detail line {index}" for index in range(60)))
            for _tick in range(5):
                root.update()
            dialog._refresh_details_scrollbar()
            root.update()
            self.assertTrue(dialog._details_yscroll.winfo_ismapped())

            # Exercise the 120/144/216-DPI boundaries at the smallest
            # supported requested geometry.  One complete row plus a border
            # gutter must remain visible.
            for scale in (1.667, 2.0, 3.0):
                root.tk.call("tk", "scaling", scale)
                dialog._refresh_live_scale()
                dialog.geometry("680x420")
                dialog.update()
                item = dialog._tree.get_children()[0]
                bbox = dialog._tree.bbox(item)
                self.assertTrue(bbox, scale)
                self.assertLess(
                    bbox[1] + bbox[3],
                    dialog._tree.winfo_height(),
                    scale)
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
                self.assertFalse(dialog._after_ids)
            root.update_idletasks()
            root.destroy()

    def test_empty_result_keeps_a_real_viewport_at_144_dpi(self):
        root = tk.Tk()
        root.geometry("1x1+0+0")
        root.tk.call("tk", "scaling", 2.0)
        result = pc.ScanResult(
            [], 120, 0.05, time.time(), time.time())
        dialog = None
        try:
            with mock.patch.object(ui, "scan_processes", return_value=result):
                dialog = ui.ProcessCleanupDialog(
                    root, pc.CleanupPolicy(sample_sec=0.05))
                deadline = time.monotonic() + 3.0
                while dialog._busy_kind or (
                        dialog._status_var.get() == "Preparing scan..."):
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail("empty cleanup scan did not finish")
                    time.sleep(0.01)
            dialog.geometry("680x432")
            for _tick in range(10):
                root.update()
            dialog._fit_responsive_labels()
            dialog.update()
            self.assertTrue(dialog._table_frame.winfo_ismapped())
            self.assertTrue(dialog._tree.winfo_ismapped())
            self.assertGreater(dialog._table_frame.winfo_width(), 1)
            self.assertGreaterEqual(
                dialog._tree.winfo_height(), dialog._px(36) - 2)
            self.assertGreater(
                int(dialog._class_legend.cget("wraplength")), 500)
            self.assertGreater(
                int(dialog._selection_legend.cget("wraplength")), 500)
        finally:
            if dialog is not None:
                dialog.cancel_and_close()
            root.update_idletasks()
            root.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
