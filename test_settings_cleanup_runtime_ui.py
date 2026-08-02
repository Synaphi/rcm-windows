"""Headed DPI/layout regression tests for compact Settings property pages."""
from __future__ import annotations

import copy
import tkinter as tk
import tkinter.font as tkfont
import unittest

import ray_monitor as rm


class SettingsCleanupRuntimeUiTests(unittest.TestCase):
    def _open(self, scale: float, geometry: str = "720x480+10+10"):
        root = tk.Tk()
        root.geometry("1x1+0+0")
        root.tk.call("tk", "scaling", scale)
        dialog = rm.SettingsDialog(
            root, copy.deepcopy(rm.DEFAULT_CONFIG), lambda _cfg: True)
        dialog.geometry(geometry)
        root.update()
        return root, dialog

    def test_baseline_cleanup_uses_two_columns_without_outer_scroll(self):
        root, dialog = self._open(1.333333, "840x580+10+10")
        try:
            dialog._show_settings_section(4)
            root.update()
            dialog._sync_settings_page(4)
            root.update()
            self.assertEqual(
                dialog._cleanup_timing_card.grid_info()["row"], 0)
            self.assertEqual(
                dialog._cleanup_safety_card.grid_info()["row"], 0)
            self.assertFalse(
                dialog._settings_scrollbars[4].winfo_ismapped())
            self.assertLessEqual(dialog.winfo_width(), 840)
            self.assertLessEqual(dialog.winfo_height(), 580)
        finally:
            dialog.destroy()
            root.destroy()

    def test_all_form_pages_reflow_from_measured_width_without_clipping(self):
        root, dialog = self._open(1.333333, "840x580+10+10")
        try:
            # At the baseline width, General and Monitoring use the compact
            # paired-card layout and do not ask for an outer scrollbar.
            for index, cards in (
                    (0, (dialog._general_pc_card,
                         dialog._general_behavior_card)),
                    (2, (dialog._monitor_temperature_card,
                         dialog._monitor_metrics_card))):
                dialog._show_settings_section(index)
                root.update()
                dialog._sync_settings_page(index)
                root.update()
                self.assertEqual(
                    cards[0].grid_info()["row"],
                    cards[1].grid_info()["row"])
                self.assertFalse(
                    dialog._settings_scrollbars[index].winfo_ismapped())

            # Cluster is allowed to stack if the Ray path row needs it, but
            # every button must remain inside the actual canvas viewport.
            dialog.geometry("720x480+10+10")
            dialog._show_settings_section(1)
            root.update()
            dialog._sync_settings_page(1)
            root.update()
            canvas = dialog._settings_canvases[1]
            canvas_right = canvas.winfo_rootx() + canvas.winfo_width()
            buttons = []
            pending = [dialog._cluster_runtime_card]
            while pending:
                widget = pending.pop()
                pending.extend(widget.winfo_children())
                if isinstance(widget, tk.Button):
                    buttons.append(widget)
            self.assertTrue(buttons)
            for button in buttons:
                self.assertLessEqual(
                    button.winfo_rootx() + button.winfo_width(),
                    canvas_right,
                    button.cget("text"))
        finally:
            dialog.destroy()
            root.destroy()

    def test_long_footer_error_is_bounded_and_full_text_is_retained(self):
        for scale in (1.333333, 3.0):
            with self.subTest(scale=scale):
                root, dialog = self._open(scale)
                try:
                    full = "validation-" * 100
                    dialog._set_settings_error(full)
                    root.update()
                    self.assertEqual(dialog._settings_error_full, full)
                    self.assertIn(
                        "click for details", dialog.error_lbl.cget("text"))
                    self.assertGreater(
                        int(dialog.error_lbl.cget("wraplength")), 0)
                    self.assertGreater(
                        dialog._settings_canvases[0].winfo_height(), 1)
                    for button in dialog._settings_action_buttons:
                        self.assertLessEqual(
                            button.winfo_rooty() + button.winfo_height(),
                            dialog.winfo_rooty() + dialog.winfo_height(),
                            button.cget("text"))
                finally:
                    dialog.destroy()
                    root.destroy()

    def test_narrow_high_dpi_reflows_and_keeps_node_actions_accessible(self):
        root, dialog = self._open(3.0)
        try:
            dialog._show_settings_section(4)
            root.update()
            dialog._sync_settings_page(4)
            root.update()
            self.assertNotEqual(
                dialog._cleanup_timing_card.grid_info()["row"],
                dialog._cleanup_safety_card.grid_info()["row"])

            dialog._show_settings_section(3)
            root.update()
            dialog._sync_settings_page(3)
            root.update()
            self.assertFalse(
                dialog._settings_scrollbars[3].winfo_ismapped())
            self.assertTrue(dialog.nodes_tree_x.winfo_ismapped())
            self.assertTrue(dialog._node_local_actions.winfo_ismapped())
            self.assertTrue(
                dialog._node_credential_actions.winfo_ismapped())
            for button in (
                    dialog.btn_node_edit, dialog.btn_node_delete,
                    dialog.btn_batch_password,
                    dialog.btn_credential_delete, dialog.btn_password):
                self.assertTrue(button.winfo_ismapped(), button.cget("text"))
                self.assertGreaterEqual(
                    button.winfo_width(), button.winfo_reqwidth(),
                    button.cget("text"))
        finally:
            dialog.destroy()
            root.destroy()

    def test_baseline_node_scrollbars_are_demand_driven(self):
        root, dialog = self._open(1.333333, "840x580+10+10")
        try:
            dialog._show_settings_section(3)
            root.update()
            dialog._sync_settings_page(3)
            dialog._refresh_node_scrollbars()
            root.update()
            self.assertEqual(dialog.nodes_tree.xview(), (0.0, 1.0))
            self.assertEqual(dialog.nodes_tree.yview(), (0.0, 1.0))
            self.assertFalse(dialog.nodes_tree_x.winfo_ismapped())
            self.assertFalse(dialog.nodes_tree_y.winfo_ismapped())
            heading_font = tkfont.Font(
                root=dialog, font=dialog._settings_font("bold"))
            for column, heading in (
                    ("role", "Ray role"),
                    ("credential", "Credential")):
                self.assertGreaterEqual(
                    dialog.nodes_tree.column(column, "width"),
                    heading_font.measure(heading)
                    + rm.scaled_px(20, dialog._ui_scale))

            for index in range(80):
                dialog.nodes_tree.insert(
                    "", "end",
                    values=(f"node-{index}", "192.0.2.20", "ray",
                            "worker", "4", "account", "3389", "None"))
            root.update()
            dialog._refresh_node_scrollbars()
            root.update()
            self.assertTrue(dialog.nodes_tree_y.winfo_ismapped())
        finally:
            dialog.destroy()
            root.destroy()

    def test_high_dpi_node_tree_always_has_one_complete_row(self):
        for scale in (2.667, 3.0):
            with self.subTest(scale=scale):
                root, dialog = self._open(scale)
                try:
                    dialog._show_settings_section(3)
                    root.update()
                    dialog._sync_settings_page(3)
                    root.update()
                    first = dialog.nodes_tree.get_children()[0]
                    bbox = dialog.nodes_tree.bbox(first)
                    self.assertTrue(bbox)
                    self.assertLessEqual(
                        bbox[1] + bbox[3],
                        dialog.nodes_tree.winfo_height())

                    dialog.nodes_tree.delete(
                        *dialog.nodes_tree.get_children())
                    for index in range(50):
                        dialog.nodes_tree.insert(
                            "", "end",
                            values=(f"node-{index}", "192.0.2.20", "ray",
                                    "worker", "4", "account", "3389", "None"))
                    root.update()
                    dialog._refresh_node_scrollbars()
                    last = dialog.nodes_tree.get_children()[-1]
                    dialog.nodes_tree.see(last)
                    root.update()
                    bbox = dialog.nodes_tree.bbox(last)
                    self.assertTrue(bbox)
                    self.assertLessEqual(
                        bbox[1] + bbox[3],
                        dialog.nodes_tree.winfo_height())
                    self.assertTrue(dialog.nodes_tree_y.winfo_ismapped())
                finally:
                    dialog.destroy()
                    root.destroy()

    def test_help_uses_only_its_text_scrollbar_and_classic_options_fit(self):
        for scale in (1.333333, 1.5, 2.0, 3.0):
            with self.subTest(scale=scale):
                root, dialog = self._open(scale)
                try:
                    dialog._show_settings_section(5)
                    root.update()
                    dialog._sync_settings_page(5)
                    root.update()
                    self.assertFalse(
                        dialog._settings_scrollbars[5].winfo_ismapped())
                    self.assertTrue(dialog.cmb_help_language.winfo_ismapped())
                    self.assertLessEqual(
                        dialog.cmb_help_language.winfo_height(),
                        dialog.e_cleanup_sample.winfo_height() + 4)
                    self.assertGreaterEqual(
                        dialog.cmb_help_language.winfo_width(),
                        dialog.cmb_help_language.winfo_reqwidth())
                finally:
                    dialog.destroy()
                    root.destroy()


if __name__ == "__main__":
    unittest.main(verbosity=2)
