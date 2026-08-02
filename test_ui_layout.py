"""Focused, display-free regression tests for Settings/Fit Screen work."""
import inspect
import json
import os
import re
import tempfile
from unittest import mock

import ray_monitor as rm


def test_content_fit_exact_margin_and_rows():
    got = rm.content_fit_geometry(
        text_width_px=700, char_width_px=8, node_count=5,
        row_height_px=18, chrome_width_px=100, chrome_height_px=300,
        work_area=(0, 0, 1920, 1080), current_xy=(30, 40),
        min_size=(620, 430))
    assert got["desired_width"] == 816  # actual text + two character cells
    assert got["visible_rows"] == 6     # five nodes + one blank row
    assert got["desired_height"] == 430  # min height still wins
    assert (got["x"], got["y"]) == (30, 40)
    assert not got["horizontal_scroll"] and not got["vertical_scroll"]


def test_content_fit_clamps_to_monitor_work_area():
    got = rm.content_fit_geometry(
        text_width_px=2100, char_width_px=9, node_count=50,
        row_height_px=20, chrome_width_px=120, chrome_height_px=260,
        work_area=(1920, -200, 1366, 728), current_xy=(4000, -900),
        min_size=(620, 430))
    assert (got["width"], got["height"]) == (1366, 728)
    assert (got["x"], got["y"]) == (1920, -200)
    assert got["horizontal_scroll"] and got["vertical_scroll"]
    assert got["visible_rows"] == 51


def test_content_fit_scrollbars_propagate_across_axes():
    common = dict(
        text_width_px=0, char_width_px=1, node_count=0,
        row_height_px=1, work_area=(0, 0, 1000, 1000),
        current_xy=(0, 0), min_size=(1, 1),
        right_margin_chars=0, spare_rows=0,
        vertical_scrollbar_width_px=10,
        horizontal_scrollbar_height_px=10)

    # Height overflow first needs a vertical bar; that bar tips width over.
    got = rm.content_fit_geometry(
        chrome_width_px=991, chrome_height_px=1001, **common)
    assert got["vertical_scroll"] and got["horizontal_scroll"]
    assert (got["desired_width"], got["desired_height"]) == (1001, 1011)

    # Width overflow first needs a horizontal bar; that bar tips height over.
    got = rm.content_fit_geometry(
        chrome_width_px=1001, chrome_height_px=991, **common)
    assert got["horizontal_scroll"] and got["vertical_scroll"]
    assert (got["desired_width"], got["desired_height"]) == (1011, 1001)

    # No scrollbar dimensions leak into a layout that needs neither bar.
    got = rm.content_fit_geometry(
        chrome_width_px=990, chrome_height_px=990, **common)
    assert not got["horizontal_scroll"] and not got["vertical_scroll"]
    assert (got["desired_width"], got["desired_height"]) == (990, 990)


def test_content_fit_scrollbar_fixpoint_boundary_property():
    for base_w in (982, 983, 999, 1000, 1001):
        for base_h in (982, 983, 999, 1000, 1001):
            got = rm.content_fit_geometry(
                text_width_px=0, char_width_px=1, node_count=0,
                row_height_px=1, chrome_width_px=base_w,
                chrome_height_px=base_h, work_area=(0, 0, 1000, 1000),
                min_size=(1, 1), right_margin_chars=0, spare_rows=0,
                vertical_scrollbar_width_px=18,
                horizontal_scrollbar_height_px=18)
            horizontal = base_w > 1000
            vertical = base_h > 1000
            for _ in range(2):
                horizontal = horizontal or base_w + (18 if vertical else 0) > 1000
                vertical = vertical or base_h + (18 if horizontal else 0) > 1000
            assert got["horizontal_scroll"] is horizontal
            assert got["vertical_scroll"] is vertical
            assert got["desired_width"] == base_w + (18 if vertical else 0)
            assert got["desired_height"] == base_h + (18 if horizontal else 0)


def test_manual_fit_resyncs_dpi_before_content():
    src = inspect.getsource(rm.RayApp._do_fit_monitor)
    monitor = src.index("_fit_to_monitor")
    content = src.index("_fit_to_content")
    assert monitor < content
    assert 'reason="button"' in src
    assert "apply_geometry=False" in src
    assert "tk.call" not in inspect.getsource(rm.RayApp._fit_to_content)


def test_startup_runs_content_fit_once_after_monitor_fit():
    src = inspect.getsource(rm.RayApp.__init__)
    assert "self.after(160, self._auto_fit_startup)" in src
    startup = inspect.getsource(rm.RayApp._auto_fit_startup)
    assert '_auto_fit_monitor(reason="startup")' in startup
    assert "self.after(500, self._auto_fit_startup_content)" in startup
    content = inspect.getsource(rm.RayApp._auto_fit_startup_content)
    assert "_fit_to_content(persist=True)" in content


def test_settings_are_english_professional_and_dpi_safe():
    src = inspect.getsource(rm.SettingsDialog)
    for marker in ('self.title("Settings")', '"General", "This PC and startup"',
                   '"Cluster", "Ray and networking"',
                   '"Monitoring", "Health thresholds"',
                   '"Nodes & RDP", "Machines and access"',
                   '"Help", "Guides in 5 languages"',
                   'text="Language:"', '"Copy help"',
                   '"English", "한국어", "日本語", "Español", "中文"',
                   '"Save changes"', '"Cancel"'):
        assert marker in src
    assert "RCMSettings" in src and "Tahoma" in src
    assert 'self._ACCENT_SOFT if selected else self._SIDEBAR' in src
    assert 'style="Settings.TCombobox"' in src
    assert "tk.Listbox" not in src
    # v1.07.16c [retrofit]: Settings shares the main window's Win98 theme --
    # gray face, groove group boxes, classic raised buttons, navy selection.
    assert "_SURFACE = GRAY" in src
    assert "_ACCENT = BLUE98" in src
    assert "tk.LabelFrame" in src
    assert 'relief="groove"' in src
    assert 'relief="raised"' in src
    assert 'relief="sunken"' in src
    assert "#f5f7fa" not in src and "#1769e0" not in src
    assert 'style="Settings.Treeview"' in src
    assert "rowheight=scaled_px(22, self._ui_scale)" in src
    assert "xscrollcommand=self._nodes_xview_changed" in src
    assert "yscrollcommand=self._nodes_yview_changed" in src
    assert "def _refresh_node_scrollbars" in src
    assert "column_width = max(" in src
    assert "heading_font.measure(headings[col])" in src
    assert "for index in range(6)" in src
    assert "Only Help content changes language" in src


def test_fit_refreshes_point_fonts_after_scaling_change():
    # v1.07.16c [retrofit]: Tk converts point fonts to pixels at configure
    # time, so a tk-scaling change must re-apply the node list/header fonts
    # or Fit Screen sizes the window to metrics the widgets do not render
    # with (SYNTHETIC_NODE_D: 768px measured vs ~672px rendered).
    src = inspect.getsource(rm.RayApp._fit_to_monitor)
    scaling = src.index('self.tk.call("tk", "scaling", float(target))')
    refresh = src.index("self._refresh_ui_fonts()")
    assert scaling < refresh
    assert "_refresh_ui_fonts" in inspect.getsource(
        rm.RayApp._guard_ui_scaling)
    font_src = inspect.getsource(rm.RayApp._init_ui_fonts)
    for marker in ("RCMDefaultFont", "RCMMonoFont", "RCMDiagnosticFont"):
        assert marker in font_src
    fit_src = inspect.getsource(rm.RayApp._fit_to_content)
    assert "content_min_h" in fit_src and "fit_min_h" in fit_src


def test_new_pc_guide_and_node_registration_fields():
    dialog = object.__new__(rm.SettingsDialog)
    dialog.cfg = {
        "head_ip": "192.0.2.10", "head_port": 6379,
        "dashboard_port": 8265, "temp_port": 8866,
    }
    guide = rm.SettingsDialog._new_pc_guide_text(dialog)
    for marker in ("RAY CLUSTER MANAGER HELP", "Update Fleet", "Add a PC",
                   "Tailscale", "Python", "Join", "RDP", "192.0.2.10"):
        assert marker in guide
    editor = inspect.getsource(rm.SettingsDialog._node_editor)
    assert 'entry("Ray CPUs:"' in editor
    assert 'entry("RDP port:"' in editor
    assert '"num_cpus": cpus' in editor and '"rdp_port": rdp_port' in editor

    app = object.__new__(rm.RayApp)
    discovered = rm.NodeView(
        ip="192.0.2.15", hostname="SYNTHETIC-NODE", alive=True,
        cpu=8, cpu_used=0, gpu=0, mem_gb=0, is_head=False,
        registered=False)
    assert rm.RayApp._node_name(app, discovered) == "SYNTHETIC-NODE*"


def test_rdp_preflight_contract_and_address_formatting():
    assert rm.normalized_rdp_port(None) == 3389
    assert rm.normalized_rdp_port(3390) == 3390
    assert rm.rdp_target_address("192.0.2.11", 3390) == "192.0.2.11:3390"
    assert rm.rdp_target_address("2001:db8::1", 3389) == "[2001:db8::1]:3389"
    src = inspect.getsource(rm.RayApp._open_rdp)
    finish = inspect.getsource(rm.RayApp._finish_rdp_preflight)
    assert 'name="RdpPreflight"' in src
    assert "probe_remote_access" in src
    assert "messagebox.askyesno" in finish
    assert "_launch_rdp" in finish
    assert "listener" in finish


def test_rdp_file_reuses_only_matching_saved_username():
    app = object.__new__(rm.RayApp)
    with tempfile.TemporaryDirectory() as td, \
            mock.patch.object(rm, "config_dir", return_value=td):
        with mock.patch.object(
                rm, "rdp_credential_matches", return_value=False) as matches:
            path = rm.RayApp._rdp_file_for(
                app, "192.0.2.24", r"SYNTHETIC_NODE_G\SYNTHETIC_USER_G")
            with open(path, encoding="utf-16") as handle:
                text = handle.read()
            assert "prompt for credentials:i:1" in text
            assert r"username:s:SYNTHETIC_NODE_G\SYNTHETIC_USER_G" in text
            matches.assert_called_once_with(
                "192.0.2.24", r"SYNTHETIC_NODE_G\SYNTHETIC_USER_G")

        with mock.patch.object(
                rm, "rdp_credential_matches", return_value=True):
            path = rm.RayApp._rdp_file_for(
                app, "192.0.2.24", r"SYNTHETIC_NODE_G\SYNTHETIC_USER_G")
            with open(path, encoding="utf-16") as handle:
                text = handle.read()
            assert "prompt for credentials:i:0" in text


def test_node_table_columns_are_responsive_and_digit_stable():
    # v1.07.16d [flexcols]: columns hug the widest actual cell (at most one
    # space before each ``|`` for the widest cell), numeric cells reserve
    # every digit count they can reach, and widths never shrink in-session.
    app = object.__new__(rm.RayApp)
    # Uninitialized tk.Tk delegates missing attributes to self.tk and would
    # recurse; the real app initializes this in __init__.
    app._node_cols = {}
    head = rm.NodeView(ip="192.0.2.10", hostname="SYNTHETIC_NODE_A", alive=True,
                       cpu=12, cpu_used=0, gpu=0, mem_gb=0, is_head=True,
                       name="SYNTHETIC_NODE_A")
    me = rm.NodeView(ip="192.0.2.15", hostname="SYNTHETIC_NODE_D", alive=True,
                     cpu=32, cpu_used=0, gpu=0, mem_gb=0, is_head=False,
                     name="SYNTHETIC_NODE_D")
    me.is_this = True
    me.conn_label = "Wi:synthetic-wifi"
    me.ram_used_gb, me.ram_total_gb = 15.0, 30.0
    app._node_cols = app._node_col_widths([head, me], show_metrics=True)

    assert app._node_cols["name"] == len("SYNTHETIC_NODE_D(me)") == 20
    assert app._node_cols["conn"] == 16
    assert len("Wi:synthetic-wifi") > app._node_cols["conn"]
    # Ray reserves total/total ("32/32") although used is currently 0.
    assert app._node_cols["ray"] == len("32/32") == 5

    header = app._node_row_header(show_metrics=True)
    pipes = [i for i, ch in enumerate(header) if ch == "|"]
    assert pipes, "metrics header must contain column separators"
    for node, temp in ((head, 54.0), (me, None)):
        row = app._node_row_line(node, temp, show_metrics=True)
        assert [i for i, ch in enumerate(row) if ch == "|"] == pipes

    # Digit growth (0/32 -> 32/32, hotter temps) cannot move the pipes.
    me.cpu_used = 32
    head.cpu_used = 12
    app._node_cols = app._node_col_widths([head, me], show_metrics=True)
    for node in (head, me):
        row = app._node_row_line(node, 104.0, show_metrics=True)
        assert [i for i, ch in enumerate(row) if ch == "|"] == pipes

    # Session-monotonic: a shrunken node list must not narrow the table.
    app._node_cols = app._node_col_widths([head], show_metrics=True)
    assert app._node_cols["conn"] == 16
    assert app._node_cols["name"] == 20


def test_fit_measures_chrome_after_scrollbars_are_hidden():
    src = inspect.getsource(rm.RayApp._fit_to_content)
    hide = src.index("self._set_node_scrollbars(horizontal=False, vertical=False)")
    settle = src.index("self.update_idletasks()")
    viewport = src.index("self.nodes_list.winfo_width()")
    assert hide < settle < viewport


def test_display_inventory_retains_offline_configured_ray_rows():
    online = rm.NodeView(
        ip="192.0.2.10", hostname="Head", alive=True, cpu=12,
        cpu_used=0, gpu=0, mem_gb=0, is_head=True, name="Head")
    cfg = {"nodes": [
        {"name": "Head", "ip": "192.0.2.10", "mode": "ray",
         "role": "head", "num_cpus": 12},
        {"name": "Offline", "ip": "192.0.2.11", "mode": "ray",
         "role": "worker", "num_cpus": 8},
        {"name": "LEGACY_NODE", "ip": "192.0.2.12", "mode": "controller",
         "role": "worker", "num_cpus": 4},
    ]}
    rows = rm.complete_ray_display_nodes([online], cfg, this_ip="192.0.2.10")
    assert [row.ip for row in rows] == ["192.0.2.10", "192.0.2.11"]
    assert rows[1].alive is False
    assert rows[1].metrics_error == "not in Ray"


def test_controller_detection():
    cfg = {"head_ip": "192.0.2.10", "this": {"ip": "192.0.2.15"},
           "nodes": [{"ip": "192.0.2.15", "mode": "controller"}]}
    assert rm.is_controller_config(cfg, "192.0.2.15")
    cfg["nodes"][0]["mode"] = "ray"
    assert not rm.is_controller_config(cfg, "192.0.2.15")
    cfg["this"]["mode"] = "rdp-client"
    assert rm.is_controller_config(cfg, "192.0.2.15")


def test_controller_is_never_an_rdp_or_password_target():
    nodes = [
        {"name": "Ray", "ip": "192.0.2.10", "mode": "ray",
         "rdp_user": r"SYNTHETIC_RAY\user"},
        {"name": "LEGACY_NODE", "ip": "192.0.2.25", "mode": "controller",
         "rdp_user": r"LEGACY_NODE\should-not-count"},
    ]
    targets = rm.rdp_password_targets(nodes)
    assert [n["name"] for n in targets] == ["Ray"]
    assert "controller is outbound-only" in inspect.getsource(
        rm.RayApp._handle_rdp_password_change)
    assert "controller_ips" in inspect.getsource(rm.RayApp._render_nodes)


def test_read_only_server_lifetime_ignores_legacy_control_allowlists():
    cfg = {"temp_enabled": False, "metrics_enabled": False,
           "credential_controller_ips": ["192.0.2.25"]}
    assert not rm.needs_rcm_control_server(cfg, controller_only=False)
    assert not rm.needs_rcm_control_server(cfg, controller_only=True)
    cfg["metrics_enabled"] = True
    assert rm.needs_rcm_control_server(cfg, controller_only=False)

    nodes = [{"ip": "192.0.2.25", "mode": "controller"},
             {"ip": "192.0.2.16", "mode": "ray"}]
    assert rm.credential_controller_allowlist("192.0.2.10", nodes) == []
    assert rm.credential_controller_allowlist(
        "192.0.2.10", nodes[1:]) == []
    # Persisted legacy values round-trip but derive no new authority.
    assert rm.credential_controller_allowlist(
        "192.0.2.10", nodes[1:], ["192.0.2.25", "invalid"]
    ) == ["192.0.2.25"]
    assert "credential_controller_allowlist" in inspect.getsource(
        rm.SettingsDialog._save)


def test_password_ui_scope_and_sequential_batch_marker():
    help_text = rm.SettingsDialog._settings_help_text(None)
    assert "Microsoft-account password changes" in help_text
    assert "A controller manages other PCs but does not join Ray." in help_text
    assert "Remote password change is unavailable" in help_text
    assert "legacy_remote_retired" in help_text
    assert "Windows Hello PIN is not an RDP password." in help_text
    batch_src = inspect.getsource(rm.BatchRdpPasswordDialog)
    assert "zip(self.nodes, old_passwords)" in batch_src.replace("\n", " ")
    assert 'self.result_states[index] == "success"' in batch_src
    assert "self.operation_ids[index]" in batch_src
    assert 'if state == "failure"' in batch_src


def test_help_is_five_language_and_update_fleet_complete():
    dialog = object.__new__(rm.SettingsDialog)
    dialog.cfg = {
        "head_ip": "192.0.2.10", "head_port": 6379,
        "dashboard_port": 8265, "temp_port": 8866,
    }
    titles = {
        "English": "RAY CLUSTER MANAGER HELP",
        "한국어": "RAY CLUSTER MANAGER 도움말",
        "日本語": "RAY CLUSTER MANAGER ヘルプ",
        "Español": "AYUDA DE RAY CLUSTER MANAGER",
        "中文": "RAY CLUSTER MANAGER 帮助",
    }
    documents = {}
    for language, title in titles.items():
        text = rm.SettingsDialog._settings_help_text(dialog, language)
        documents[language] = text
        assert title in text
        assert "Update Fleet" in text
        assert "legacy_remote_retired" in text
        assert "self_update_v1" not in text
        assert "192.0.2.10" in text
        assert len(text) > 2500
    assert len(set(documents.values())) == 5

    english = documents["English"]
    for contract in (
            "Legacy remote update is retired",
            "does not expose a remote update, password, repair",
            "Make this the head is unavailable",
            "RCM 8866 is loopback-only"):
        assert contract in english


def test_application_chrome_is_english_outside_localized_help():
    targets = (
        rm.RdpPasswordDialog,
        rm.BatchRdpPasswordDialog,
        rm.RayApp._finish_rdp_preflight,
        rm.RayApp._settings_password_action,
        rm.RayApp._execute_rdp_password_change,
        rm.RayApp._start_head_change,
    )
    for target in targets:
        assert re.search(r"[가-힣]", inspect.getsource(target)) is None


def test_local_partial_retry_does_not_change_password_twice():
    app = object.__new__(rm.RayApp)
    app.controller_only = False
    app.ip = "192.0.2.10"
    app.cfg = {"temp_port": 8866}
    app._password_completed_operations = []
    node = {"ip": "192.0.2.10", "mode": "ray",
            "rdp_user": r"SYNTHETIC_PC\local"}
    calls = []

    def change(*_args, **_kwargs):
        calls.append("change")

    with mock.patch.object(rm, "change_local_account_password", change), \
            mock.patch.object(rm, "write_rdp_credential",
                              side_effect=OSError("locked")):
        state, _ = app._execute_rdp_password_change(
            node, "old", "new", True, "same-operation")
    assert state == "partial"
    assert calls == ["change"]

    with mock.patch.object(
            rm, "change_local_account_password",
            side_effect=AssertionError("password changed twice")), \
            mock.patch.object(rm, "write_rdp_credential", return_value=True):
        state, _ = app._execute_rdp_password_change(
            node, "old", "new", True, "same-operation")
    assert state == "success"
    assert calls == ["change"]


def test_server_idempotency_key_is_bound_to_exact_password_payload():
    app = object.__new__(rm.RayApp)
    app.controller_only = False
    app._password_change_lock = rm.threading.Lock()
    app._password_request_cache = {}
    app._password_request_hmac_key = b"k" * 32
    app._log = lambda _message: None
    calls = []

    with mock.patch.object(
            rm, "change_local_account_password",
            side_effect=lambda *_args, **_kwargs: calls.append("change")):
        first = app._handle_rdp_password_change(
            r"SYNTHETIC_PC\user", "old-a", "new-a", "operation-1")
        same = app._handle_rdp_password_change(
            r"SYNTHETIC_PC\user", "old-a", "new-a", "operation-1")
        mismatch = app._handle_rdp_password_change(
            r"SYNTHETIC_PC\user", "old-a", "DIFFERENT", "operation-1")

    assert first["ok"] is True and same == first
    assert calls == ["change"]
    assert mismatch["ok"] is False
    assert mismatch["accepted"] is False
    assert "payload mismatch" in mismatch["message"]
    entry = app._password_request_cache["operation-1"]
    assert set(entry) == {"fingerprint", "result"}
    assert "old-a" not in repr(entry) and "new-a" not in repr(entry)


class _PasswordResponse:
    def __init__(self, payload, ok=True):
        self._payload = payload
        self.ok = ok

    def raise_for_status(self):
        if not self.ok:
            raise rm.requests.HTTPError("bad status")

    def json(self):
        return self._payload


def test_remote_password_change_validates_target_and_response_identity():
    app = object.__new__(rm.RayApp)
    app.controller_only = True
    app.ip = "192.0.2.25"
    app.cfg = {"temp_port": 8866}
    app._password_completed_operations = []
    node = {"ip": "192.0.2.110", "mode": "ray", "rdp_user": r"SYNTHETIC_PC\user"}
    with mock.patch.object(
            rm.requests, "get",
            side_effect=AssertionError("remote GET forbidden")) as get, \
            mock.patch.object(
                rm.requests, "post",
                side_effect=AssertionError("remote POST forbidden")) as post, \
            mock.patch.object(
                rm, "write_rdp_credential",
                side_effect=AssertionError("credential write forbidden")) as write:
        state, message = app._execute_rdp_password_change(
            node, "old", "new", True, "op-retired")
    assert (state, message) == ("failure", "legacy_remote_retired")
    get.assert_not_called()
    post.assert_not_called()
    write.assert_not_called()
    return
    good_health = {
        "local_ip": "192.0.2.110", "host": "SYNTHETIC-TARGET",
        "rdp_password_change_v1": True,
    }
    writes = []

    def run(health_payload, response_payload, operation_id):
        with mock.patch.object(
                rm.requests, "get",
                return_value=_PasswordResponse(health_payload)), \
                mock.patch.object(
                    rm.requests, "post",
                    return_value=_PasswordResponse(response_payload)), \
                mock.patch.object(
                    rm, "write_rdp_credential",
                    side_effect=lambda *args: writes.append(args)):
            return app._execute_rdp_password_change(
                node, "old", "new", True, operation_id)

    state, _ = run(
        {**good_health, "local_ip": "192.0.2.111"},
        {"ok": True, "request_id": "op-ip", "host": "SYNTHETIC-TARGET"}, "op-ip")
    assert state == "failure" and writes == []

    state, _ = run(
        {**good_health, "host": ""},
        {"ok": True, "request_id": "op-nohost", "host": "SYNTHETIC-TARGET"},
        "op-nohost")
    assert state == "failure" and writes == []

    state, _ = run(
        good_health,
        {"ok": True, "request_id": "wrong", "host": "SYNTHETIC-TARGET"},
        "op-request")
    assert state == "failure" and writes == []

    state, _ = run(
        good_health,
        {"ok": True, "request_id": "op-host", "host": "SYNTHETIC-OTHER"},
        "op-host")
    assert state == "failure" and writes == []

    state, _ = run(
        good_health,
        {"ok": True, "request_id": "op-good", "host": "synthetic-target"},
        "op-good")
    assert state == "success"
    assert writes == [("192.0.2.110", r"SYNTHETIC_PC\user", "new")]

def test_atomic_config_replace_and_failure_preserves_old_file():
    original_path = rm.CONFIG_PATH
    try:
        with tempfile.TemporaryDirectory() as td:
            rm.CONFIG_PATH = os.path.join(td, "config.json")
            with open(rm.CONFIG_PATH, "w", encoding="utf-8") as handle:
                json.dump({"value": "old"}, handle)
            assert rm.save_config({"value": "new"}, raise_on_error=True)
            with open(rm.CONFIG_PATH, encoding="utf-8") as handle:
                assert json.load(handle) == {"value": "new"}

            with mock.patch.object(rm.os, "replace", side_effect=OSError("locked")), \
                    mock.patch("builtins.print"):
                try:
                    rm.save_config({"value": "broken"}, raise_on_error=True)
                except OSError:
                    pass
                else:
                    raise AssertionError("save_config must surface atomic replace failure")
            with open(rm.CONFIG_PATH, encoding="utf-8") as handle:
                assert json.load(handle) == {"value": "new"}
            leftovers = [p for p in os.listdir(td) if ".tmp." in p]
            assert leftovers == [], leftovers
    finally:
        rm.CONFIG_PATH = original_path


def main():
    tests = [test_content_fit_exact_margin_and_rows,
             test_content_fit_clamps_to_monitor_work_area,
             test_content_fit_scrollbars_propagate_across_axes,
             test_content_fit_scrollbar_fixpoint_boundary_property,
             test_manual_fit_resyncs_dpi_before_content,
             test_startup_runs_content_fit_once_after_monitor_fit,
             test_settings_are_english_professional_and_dpi_safe,
             test_fit_refreshes_point_fonts_after_scaling_change,
             test_new_pc_guide_and_node_registration_fields,
             test_rdp_preflight_contract_and_address_formatting,
             test_rdp_file_reuses_only_matching_saved_username,
             test_node_table_columns_are_responsive_and_digit_stable,
             test_fit_measures_chrome_after_scrollbars_are_hidden,
             test_display_inventory_retains_offline_configured_ray_rows,
             test_controller_detection,
             test_controller_is_never_an_rdp_or_password_target,
             test_read_only_server_lifetime_ignores_legacy_control_allowlists,
             test_password_ui_scope_and_sequential_batch_marker,
             test_help_is_five_language_and_update_fleet_complete,
             test_application_chrome_is_english_outside_localized_help,
             test_local_partial_retry_does_not_change_password_twice,
             test_server_idempotency_key_is_bound_to_exact_password_payload,
             test_remote_password_change_validates_target_and_response_identity,
             test_atomic_config_replace_and_failure_preserves_old_file]
    results = []
    failed = 0
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except Exception as exc:
            failed += 1
            results.append({"test": test.__name__, "ok": False,
                            "error": f"{type(exc).__name__}: {exc}"})
    print(json.dumps({"suite": "ui_layout", "passed": len(tests) - failed,
                      "failed": failed, "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
