"""Display-free regression tests for the non-blocking RDP preflight."""
import json
import socket
from unittest import mock

import ray_monitor as rm


class _Socket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_tcp_probe_classifies_and_closes():
    opened = _Socket()
    with mock.patch.object(rm.socket, "create_connection", return_value=opened) as call:
        assert rm.tcp_probe_state("192.0.2.11", 3390, 0.2) == "open"
    call.assert_called_once_with(("192.0.2.11", 3390), timeout=0.2)
    assert opened.closed

    for error, expected in (
            (socket.timeout(), "timeout"),
            (TimeoutError(), "timeout"),
            (ConnectionRefusedError(), "refused"),
            (OSError(10061, "refused"), "refused"),
            (OSError(10060, "timeout"), "timeout"),
            (OSError(12345, "other"), "error")):
        with mock.patch.object(rm.socket, "create_connection", side_effect=error):
            assert rm.tcp_probe_state("192.0.2.11", 3389, 0.2) == expected
    assert rm.tcp_probe_state("", 3389) == "error"


def test_remote_access_probes_only_selected_rdp_port():
    calls = []

    def probe(host, port, timeout):
        calls.append((host, port, timeout))
        return "refused"

    with mock.patch.object(rm, "tcp_probe_state", side_effect=probe):
        result = rm.probe_remote_access(
            "192.0.2.11", rdp_port=3390, rcm_port=8866, timeout=0.25)
    assert result == {
        "rdp": "refused",
        "rcm": "legacy_remote_retired",
    }
    assert calls == [("192.0.2.11", 3390, 0.25)]


def _preflight_app(selected):
    app = object.__new__(rm.RayApp)
    app._closing = False
    app._rdp_probe_generation = 7
    app._rdp_probe_running = True
    app._selected_node = mock.Mock(return_value=selected)
    app._update_rdp_button = mock.Mock()
    app._set_diag = mock.Mock()
    app._log = mock.Mock()
    app._launch_rdp = mock.Mock()
    app._rdp_port_for_node = mock.Mock(
        side_effect=lambda node: rm.normalized_rdp_port(node.rdp_port))
    return app


def _node(ip="192.0.2.11", registered=True):
    return rm.NodeView(
        ip=ip, hostname="SYNTHETIC_NODE_G", alive=True, cpu=16, cpu_used=0,
        gpu=0, mem_gb=0, is_head=False, name="SYNTHETIC_NODE_G",
        rdp_port=3389, registered=registered)


def test_stale_or_changed_selection_never_launches():
    node = _node()
    app = _preflight_app(node)
    app._finish_rdp_preflight(6, node, {"rdp": "open", "rcm": "open"})
    app._launch_rdp.assert_not_called()
    assert app._rdp_probe_running is True

    app = _preflight_app(_node("192.0.2.12"))
    app._finish_rdp_preflight(7, node, {"rdp": "open", "rcm": "open"})
    app._launch_rdp.assert_not_called()
    assert app._rdp_probe_running is False
    assert "target changed" in app._set_diag.call_args.args[1]


def test_open_rdp_launches_but_failed_probe_requires_consent():
    node = _node(registered=False)
    app = _preflight_app(node)
    app._finish_rdp_preflight(7, node, {"rdp": "open", "rcm": "timeout"})
    app._launch_rdp.assert_called_once_with(node)

    app = _preflight_app(node)
    with mock.patch.object(rm.messagebox, "askyesno", return_value=False) as ask:
        app._finish_rdp_preflight(
            7, node, {"rdp": "timeout", "rcm": "open"})
    app._launch_rdp.assert_not_called()
    prompt = ask.call_args.args[1]
    assert "Only the selected RDP port was probed" in prompt
    assert "legacy RCM remote health is retired" in prompt
    assert "8866 responds" not in prompt
    assert "not registered in this PC's Settings inventory" in prompt
    assert "Open Windows Remote Desktop anyway?" in prompt

    app = _preflight_app(node)
    with mock.patch.object(rm.messagebox, "askyesno", return_value=True):
        app._finish_rdp_preflight(
            7, node, {"rdp": "refused", "rcm": "open"})
    app._launch_rdp.assert_called_once_with(node)


def main():
    tests = [test_tcp_probe_classifies_and_closes,
             test_remote_access_probes_only_selected_rdp_port,
             test_stale_or_changed_selection_never_launches,
             test_open_rdp_launches_but_failed_probe_requires_consent]
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
    print(json.dumps({"suite": "rdp_preflight",
                      "passed": len(tests) - failed, "failed": failed,
                      "results": results}, ensure_ascii=False, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
