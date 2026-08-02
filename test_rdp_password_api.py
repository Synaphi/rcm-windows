"""Loopback regression for retired legacy mutation HTTP surfaces."""

import http.client
import json

import temps_server


NOT_FOUND = b'{"error":"not_found","ok":false}'
CAPABILITIES = (
    "repair",
    "rdp_password_change_v1",
    "self_update_v1",
    "cluster_config_v1",
)


def _request(port, method, path, body=b"", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    result = (
        response.status,
        response.getheader("Content-Type"),
        response.read(),
    )
    conn.close()
    return result


def _server(counter):
    def touched(*_args, **_kwargs):
        counter["effects"] += 1
        return {"ok": True}

    server = temps_server.TempsServer(
        port=0,
        bind="127.0.0.1",
        repair_handler=touched,
        repair_status_provider=touched,
        health_provider=lambda: {
            **{name: True for name in CAPABILITIES},
            "local_identity": "synthetic",
        },
        repair_allowed_hosts={"127.0.0.1"},
        rdp_password_handler=touched,
        control_allowed_hosts={"127.0.0.1"},
        self_update_handler=touched,
        update_allowed_hosts={"127.0.0.1"},
        cluster_config_handler=touched,
        cluster_allowed_hosts={"127.0.0.1"},
    )
    server.start()
    assert server.wait_ready(), server.error
    return server, int(server._server.server_address[1])


def _stop(server):
    server.stop()
    server.join(timeout=3)
    assert not server.is_alive()


def test_health_forces_retired_capabilities_false_after_provider_merge():
    counter = {"effects": 0}
    server, port = _server(counter)
    try:
        status, content_type, body = _request(port, "GET", "/health?probe=1")
        assert status == 200
        assert content_type == "application/json; charset=utf-8"
        payload = json.loads(body)
        assert payload["local_identity"] == "synthetic"
        assert all(payload[name] is False for name in CAPABILITIES)
        assert counter["effects"] == 0
        for name in (
                "repair_handler", "repair_status_provider",
                "rdp_password_handler", "self_update_handler",
                "cluster_config_handler"):
            assert not hasattr(server._server, name)
    finally:
        _stop(server)


def test_every_post_is_exact_404_and_invokes_zero_handlers():
    counter = {"effects": 0}
    server, port = _server(counter)
    try:
        for path in (
                "/repair", "/rdp-password", "/self-update",
                "/cluster-config", "/metrics", "/unknown",
                "/repair?ignored=1", "/repair/"):
            status, content_type, body = _request(
                port, "POST", path, body=b'{"synthetic":"body"}',
                headers={"Content-Type": "application/json"})
            assert (status, content_type, body) == (
                404, "application/json; charset=utf-8", NOT_FOUND)
        assert counter["effects"] == 0
    finally:
        _stop(server)


def test_non_success_gets_and_other_methods_are_exact_error_only():
    counter = {"effects": 0}
    server, port = _server(counter)
    try:
        for method, path in (
                ("GET", "/"), ("GET", "/repair"), ("GET", "/temps/"),
                ("GET", "/health/"), ("PUT", "/repair"),
                ("PATCH", "/metrics"), ("DELETE", "/health"),
                ("OPTIONS", "/ping")):
            assert _request(port, method, path, b"x") == (
                404, "application/json; charset=utf-8", NOT_FOUND)
        assert counter["effects"] == 0
    finally:
        _stop(server)


def test_exact_success_get_set_and_query_routing():
    counter = {"effects": 0}
    server, port = _server(counter)
    try:
        for path in ("/temps", "/metrics", "/health", "/ping?ignored=1"):
            assert _request(port, "GET", path)[0] == 200
        assert counter["effects"] == 0
    finally:
        _stop(server)


def test_success_routes_reject_trailing_slashes():
    counter = {"effects": 0}
    server, port = _server(counter)
    try:
        for path in ("/temps/", "/metrics/", "/health/", "/ping/"):
            assert _request(port, "GET", path) == (
                404, "application/json; charset=utf-8", NOT_FOUND)
    finally:
        _stop(server)


def test_non_loopback_bind_values_are_rejected():
    for bind in ("0.0.0.0", "::1", "localhost", "192.0.2.10", ""):
        try:
            temps_server.TempsServer(port=0, bind=bind)
        except ValueError as exc:
            assert str(exc) == (
                "bind must be exact IPv4 loopback 127.0.0.1")
        else:
            raise AssertionError(f"bind unexpectedly accepted: {bind!r}")


def main():
    tests = [
        test_health_forces_retired_capabilities_false_after_provider_merge,
        test_every_post_is_exact_404_and_invokes_zero_handlers,
        test_non_success_gets_and_other_methods_are_exact_error_only,
        test_exact_success_get_set_and_query_routing,
        test_success_routes_reject_trailing_slashes,
        test_non_loopback_bind_values_are_rejected,
    ]
    results = []
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except Exception as exc:
            results.append({
                "test": test.__name__, "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
    failed = sum(not item["ok"] for item in results)
    print(json.dumps({
        "suite": "retired_http_mutations",
        "passed": len(results) - failed,
        "failed": failed,
        "results": results,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
