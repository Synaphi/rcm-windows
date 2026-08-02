import json
from unittest import mock

import ray_monitor
from src.rcm import legacy_compat


NODES = [{"name": "synthetic-head", "ip": "192.0.2.10", "role": "head", "num_cpus": 4},
         {"name": "synthetic-worker", "ip": "192.0.2.11", "role": "worker", "num_cpus": 4}]


class ForbiddenHttp:
    def get(self, *_args, **_kwargs):
        raise AssertionError("legacy remote GET forbidden")
    def post(self, *_args, **_kwargs):
        raise AssertionError("legacy remote POST forbidden")


def _orchestrator():
    return ray_monitor.ClusterReconfigurator({
        "head_ip": "192.0.2.10",
        "dashboard_port": 8265,
        "temp_port": 8866,
        "cluster_epoch": 7,
        "nodes": NODES,
    }, http=ForbiddenHttp())


def test_preflight_and_execute_return_exact_retirement_without_effects():
    orchestrator = _orchestrator()
    candidate = NODES[1]
    info = orchestrator.preflight(candidate)
    assert info["candidate_ready"] is False
    assert info["reason"] == "legacy_remote_retired"
    assert {
        item["reason"] for item in info["incompatible"]
    } == {"legacy_remote_retired"}
    with (
        mock.patch.object(
            ray_monitor, "write_cluster_manifest",
            side_effect=AssertionError("config write forbidden")) as write,
        mock.patch.object(
            ray_monitor.threading.Thread, "start",
            side_effect=AssertionError("thread forbidden")) as start,
    ):
        result = orchestrator.execute(candidate, preflight=info)
    assert result == ray_monitor.ActionResult(
        False, "legacy_remote_retired")
    write.assert_not_called()
    start.assert_not_called()


def test_direct_push_rollback_and_dashboard_helpers_are_effect_free():
    orchestrator = _orchestrator()
    assert orchestrator._push(NODES[0], {}) is False
    assert orchestrator._rollback({}, NODES) is False
    assert orchestrator._default_head_alive("192.0.2.10") is False
    assert orchestrator._default_verify("192.0.2.10") == {
        "alive_nodes": 0,
        "total_cpu": 0.0,
        "error": "legacy_remote_retired",
    }
    assert orchestrator._wait_for_head("192.0.2.10", timeout=0) is False


def test_inbound_cluster_shim_and_convergence_are_retired():
    app = object.__new__(ray_monitor.RayApp)
    payload = {"epoch": 8, "nodes": NODES}
    with (
        mock.patch.object(
            legacy_compat, "save_config",
            side_effect=AssertionError("save forbidden")) as save,
        mock.patch.object(
            legacy_compat.threading.Timer, "start",
            side_effect=AssertionError("timer forbidden")) as timer,
    ):
        result = app._handle_cluster_config(payload)
        assert app._schedule_cluster_convergence({}, {}) is None
        assert app._converge_to_cluster_config({}, {}) is None
        assert app._apply_cluster_config_runtime({}) is None
    assert result == {
        "_status": 410,
        "ok": False,
        "accepted": False,
        "reason": "legacy_remote_retired",
    }
    save.assert_not_called()
    timer.assert_not_called()


def test_execute_without_preflight_is_retired():
    assert _orchestrator().execute(NODES[1]) == ray_monitor.ActionResult(False, "legacy_remote_retired")


def test_execute_ignores_synthetic_success_preflight():
    result = _orchestrator().execute(NODES[1], preflight={"candidate_ready": True})
    assert result == ray_monitor.ActionResult(False, "legacy_remote_retired")


def test_cluster_config_rejects_arbitrary_payload_before_validation():
    app = object.__new__(ray_monitor.RayApp)
    assert app._handle_cluster_config({"not": "a manifest"})["reason"] == "legacy_remote_retired"


def test_schedule_cluster_convergence_is_effect_free():
    app = object.__new__(ray_monitor.RayApp)
    with mock.patch.object(legacy_compat.threading.Timer, "start",
                           side_effect=AssertionError("timer forbidden")) as start:
        assert app._schedule_cluster_convergence({}, {}) is None
    start.assert_not_called()


def test_converge_cluster_config_is_effect_free():
    app = object.__new__(ray_monitor.RayApp)
    assert app._converge_to_cluster_config({}, {}) is None


def test_apply_cluster_config_runtime_is_effect_free():
    app = object.__new__(ray_monitor.RayApp)
    app.cfg = {"sentinel": "unchanged"}
    assert app._apply_cluster_config_runtime({"sentinel": "new"}) is None
    assert app.cfg == {"sentinel": "unchanged"}


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(json.dumps({"suite": "cluster_reconfig_retirement",
                      "passed": len(tests), "failed": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
