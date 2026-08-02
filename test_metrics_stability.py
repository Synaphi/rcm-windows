"""Regression tests for v1.5.34 [metriccache] metrics blanking.

These contracts pin the bug where one slow /metrics request cleared every
hardware field to "--" for several refresh cycles. They are pytest-free so the
release gate can run them anywhere the app can be built.
"""
import json
import os
import sys
import tempfile
import threading
import time
from unittest import mock

import ray_monitor as rm
import sensor_poller as sp
import temps_server as ts


def make_node():
    return rm.NodeView(
        ip="192.0.2.26",
        hostname="SYNTHETIC_NODE_E",
        alive=True,
        cpu=16.0,
        cpu_used=0.0,
        gpu=0.0,
        mem_gb=0.0,
        is_head=False,
        name="SYNTHETIC_NODE_E",
        is_this=True,
    )


def make_monitor():
    cfg = dict(rm.DEFAULT_CONFIG)
    cfg["metrics_timeout_sec"] = 3.0
    return rm.ClusterMonitor(cfg, lambda view: None)


def fill_metrics(node):
    node.temp_cpu_pkg = 55.0
    node.temp_cpu_max = 58.0
    node.temp_error = ""
    node.os_cpu_pct = 31.0
    node.ram_total_gb = 32.0
    node.ram_used_gb = 10.0
    node.ram_available_gb = 22.0
    node.ram_pct = 31.2
    node.disks = [{"name": "C:", "present": True, "pct": 41.0, "active": True}]
    node.disk_io_bps = 1234.0
    node.disk_active = True
    node.disk_error = ""
    node.net_down_bps = 1000.0
    node.net_up_bps = 200.0
    node.ping_ms = 3.0
    node.net_down_total_bytes = 100000.0
    node.net_up_total_bytes = 20000.0
    node.metrics_uptime_sec = 99.0
    node.metrics_ts = time.time()
    node.conn_label = "Wi:test"
    node.conn_type = "Wi"
    node.conn_name = "test"
    node.conn_category = "Private"
    node.net_error = ""
    node.metrics_error = ""


def test_metrics_payload_uses_cache():
    original_temp_payload = ts.temp_payload
    original_system_metrics = ts._system_metrics
    try:
        calls = {"system": 0}

        def temp_payload():
            return {"cpu_pkg": 55.0, "error": "", "ts": 123.0}

        def system_metrics():
            calls["system"] += 1
            return {"os_cpu_pct": 99.0}

        ts.temp_payload = temp_payload
        ts._system_metrics = system_metrics
        with ts._METRICS_LOCK:
            ts._METRICS_CACHE = {
                "os_cpu_pct": 12.5,
                "ram_total_gb": 32.0,
                "disks": [{"name": "C:", "present": True, "pct": 42.0}],
                "metrics_ts": time.time() - 0.5,
            }
        payload = ts.metrics_payload()
        assert payload["cpu_pkg"] == 55.0
        assert payload["os_cpu_pct"] == 12.5
        assert payload["disks"][0]["pct"] == 42.0
        assert 0.0 <= payload["metrics_age_sec"] < 5.0
        assert calls["system"] == 0, "metrics_payload must not collect synchronously"

        payload["disks"][0]["pct"] = 7.0
        cached = ts.cached_system_metrics()
        assert cached["disks"][0]["pct"] == 42.0, "cache must copy nested disks"
    finally:
        ts.temp_payload = original_temp_payload
        ts._system_metrics = original_system_metrics


def test_localnetwork_keeps_wifi_or_ethernet_identity():
    # Windows NCSI can say LocalNetwork even while LEGACY_NODE's adapter is the
    # useful active connection. The UI should identify the adapter instead of
    # collapsing every such profile to the unhelpful word "Local".
    assert ts._compact_conn_label("Wi", "Home-5G", "Priv", "Local") == \
        "Wi:Home-5G"
    assert ts._compact_conn_label("Eth", "Network", "Priv", "Local") == \
        "Eth:Priv"
    assert ts._compact_conn_label("Local", "Unknown", "Priv", "Local") == \
        "Local"
    assert ts._compact_conn_label("Wi", "Home-5G", "Priv", "Offline") == \
        "Offline"


def test_storage_temperature_selects_only_physical_ssd_containing_c():
    # v1.07.16c [retrofit]: pythonnet 3.x wraps ``Computer.Hardware`` items as
    # the declared interface type (IHardware), so concrete members such as
    # ``StorageDevice.Storage`` and ``Partition.DriveLetter`` raise
    # AttributeError on direct access and are reachable only through
    # runtime-type reflection (verified live on SYNTHETIC_NODE_D, two NVMe SSDs).
    # These fakes emulate that boundary; the pre-retrofit direct-attribute
    # implementation fails against them.
    class DotNetProperty:
        def __init__(self, value):
            self._value = value

        def GetValue(self, _obj):
            return self._value

    class DotNetType:
        def __init__(self, members):
            self._members = members

        def GetProperty(self, name):
            if name in self._members:
                return DotNetProperty(self._members[name])
            return None

    class Partition:
        def __init__(self, drive):
            self._drive = drive

        def __getattr__(self, name):
            if name == "GetType":
                return lambda: DotNetType({"DriveLetter": self._drive})
            raise AttributeError(
                f"'IPartition' object has no attribute {name!r}")

    class Storage:
        def __init__(self, drives):
            self.Partitions = [Partition(drive) for drive in drives]

    class Sensor:
        SensorType = "Temperature"

        def __init__(self, name, value):
            self.Name = name
            self.Value = value

    class Hardware:
        HardwareType = "Storage"

        def __init__(self, drives, sensors):
            self._storage = Storage(drives)
            self.Sensors = sensors

        def Update(self):
            pass

        def GetType(self):
            return DotNetType({"Storage": self._storage})

        @property
        def Storage(self):
            raise AttributeError("'IHardware' object has no attribute 'Storage'")

    c_ssd = Hardware(
        ["C:", "F:"],
        [Sensor("Critical Temperature", 85.0),
         Sensor("Temperature #1", 51.0),
         Sensor("Composite Temperature", 44.0)],
    )
    second_ssd = Hardware(["D:"], [Sensor("Composite Temperature", 61.0)])
    poller = sp.LHMSensorPoller()
    poller._computer = type("Computer", (), {"Hardware": [c_ssd, second_ssd]})()
    poller._opened = True

    reading = poller.read()
    assert reading.storage_temps_c == {"C:": 44.0}
    assert reading.to_dict()["storage_temps_c"] == {"C:": 44.0}


def test_disk_metrics_attaches_fresh_c_ssd_temperature_only():
    original_last = ts.sensor_poller.last
    original_disk_usage = ts.psutil.disk_usage
    original_disk_activity = ts._disk_activity
    reading = sp.TempReading(
        storage_temps_c={"C:": 43.6, "D:": 58.0}, ts=time.time())
    usage = type("Usage", (), {
        "total": 1024 ** 3, "used": 512 ** 3,
        "free": 512 ** 3, "percent": 50.0,
    })()
    try:
        ts.sensor_poller.last = lambda: reading
        ts.psutil.disk_usage = lambda root: usage
        ts._disk_activity = lambda: (0.0, False)
        disks = ts._disk_metrics()["disks"]
        by_drive = {item["drive"]: item for item in disks}
        assert by_drive["C:"]["temperature_c"] == 43.6
        assert by_drive["G:"]["temperature_c"] is None
    finally:
        ts.sensor_poller.last = original_last
        ts.psutil.disk_usage = original_disk_usage
        ts._disk_activity = original_disk_activity


def test_node_disk_text_places_ssd_temperature_to_capacity_right():
    app = object.__new__(rm.RayApp)
    node = make_node()
    node.disks = [{
        "drive": "C:", "present": True, "pct": 50.0,
        "active": False, "temperature_c": 44.0,
    }]
    text = app._node_disk_text(node)
    assert text.endswith(" 44°")
    assert len(text) <= rm.NODE_DISK_COL_WIDTH


def test_background_metrics_lifecycle_is_nonblocking_and_generation_safe():
    original_system_metrics = ts._system_metrics
    ts.stop_background_metrics()
    with ts._METRICS_LOCK:
        ts._METRICS_CACHE = {}
    old_entered = threading.Event()
    old_release = threading.Event()
    new_entered = threading.Event()
    phase = {"value": "old"}

    def staged_metrics():
        if phase["value"] == "old":
            old_entered.set()
            old_release.wait(timeout=3.0)
            return {"os_cpu_pct": 11.0, "disks": [], "metrics_ts": time.time()}
        new_entered.set()
        return {"os_cpu_pct": 77.0, "disks": [], "metrics_ts": time.time()}

    try:
        ts._system_metrics = staged_metrics
        start = time.perf_counter()
        ts.start_background_metrics(interval_sec=10.0)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert elapsed_ms < 200.0, f"start blocked for {elapsed_ms:.1f}ms"
        assert old_entered.wait(timeout=1.0), "old poller did not start"

        stopper = threading.Thread(target=ts.stop_background_metrics)
        stopper.start()
        time.sleep(0.05)
        phase["value"] = "new"
        ts.start_background_metrics(interval_sec=10.0)
        assert new_entered.wait(timeout=1.0), "new poller did not start"
        old_release.set()
        stopper.join(timeout=7.0)
        assert not stopper.is_alive(), "stop_background_metrics did not finish"
        time.sleep(0.05)
        cached = ts.cached_system_metrics()
        assert cached.get("os_cpu_pct") == 77.0, cached
    finally:
        old_release.set()
        ts.stop_background_metrics()
        ts._system_metrics = original_system_metrics
        with ts._METRICS_LOCK:
            ts._METRICS_CACHE = {}


def test_single_timeout_keeps_last_good_metrics():
    mon = make_monitor()
    node = make_node()
    fill_metrics(node)
    mon._remember_metric_cache(node)

    mon._note_metric_soft_miss(node, "timeout")
    assert node.os_cpu_pct == 31.0
    assert node.ram_used_gb == 10.0
    assert node.disks and node.disks[0]["pct"] == 41.0
    assert node.net_down_bps == 1000.0
    assert node.ping_ms is None
    assert node.conn_label == "Wi:test"
    assert node.metrics_error == "timeout (stale)"
    with mon._metrics_lock:
        assert node.ip in mon._metrics_cache
        assert node.ip not in mon._metrics_skip_until


def test_second_timeout_blanks_and_backs_off():
    mon = make_monitor()
    node = make_node()
    fill_metrics(node)
    mon._remember_metric_cache(node)
    before = time.monotonic()

    mon._note_metric_soft_miss(node, "timeout")
    mon._note_metric_soft_miss(node, "timeout")
    assert node.os_cpu_pct is None
    assert node.ram_used_gb is None
    assert node.disks == []
    assert node.metrics_error == "timeout"
    with mon._metrics_lock:
        assert node.ip not in mon._metrics_cache
        assert mon._metrics_skip_until[node.ip] >= before + 4.5


def test_fetch_timeout_path_keeps_then_clears_cached_metrics():
    mon = make_monitor()
    cached = make_node()
    fill_metrics(cached)
    mon._remember_metric_cache(cached)
    node = make_node()
    urls = []
    original_get = rm.requests.get

    def timeout_get(url, timeout):
        urls.append((url, timeout))
        raise rm.requests.Timeout("simulated timeout")

    try:
        rm.requests.get = timeout_get
        mon._enrich_metrics([node])
        assert urls and urls[-1][0] == "http://127.0.0.1:8866/metrics"
        assert urls[-1][1] == 3.0
        assert node.os_cpu_pct == 31.0
        assert node.ram_used_gb == 10.0
        assert node.disks and node.disks[0]["pct"] == 41.0
        assert node.net_down_bps == 1000.0
        assert node.ping_ms is None
        assert node.conn_label == "Wi:test"
        assert node.metrics_error == "timeout (stale)"
        with mon._metrics_lock:
            assert node.ip in mon._metrics_cache
            assert node.ip not in mon._metrics_skip_until

        before = time.monotonic()
        mon._enrich_metrics([node])
        assert node.os_cpu_pct is None
        assert node.ram_used_gb is None
        assert node.disks == []
        assert node.net_down_bps is None
        assert node.conn_label == ""
        assert node.metrics_error == "timeout"
        with mon._metrics_lock:
            assert node.ip not in mon._metrics_cache
            assert mon._metrics_skip_until[node.ip] >= before + 4.5
    finally:
        rm.requests.get = original_get


def test_reported_metrics_age_clears_system_values_but_keeps_temp_and_ping():
    mon = make_monitor()
    node = make_node()
    original_get = rm.requests.get

    class FakeElapsed:
        def total_seconds(self):
            return 0.004

    class FakeResponse:
        ok = True
        status_code = 200
        elapsed = FakeElapsed()

        def json(self):
            return {
                "cpu_pkg": 55.0,
                "cpu_max": 58.0,
                "gpu": None,
                "error": "",
                "os_cpu_pct": 99.0,
                "ram_total_gb": 32.0,
                "ram_used_gb": 31.0,
                "ram_available_gb": 1.0,
                "ram_pct": 96.0,
                "disks": [{"name": "C:", "present": True, "pct": 91.0}],
                "disk_io_bps": 1000.0,
                "disk_active": True,
                "disk_error": "",
                "net_down_bps": 1000.0,
                "net_up_bps": 200.0,
                "net_down_total_bytes": 123.0,
                "net_up_total_bytes": 45.0,
                "metrics_uptime_sec": 120.0,
                # The producer reports age using its own clock. Its absolute
                # timestamp may be skewed and must not be subtracted locally.
                "metrics_ts": time.time() + 8.0,
                "metrics_age_sec": 30.0,
                "conn_label": "Wi:test",
                "conn_type": "Wi",
                "conn_name": "test",
                "conn_category": "Private",
                "net_error": "",
                "metrics_error": "",
            }

    try:
        rm.requests.get = lambda url, timeout: FakeResponse()
        mon._fetch_one_metrics(node, 8866, 3.0)
        assert node.temp_cpu_pkg == 55.0
        assert node.ping_ms == 4.0
        assert node.os_cpu_pct is None
        assert node.ram_used_gb is None
        assert node.disks == []
        assert node.net_down_bps is None
        assert node.conn_label == ""
        assert node.metrics_ts is not None
        assert node.metrics_error.startswith("metrics stale ")
    finally:
        rm.requests.get = original_get


def test_remote_metrics_retire_without_request_or_fallback():
    mon = make_monitor()
    node = make_node()
    node.is_this = False
    fill_metrics(node)
    with mock.patch.object(
            rm.requests, "get",
            side_effect=AssertionError("remote metrics request forbidden")) as get:
        mon._fetch_one_metrics(node, 8866, 3.0)
    get.assert_not_called()
    assert node.os_cpu_pct is None
    assert node.ram_used_gb is None
    assert node.disks == []
    assert node.temp_error == "legacy_remote_retired"
    assert node.metrics_error == "legacy_remote_retired"
    return
    original_get = rm.requests.get
    payload = {
        "cpu_pkg": 55.0,
        "cpu_max": 58.0,
        "gpu": None,
        "error": "",
        "os_cpu_pct": 42.0,
        "ram_total_gb": 32.0,
        "ram_used_gb": 12.0,
        "ram_available_gb": 20.0,
        "ram_pct": 37.5,
        "disks": [{"name": "C:", "present": True, "pct": 41.0}],
        "disk_io_bps": 1000.0,
        "disk_active": True,
        "disk_error": "",
        "net_down_bps": 1000.0,
        "net_up_bps": 200.0,
        "net_down_total_bytes": 123.0,
        "net_up_total_bytes": 45.0,
        "metrics_uptime_sec": 120.0,
        # Reproduce the consumer SYNTHETIC_NODE_A clock being about eight seconds ahead
        # of the remote SYNTHETIC_NODE_E producer.
        "metrics_ts": time.time() - 8.1,
        "conn_label": "Wi:test",
        "conn_type": "Wi",
        "conn_name": "test",
        "conn_category": "Private",
        "net_error": "",
        "metrics_error": "",
    }

    class FakeElapsed:
        def total_seconds(self):
            return 0.004

    class FakeResponse:
        ok = True
        status_code = 200
        elapsed = FakeElapsed()

        def json(self):
            return dict(payload)

    try:
        rm.requests.get = lambda url, timeout: FakeResponse()
        mon._fetch_one_metrics(node, 8866, 3.0)
        assert node.os_cpu_pct == 42.0
        assert node.ram_used_gb == 12.0
        assert node.metrics_error == ""

        # A legacy peer has no metrics_age_sec, but an advancing producer
        # timestamp proves the cache is fresh regardless of wall-clock skew.
        with mon._metrics_lock:
            mon._metrics_remote_progress[node.ip] = (
                payload["metrics_ts"], time.monotonic() - 30.0)
        payload["metrics_ts"] += 1.5
        mon._fetch_one_metrics(node, 8866, 3.0)
        assert node.os_cpu_pct == 42.0
        assert node.ram_used_gb == 12.0
        assert node.metrics_error == ""
        assert node.metrics_age_sec == 0.0
    finally:
        rm.requests.get = original_get


def test_local_metrics_uses_loopback_and_timeout_3s():
    src = open(rm.__file__, encoding="utf-8").read()
    assert '"metrics_timeout_sec": 3.0' in src
    assert 'host = "127.0.0.1"' in src
    assert 'if not getattr(node, "is_this", False):' in src
    assert "requests.get(f\"http://{host}:{port}/metrics\"" in src
    assert "requests.get(f\"http://{node.ip}:{port}/metrics\"" not in src


def test_config_migrates_metriccache_defaults():
    original_config_path = rm.CONFIG_PATH
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": 10,
                "temp_port": 18871,
                "metrics_timeout_sec": 1.5,
            }, f)
        try:
            rm.CONFIG_PATH = path
            cfg = rm.load_config()
            assert cfg["schema_version"] == rm.DEFAULT_CONFIG["schema_version"]
            assert cfg["temp_port"] == 8866
            assert cfg["metrics_timeout_sec"] == 3.0
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["schema_version"] == rm.DEFAULT_CONFIG["schema_version"]
            assert saved["temp_port"] == 8866
            assert saved["metrics_timeout_sec"] == 3.0
        finally:
            rm.CONFIG_PATH = original_config_path


def test_test_temp_port_override_does_not_persist():
    original_config_path = rm.CONFIG_PATH
    old_skip = os.environ.get("RCM_SKIP_UAC_FOR_TESTS")
    old_port = os.environ.get("RCM_TEST_TEMP_PORT")
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "config.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": 11,
                "temp_port": 8866,
                "metrics_timeout_sec": 3.0,
            }, f)
        try:
            rm.CONFIG_PATH = path
            os.environ["RCM_SKIP_UAC_FOR_TESTS"] = "1"
            os.environ["RCM_TEST_TEMP_PORT"] = "18872"
            cfg = rm.load_config()
            assert cfg["temp_port"] == 18872
            rm.save_config(cfg)
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["temp_port"] == 8866
            assert "_persist_temp_port" not in saved
        finally:
            rm.CONFIG_PATH = original_config_path
            if old_skip is None:
                os.environ.pop("RCM_SKIP_UAC_FOR_TESTS", None)
            else:
                os.environ["RCM_SKIP_UAC_FOR_TESTS"] = old_skip
            if old_port is None:
                os.environ.pop("RCM_TEST_TEMP_PORT", None)
            else:
                os.environ["RCM_TEST_TEMP_PORT"] = old_port


def main():
    tests = [
        test_metrics_payload_uses_cache,
        test_localnetwork_keeps_wifi_or_ethernet_identity,
        test_storage_temperature_selects_only_physical_ssd_containing_c,
        test_disk_metrics_attaches_fresh_c_ssd_temperature_only,
        test_node_disk_text_places_ssd_temperature_to_capacity_right,
        test_background_metrics_lifecycle_is_nonblocking_and_generation_safe,
        test_single_timeout_keeps_last_good_metrics,
        test_second_timeout_blanks_and_backs_off,
        test_fetch_timeout_path_keeps_then_clears_cached_metrics,
        test_reported_metrics_age_clears_system_values_but_keeps_temp_and_ping,
        test_remote_metrics_retire_without_request_or_fallback,
        test_local_metrics_uses_loopback_and_timeout_3s,
        test_config_migrates_metriccache_defaults,
        test_test_temp_port_override_does_not_persist,
    ]
    results, failed = [], 0
    for test in tests:
        try:
            test()
            results.append({"test": test.__name__, "ok": True})
        except AssertionError as exc:
            failed += 1
            results.append({"test": test.__name__, "ok": False, "error": str(exc)})
    print(json.dumps({
        "suite": "metrics_stability",
        "version": rm.APP_VERSION,
        "passed": len(tests) - failed,
        "failed": failed,
        "results": results,
    }, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
