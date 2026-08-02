from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ray_monitor
from ray_monitor import RayController, resolve_identity


class DriverOnlyNodeTests(unittest.TestCase):
    def base_config(self, cpus):
        return {
            "head_ip": "192.0.2.20",
            "head_port": 6379,
            "dashboard_port": 8265,
            "ray_exe": "auto",
            "this": {
                "role": "worker",
                "mode": "ray",
                "ip": "192.0.2.21",
                "num_cpus": cpus,
            },
            "nodes": [],
        }

    def test_zero_cpu_generates_driver_only_ray_argument(self):
        controller = RayController(self.base_config(0), lambda _message: None)
        self.assertEqual(controller._cpu_args(0), ["--num-cpus", "0"])

    def test_unknown_cpu_keeps_join_refusal(self):
        controller = RayController(
            self.base_config(None), lambda _message: None)
        result = controller._start_worker_locked()
        self.assertFalse(result.ok)
        self.assertIn("Could not determine CPU count", result.message)

    def test_schema_13_zero_auto_migrates_to_auto(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps({
                    "schema_version": 13,
                    "head_ip": "192.0.2.20",
                    "this": {
                        "role": "worker",
                        "mode": "ray",
                        "ip": "192.0.2.21",
                        "num_cpus": 0,
                    },
                    "nodes": [],
                }),
                encoding="utf-8")
            with (
                mock.patch.object(ray_monitor, "CONFIG_PATH", str(config_path)),
                mock.patch.object(ray_monitor, "logical_cpus", return_value=8),
            ):
                cfg = ray_monitor.load_config()
                role, ip, cpus = resolve_identity(cfg)

            self.assertEqual(cfg["schema_version"], 15)
            self.assertEqual(cfg["this"]["num_cpus"], "auto")
            self.assertEqual((role, ip, cpus), ("worker", "192.0.2.21", 8))


if __name__ == "__main__":
    unittest.main()
