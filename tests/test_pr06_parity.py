from __future__ import annotations

import json
from pathlib import Path
import unittest

from rcm.ray import RayCommandBuilder, RayMode, RayStartSpec
from rcm.rdp import RdpRequest, RdpService


FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "characterization_contract.json"
)


class _UnusedCredentials:
    def contains(self, reference: object) -> bool:
        raise AssertionError("prompt-path planning must not query credentials")

    def resolve(self, reference: object) -> object:
        raise AssertionError("prompt-path planning must not resolve credentials")


class _UnusedLauncher:
    def capability(self) -> object:
        raise AssertionError("planning must not query host capability")

    def launch(self, plan: object) -> object:
        raise AssertionError("planning must not launch a process")

    def cleanup(self, receipt: object) -> None:
        raise AssertionError("planning must not remove an artifact")


def _contracts() -> dict[str, object]:
    document = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    return document["contracts"]


class FrozenCharacterizationParityTests(unittest.TestCase):
    def test_rdp_plan_matches_frozen_native_file_contract(self) -> None:
        frozen = _contracts()["rdp"]
        service = RdpService(
            credentials=_UnusedCredentials(),
            launcher=_UnusedLauncher(),
        )
        request = RdpRequest(
            "192.0.2.44",
            r"SYNTHETIC\operator",
            port=3390,
        )

        plan = service.plan(request)

        self.assertEqual(frozen["file_name"], plan.file_name)
        self.assertEqual(frozen["ipv4_target"], plan.target)
        expected_lines = list(frozen["file_lines"])
        expected_lines.insert(2, "keyboardhook:i:0")
        self.assertEqual(
            expected_lines,
            plan.file_bytes.decode("utf-16").splitlines(),
        )
        self.assertEqual(
            frozen["launch_args"],
            ["mstsc.exe", plan.file_name],
        )
        self.assertEqual(
            frozen["ipv6_target"],
            RdpRequest(
                "2001:db8::44",
                r"SYNTHETIC\operator",
                port=3390,
            ).target,
        )

    def test_ray_head_and_worker_argv_match_frozen_contract(self) -> None:
        frozen = _contracts()["ray_commands"]
        builder = RayCommandBuilder()
        head = builder.start(
            RayStartSpec(
                "ray.exe",
                RayMode.HEAD,
                node_ip_address="192.0.2.10",
                port=6379,
                dashboard_host="0.0.0.0",
                num_cpus=8,
            )
        )
        worker = builder.start(
            RayStartSpec(
                "ray.exe",
                RayMode.WORKER,
                address="192.0.2.10:6379",
                node_ip_address="192.0.2.20",
                num_cpus=4,
                temp_dir="<SANDBOX>/Temp/ray",
                node_manager_port=6380,
                object_manager_port=6381,
                runtime_env_agent_port=6382,
                dashboard_agent_grpc_port=6383,
                dashboard_agent_listen_port=6384,
                metrics_export_port=6385,
                min_worker_port=10002,
                max_worker_port=10100,
                node_name="SYNTHETIC_WORKER",
                block=True,
            )
        )

        self.assertEqual(
            frozen["start_head"]["calls"][1]["args"],
            list(head.arguments[1:]),
        )
        self.assertEqual(
            frozen["join_worker"]["popen_args"],
            list(worker.arguments),
        )


if __name__ == "__main__":
    unittest.main()
