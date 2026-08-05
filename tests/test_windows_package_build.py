from __future__ import annotations

from contextlib import nullcontext
import inspect
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import build_windows_package as package_build
from scripts import verify_package_candidate as candidate_verify


def _configuration_checks_fixture() -> dict[str, object]:
    return {
        deployment: {
            "deployment": deployment,
            "create_exit_code": 0,
            "reload_exit_code": 0,
            "generation": 1,
            "config_size": 512,
            "config_sha256": marker * 64,
            "maximum_network_connections": 0,
            "maximum_network_listeners": 0,
            "maximum_descendants": 1,
            "process_residue": 0,
            "temporary_artifact_residue": 0,
        }
        for deployment, marker in (
            ("installed", "a"),
            ("portable", "b"),
        )
    }


class WindowsPackageBuildTests(unittest.TestCase):
    def test_output_and_inputs_must_be_explicitly_external(self) -> None:
        root = package_build.repository_root()
        with self.assertRaisesRegex(
            package_build.BuildInputError,
            "outside the repository",
        ):
            package_build.validate_external_path(
                root / "dist",
                root=root,
                label="output root",
                must_exist=False,
            )
        with self.assertRaisesRegex(
            package_build.BuildInputError,
            "absolute",
        ):
            package_build.validate_external_path(
                Path("relative"),
                root=root,
                label="wheelhouse",
                must_exist=True,
            )

    def test_pyinstaller_command_has_exact_hidden_import_and_data_closure(
        self,
    ) -> None:
        root = package_build.repository_root()
        manifest = json.loads(
            (root / "packaging" / "vendor-data.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            staged = Path(temporary) / "staged"
            command = package_build.pyinstaller_command(
                python=Path(temporary) / "python.exe",
                root=root,
                output=output,
                offline_guard=Path(temporary) / "offline-guard",
                version_file=Path(temporary) / "version-info.txt",
                staged_vendor=staged,
                vendor_records=manifest["files"],
            )
        hidden = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--hidden-import"
        ]
        data = [
            command[index + 1]
            for index, item in enumerate(command)
            if item == "--add-data"
        ]
        self.assertEqual(list(package_build.HIDDEN_IMPORTS), hidden)
        self.assertIn("--windowed", command)
        self.assertNotIn("--console", command)
        self.assertIn("--version-file", command)
        self.assertEqual(13, len(data))
        self.assertTrue(
            any(item.endswith("vendor-data.json;build-metadata") for item in data)
        )
        self.assertTrue(
            any(item.endswith("THIRD_PARTY_NOTICES.md;.") for item in data)
        )
        self.assertTrue(
            any(item.endswith("resources\\help.json;rcm/resources") for item in data)
            or any(item.endswith("resources/help.json;rcm/resources") for item in data)
        )
        self.assertEqual(
            str(root / "packaging" / "entrypoint.py"),
            command[-1],
        )

    def test_package_script_has_no_downloader_or_shell_execution(self) -> None:
        source = Path(package_build.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "requests.",
            "urllib.",
            "urlopen(",
            "Invoke-WebRequest",
            "shell=True",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_build_environment_drops_python_and_pip_injection_variables(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = package_build._minimal_environment(
                source_date_epoch=1,
                cache_root=Path(temporary),
                offline_guard_root=Path(temporary) / "offline-guard",
            )
        for forbidden in (
            "PYTHONPATH",
            "PYTHONHOME",
            "VIRTUAL_ENV",
        ):
            self.assertNotIn(forbidden, environment)
        self.assertEqual("1", environment["PIP_NO_INDEX"])
        self.assertEqual("1", environment["PYTHONNOUSERSITE"])
        self.assertEqual("deny", environment["RCM_BUILD_NETWORK_POLICY"])
        self.assertEqual(
            str(Path(temporary) / "offline-guard"),
            environment["RCM_OFFLINE_GUARD_ROOT"],
        )

    def test_offline_guard_covers_udp_reflection_and_isolated_children(
        self,
    ) -> None:
        source = Path(package_build.__file__).read_text(encoding="utf-8")
        for required in (
            '"bind"',
            '"sendto"',
            '"sendmsg"',
            '"socketpair"',
            "_guarded_popen_type",
            "_guarded_create_process",
            '"execve"',
            '"spawnv"',
            '"startfile"',
            '"system"',
            "sitecustomize.py",
            "RCM_OFFLINE_GUARD_ROOT",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "guard"
            digest = package_build._write_offline_guard(destination)
            data = (destination / "sitecustomize.py").read_bytes()
        self.assertEqual(
            package_build.hashlib.sha256(data).hexdigest(),
            digest,
        )
        self.assertIn(b"_install_offline_guards", data)
        with tempfile.TemporaryDirectory() as temporary:
            version_file = Path(temporary) / "version-info.txt"
            version_digest = package_build._write_windows_version_resource(
                version_file
            )
            version_data = version_file.read_bytes()
        self.assertEqual(
            package_build.hashlib.sha256(version_data).hexdigest(),
            version_digest,
        )
        self.assertIn(b"filevers=(2, 8, 5, 1)", version_data)
        self.assertIn(
            b"FileVersion', '2.' + '8.' + '5.' + '1'",
            version_data,
        )
        self.assertIn(
            b"OriginalFilename', 'RCM-2.08.05a-windows-x64.exe'",
            version_data,
        )
        self.assertIn(b"ProductVersion', '2.08.05a'", version_data)

        verifier_source = inspect.getsource(candidate_verify._main_window_state)
        self.assertIn("IsWindow", verifier_source)
        self.assertGreaterEqual(verifier_source.count("if not is_window(hwnd)"), 2)

    def test_offline_child_guard_remains_subclass_compatible(self) -> None:
        guarded = package_build._guarded_popen_type(
            allow_pyinstaller_child=False
        )

        class CompatibleChild(guarded):
            pass

        self.assertTrue(
            issubclass(CompatibleChild, package_build._ORIGINAL_POPEN)
        )
        with self.assertRaisesRegex(
            package_build.OfflineNetworkError,
            "child process creation",
        ):
            guarded(["forbidden-child.exe"])
        with self.assertRaisesRegex(
            package_build.OfflineNetworkError,
            "child process creation",
        ):
            package_build._guarded_create_process()

    def test_pyinstaller_module_table_must_include_config_foundation(
        self,
    ) -> None:
        self.assertEqual(
            package_build.REQUIRED_FROZEN_MODULES,
            tuple(candidate_verify.EXPECTED_REQUIRED_MODULES),
        )
        self.assertIn(
            "src.rcm.legacy_compat",
            package_build.HIDDEN_IMPORTS,
        )
        self.assertIn(
            "src.rcm.legacy_compat",
            package_build.REQUIRED_FROZEN_MODULES,
        )
        self.assertNotIn(
            "rcm.legacy_compat",
            package_build.REQUIRED_FROZEN_MODULES,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            toc = (
                output
                / "work"
                / "RayClusterManager-PR07"
                / "PYZ-00.toc"
            )
            toc.parent.mkdir(parents=True)
            records = [
                (name, f"C:/synthetic/{name}.py", "PYMODULE")
                for name in package_build.REQUIRED_FROZEN_MODULES
            ]
            toc.write_text(repr(("synthetic.pyz", records)), encoding="utf-8")
            self.assertEqual(
                tuple(sorted(package_build.REQUIRED_FROZEN_MODULES)),
                package_build._frozen_modules(output),
            )
            toc.write_text(
                repr(("synthetic.pyz", records[:-1])),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                package_build.BuildInputError,
                "omitted required",
            ):
                package_build._frozen_modules(output)

    def test_candidate_connection_probe_supports_locked_psutil_api(self) -> None:
        class AccessDenied(Exception):
            pass

        class NoSuchProcess(Exception):
            pass

        class ZombieProcess(Exception):
            pass

        class LockedPsutilProcess:
            def connections(self, *, kind: str) -> list[object]:
                self.kind = kind
                return [
                    SimpleNamespace(status="ESTABLISHED"),
                    SimpleNamespace(status="LISTEN"),
                ]

        process = LockedPsutilProcess()
        module = SimpleNamespace(
            AccessDenied=AccessDenied,
            NoSuchProcess=NoSuchProcess,
            ZombieProcess=ZombieProcess,
            CONN_LISTEN="LISTEN",
        )
        self.assertEqual(
            (2, 1),
            candidate_verify._network_counts([process], module),
        )
        self.assertEqual("inet", process.kind)
        process.connections = mock.Mock(side_effect=AccessDenied())
        with self.assertRaisesRegex(
            candidate_verify.CandidateError,
            "denied",
        ):
            candidate_verify._network_counts([process], module)
        process.connections = mock.Mock(side_effect=NoSuchProcess())
        self.assertEqual(
            (0, 0),
            candidate_verify._network_counts([process], module),
        )

    def test_candidate_verifier_import_is_standard_library_only(self) -> None:
        source = Path(candidate_verify.__file__).read_text(encoding="utf-8")
        self.assertNotIn("\nimport psutil", source)
        self.assertIn('importlib.import_module("psutil")', source)

    def test_candidate_lifecycle_plan_and_window_states_are_exact(self) -> None:
        self.assertEqual(
            {
                "visible-quit": 50,
                "close-show-quit": 25,
                "minimized-show-quit": 25,
            },
            candidate_verify.SCENARIO_COUNTS,
        )
        self.assertEqual(100, candidate_verify.RUN_COUNT)
        passing = {
            "visible-quit": ["ABSENT", "HIDDEN", "VISIBLE", "VISIBLE"],
            "close-show-quit": [
                "ABSENT",
                "HIDDEN",
                "VISIBLE",
                "HIDDEN",
                "VISIBLE",
            ],
            "minimized-show-quit": [
                "ABSENT",
                "HIDDEN",
                "MINIMIZED",
                "VISIBLE",
            ],
        }
        for scenario, observations in passing.items():
            with self.subTest(scenario=scenario):
                self.assertTrue(
                    candidate_verify._window_sequence_passes(
                        scenario,
                        observations,
                    )
                )
        for scenario, observations in (
            ("visible-quit", ["ABSENT"]),
            ("visible-quit", ["VISIBLE", "MINIMIZED"]),
            ("close-show-quit", ["VISIBLE", "ABSENT", "VISIBLE"]),
            (
                "close-show-quit",
                ["VISIBLE", "MINIMIZED", "VISIBLE", "HIDDEN", "VISIBLE"],
            ),
            (
                "close-show-quit",
                ["VISIBLE", "HIDDEN", "VISIBLE", "HIDDEN", "VISIBLE"],
            ),
            ("minimized-show-quit", ["HIDDEN", "VISIBLE"]),
            ("minimized-show-quit", ["MINIMIZED", "HIDDEN", "VISIBLE"]),
            ("minimized-show-quit", ["VISIBLE", "MINIMIZED", "VISIBLE"]),
            ("unreviewed", ["VISIBLE"]),
        ):
            with self.subTest(scenario=scenario, negative=True):
                self.assertFalse(
                    candidate_verify._window_sequence_passes(
                        scenario,
                        observations,
                    )
                )

    def test_candidate_main_window_identity_and_states_are_narrow(self) -> None:
        records = [
            (100, 7, "Ray Cluster Manager", "TkTopLevel", True, False),
            (101, 7, "Ray Cluster Manager Help", "TkTopLevel", True, False),
            (102, 8, "Ray Cluster Manager", "TkTopLevel", True, False),
        ]
        self.assertEqual(
            "VISIBLE",
            candidate_verify._classify_main_windows(records, {7}),
        )
        records[0] = (*records[0][:4], False, False)
        self.assertEqual(
            "HIDDEN",
            candidate_verify._classify_main_windows(records, {7}),
        )
        records[0] = (*records[0][:4], True, True)
        self.assertEqual(
            "MINIMIZED",
            candidate_verify._classify_main_windows(records, {7}),
        )
        self.assertEqual(
            "ABSENT",
            candidate_verify._classify_main_windows(records, {9}),
        )

    def test_not_built_candidate_cannot_be_executed_by_verifier(self) -> None:
        root = candidate_verify.repository_root()
        tracked = json.loads(
            (root / "packaging" / "bundle-data.json").read_text("utf-8")
        )
        candidate = tracked["candidate"]
        candidate.update({
            "state": "not_built",
            "file": None,
            "size": None,
            "sha256": None,
            "public_source_snapshot_sha256": None,
            "package_manifest_sha256": None,
            "blockers": ["candidate_not_built"],
        })
        with (
            mock.patch.object(
                candidate_verify, "_read_json", return_value=tracked),
            self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "not executable",
            ),
        ):
            candidate_verify._load_contract(root)

    def test_candidate_contract_binds_package_root_and_allows_preview_freeze(
        self,
    ) -> None:
        root = candidate_verify.repository_root()
        tracked = json.loads(
            (root / "packaging" / "bundle-data.json").read_text(
                encoding="utf-8")
        )
        for key, value in (
            ("package", "synthetic"),
            ("source_root", "synthetic"),
        ):
            mutated = json.loads(json.dumps(tracked))
            mutated[key] = value
            with (
                mock.patch.object(
                    candidate_verify, "_read_json", return_value=mutated),
                self.assertRaisesRegex(
                    candidate_verify.CandidateError, "schema"),
            ):
                candidate_verify._load_contract(root)
        frozen = json.loads(json.dumps(tracked))
        frozen["candidate"]["state"] = "frozen"
        frozen["candidate"]["file"] = "RayClusterManager-PR07.exe"
        frozen["candidate"]["size"] = 1
        frozen["candidate"]["sha256"] = "a" * 64
        frozen["candidate"]["public_source_snapshot_sha256"] = "b" * 64
        frozen["candidate"]["package_manifest_sha256"] = "d" * 64
        frozen["candidate"]["verification"]["passed_cycles"] = 100
        frozen["candidate"]["verification"]["evidence_sha256"] = "e" * 64
        frozen["candidate"]["blockers"] = []
        with (
            mock.patch.object(
                candidate_verify, "_read_json", return_value=frozen),
        ):
            self.assertEqual(
                frozen["candidate"],
                candidate_verify._load_contract(root),
            )

    def test_candidate_runner_uses_bounded_lifecycle_command(self) -> None:
        source = Path(candidate_verify.__file__).read_text(encoding="utf-8")
        self.assertEqual(
            (
                "live_system_access",
                "live_system_mutation",
                "production_config_mutation",
                "official_artifact_mutation",
                "mutex_residue",
                "named_pipe_residue",
                "temporary_artifact_residue",
                "elevated_token_activity",
                "uac_prompt_activity",
                "helper_process_residue",
                "startup_entry_mutation",
                "scheduled_task_mutation",
                "rdp_host_configuration_mutation",
                "firewall_rule_mutation",
                "network_location_awareness_mutation",
                "credential_material_mutation",
                "ray_runtime_mutation",
                "tailscale_runtime_mutation",
                "production_state_preservation",
                "development_state_preservation",
                "stale_owner_preservation",
                "sentinel_state_preservation",
                "configuration_bootstrap",
            ),
            tuple(candidate_verify.CLAIM_ASSERTIONS),
        )
        self.assertIn(
            '(str(executable), "--lifecycle-check", scenario)',
            source,
        )
        self.assertIn(
            '(str(candidate), "--internal-configuration-check")',
            source,
        )
        self.assertIn('for deployment in ("installed", "portable")', source)
        self.assertIn('"LOCALAPPDATA": str(local_root)', source)
        self.assertIn("local_root.mkdir()", source)
        self.assertIn("first_ready - started > 5.0", source)
        self.assertIn("finished - first_ready > 5.0", source)
        self.assertIn("maximum_descendants != 1", source)
        self.assertIn("_approved_onefile_processes(", source)
        self.assertIn("os.path.samefile(image, executable)", source)
        self.assertIn("_await_no_residue(", source)
        self.assertIn("bool(is_iconic(hwnd))", source)
        self.assertIn("or failure", source)
        self.assertIn("except psutil_module.AccessDenied", source)
        self.assertEqual(
            {"MEASURED", "NOT_APPLICABLE"},
            {
                assertion["status"]
                for assertion in candidate_verify.CLAIM_ASSERTIONS.values()
            },
        )
        for claim, assertion in candidate_verify.CLAIM_ASSERTIONS.items():
            if assertion["status"] == "NOT_APPLICABLE":
                self.assertNotIn(f'"{claim}": 0', source)
        self.assertNotIn("LIFECYCLE PASS", source)
        self.assertIn("LIFECYCLE OBSERVED", source)
        self.assertIn("SUPPLEMENTAL OBSERVED", source)
        self.assertNotIn('print(f"evidence:', source)

    def test_onefile_lineage_is_exact_and_child_window_is_observed(self) -> None:
        class Process:
            def __init__(
                self,
                pid: int,
                created: float,
                parent: int,
                image: str,
                *,
                image_error: Exception | None = None,
            ) -> None:
                self.pid = pid
                self.created = created
                self.parent = parent
                self.image = image
                self.image_error = image_error

            def create_time(self) -> float:
                return self.created

            def ppid(self) -> int:
                return self.parent

            def exe(self) -> str:
                if self.image_error is not None:
                    raise self.image_error
                return self.image

            def is_running(self) -> bool:
                return True

        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            candidate = root_path / "candidate.exe"
            other = root_path / "other.exe"
            candidate.write_bytes(b"candidate")
            other.write_bytes(b"other")
            root = Process(10, 1.0, 1, str(candidate))
            child = Process(11, 2.0, 10, str(candidate))
            root_identity = candidate_verify._process_identity(root)
            active, bound = candidate_verify._approved_onefile_processes(
                root,
                [],
                executable=candidate,
                root_identity=root_identity,
                bound_child=None,
            )
            self.assertEqual((root,), active)
            self.assertIsNone(bound)
            active, bound = candidate_verify._approved_onefile_processes(
                root,
                [child],
                executable=candidate,
                root_identity=root_identity,
                bound_child=None,
            )
            self.assertEqual((root, child), active)
            self.assertEqual((11, 2.0), bound)
            vanished = Process(11, 2.0, 10, str(candidate))
            vanished.ppid = mock.Mock(side_effect=RuntimeError("exited"))
            vanished.is_running = mock.Mock(return_value=False)
            active, rebound = candidate_verify._approved_onefile_processes(
                root,
                [vanished],
                executable=candidate,
                root_identity=root_identity,
                bound_child=bound,
            )
            self.assertEqual((root,), active)
            self.assertEqual(bound, rebound)
            records = [
                (100, 11, "Ray Cluster Manager", "TkTopLevel", True, False),
            ]
            self.assertEqual(
                "VISIBLE",
                candidate_verify._classify_main_windows(records, {10, 11}),
            )
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "ambiguous",
            ):
                candidate_verify._classify_main_windows(
                    [
                        *records,
                        (
                            101,
                            10,
                            "Ray Cluster Manager",
                            "TkTopLevel",
                            True,
                            False,
                        ),
                    ],
                    {10, 11},
                )

            denied_parent = Process(11, 2.0, 10, str(candidate))
            denied_parent.ppid = mock.Mock(side_effect=PermissionError("denied"))
            denied_identity = Process(11, 2.0, 10, str(candidate))
            denied_identity.create_time = mock.Mock(
                side_effect=PermissionError("denied")
            )
            invalid = (
                [child, Process(12, 3.0, 11, str(candidate))],
                [Process(11, 2.0, 99, str(candidate))],
                [Process(11, 2.0, 10, str(other))],
                [denied_parent],
                [denied_identity],
                [
                    Process(
                        11,
                        2.0,
                        10,
                        str(candidate),
                        image_error=PermissionError("denied"),
                    )
                ],
            )
            for descendants in invalid:
                with self.subTest(descendants=len(descendants)):
                    with self.assertRaises(candidate_verify.CandidateError):
                        candidate_verify._approved_onefile_processes(
                            root,
                            descendants,
                            executable=candidate,
                            root_identity=root_identity,
                            bound_child=None,
                        )
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "identity changed",
            ):
                candidate_verify._approved_onefile_processes(
                    root,
                    [Process(11, 3.0, 10, str(candidate))],
                    executable=candidate,
                    root_identity=root_identity,
                    bound_child=bound,
                )
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "malformed",
            ):
                candidate_verify._process_identity(
                    Process(12, float("nan"), 10, str(candidate))
                )

    def test_candidate_residue_probe_handles_process_exit_race_fail_closed(
        self,
    ) -> None:
        class AccessDenied(Exception):
            pass

        class NoSuchProcess(Exception):
            pass

        class ZombieProcess(Exception):
            pass

        class ExitedProcess:
            def create_time(self) -> float:
                return 1.0

            def status(self) -> str:
                raise NoSuchProcess()

        class DeniedProcess:
            def create_time(self) -> float:
                return 2.0

            def status(self) -> str:
                raise AccessDenied()

        class ReusedProcess:
            def create_time(self) -> float:
                return 99.0

            def status(self) -> str:
                return "running"

        class AliveProcess:
            def create_time(self) -> float:
                return 4.0

            def status(self) -> str:
                return "running"

        module = SimpleNamespace(
            AccessDenied=AccessDenied,
            NoSuchProcess=NoSuchProcess,
            ZombieProcess=ZombieProcess,
            STATUS_ZOMBIE="zombie",
            Process=lambda pid: {
                1: ExitedProcess(),
                2: DeniedProcess(),
                3: ReusedProcess(),
                4: AliveProcess(),
            }[pid],
        )
        self.assertEqual(
            [2, 4],
            candidate_verify._residue_pids(
                {1: 1.0, 2: 2.0, 3: 3.0, 4: 4.0},
                module,
            ),
        )

    def test_candidate_cleanup_terminates_observed_reparented_processes(
        self,
    ) -> None:
        class Target:
            def __init__(self, pid: int) -> None:
                self.pid = pid
                self.terminated = 0

            def children(self, *, recursive: bool) -> list[object]:
                self.recursive = recursive
                return []

            def terminate(self) -> None:
                self.terminated += 1

            def kill(self) -> None:
                raise AssertionError("clean terminate should not require kill")

        class CompletedProcess:
            def poll(self) -> int:
                return 0

            def communicate(self, *, timeout: int) -> tuple[str, str]:
                self.timeout = timeout
                return "", ""

        root = Target(1)
        orphan = Target(2)
        module = SimpleNamespace(
            wait_procs=lambda targets, timeout: (targets, []),
        )
        candidate_verify._terminate_tree(
            CompletedProcess(),
            root,
            module,
            {1: root, 2: orphan},
        )
        self.assertEqual(1, root.terminated)
        self.assertEqual(1, orphan.terminated)

    def test_candidate_diagnostics_never_echo_caller_paths(self) -> None:
        canary = "CALLER-CANARY-evidence-name.json"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / canary
            path.write_bytes(b"{invalid")
            with self.assertRaises(candidate_verify.CandidateError) as raised:
                candidate_verify._read_json(
                    path,
                    label="package manifest",
                )
            diagnostic = str(raised.exception)
            self.assertEqual("invalid JSON: package manifest", diagnostic)
            self.assertNotIn(canary, diagnostic)
            self.assertNotIn(str(path.parent), diagnostic)
        with self.assertRaises(candidate_verify.CandidateError) as raised:
            candidate_verify._decode_json_bytes(
                b"{invalid",
                label="frozen evidence",
            )
        self.assertEqual(
            "invalid reviewed JSON: frozen evidence",
            str(raised.exception),
        )

    def test_frozen_evidence_is_validated_without_timing_rerun(self) -> None:
        manifest = {
            "candidate": {"path": "candidate.exe"},
            "source": {"commit": "a" * 40},
        }

        def receipt(scenario: str, duration: int = 30) -> dict[str, object]:
            states = {
                "visible-quit": ["ABSENT", "VISIBLE"],
                "close-show-quit": ["VISIBLE", "HIDDEN", "VISIBLE"],
                "minimized-show-quit": ["MINIMIZED", "VISIBLE"],
            }[scenario]
            return {
                "scenario": scenario,
                "duration_ms": duration,
                "ready_ms": 10,
                "window_states": states,
                "maximum_network_connections": 0,
                "maximum_network_listeners": 0,
                "maximum_descendants": 1,
                "temporary_artifact_residue": 0,
                "mutex_residue": 0,
                "exit_code": 0,
            }

        receipts = [
            receipt(scenario)
            for scenario, count in candidate_verify.SCENARIO_COUNTS.items()
            for _ in range(count)
        ]
        value = candidate_verify._evidence_value(
            manifest=manifest,
            receipts=receipts,
            configuration_checks=_configuration_checks_fixture(),
            vendor_bytes=123,
            residue_count=0,
        )
        raw = candidate_verify._canonical_bytes(value)
        digest = candidate_verify.hashlib.sha256(raw).hexdigest()
        contract = {
            "state": "frozen",
            "verification": {"evidence_sha256": digest},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "CALLER-CANARY-frozen-evidence-name.json"
            frozen.write_bytes(raw)
            with (
                mock.patch.object(
                    candidate_verify,
                    "_hold_windows_file",
                    side_effect=lambda _path: nullcontext(),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_validate_identity",
                    return_value=(manifest, contract, 123),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_run_once",
                    side_effect=AssertionError("frozen evidence reran"),
                ),
                mock.patch("builtins.print") as output,
            ):
                self.assertEqual(
                    frozen.resolve(),
                    candidate_verify.verify(
                        executable=root / "candidate.exe",
                        package_manifest=root / "manifest.json",
                        evidence=frozen,
                    ),
                )
            printed = "\n".join(
                str(call.args[0]) for call in output.call_args_list
            )
            self.assertIn("evidence_validated=true", printed)
            self.assertNotIn(frozen.name, printed)
            self.assertNotIn(str(root), printed)

            changed = json.loads(raw)
            changed["observations"]["configuration_checks"]["installed"][
                "maximum_network_connections"
            ] = 1
            configuration_tamper = candidate_verify._canonical_bytes(changed)
            frozen.write_bytes(configuration_tamper)
            contract["verification"]["evidence_sha256"] = (
                candidate_verify.hashlib.sha256(
                    configuration_tamper
                ).hexdigest()
            )
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "configuration",
            ):
                candidate_verify._validate_frozen_evidence(
                    evidence=frozen,
                    manifest=manifest,
                    contract=contract,
                    vendor_bytes=123,
                )
            changed = json.loads(raw)
            changed["lifecycle"]["receipts"][0]["duration_ms"] = 31
            changed["observations"]["maximum_duration_ms"] = 31
            frozen.write_bytes(candidate_verify._canonical_bytes(changed))
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "hash",
            ):
                candidate_verify._validate_frozen_evidence(
                    evidence=frozen,
                    manifest=manifest,
                    contract=contract,
                    vendor_bytes=123,
                )
            changed["lifecycle"]["receipts"][0]["window_states"] = ["HIDDEN"]
            tampered = candidate_verify._canonical_bytes(changed)
            frozen.write_bytes(tampered)
            contract["verification"]["evidence_sha256"] = (
                candidate_verify.hashlib.sha256(tampered).hexdigest()
            )
            with self.assertRaisesRegex(
                candidate_verify.CandidateError,
                "assertion",
            ):
                candidate_verify._validate_frozen_evidence(
                    evidence=frozen,
                    manifest=manifest,
                    contract=contract,
                    vendor_bytes=123,
                )

    def test_frozen_independent_rerun_is_supplemental_evidence(self) -> None:
        manifest = {
            "candidate": {"path": "candidate.exe"},
            "source": {"commit": "a" * 40},
        }

        def receipt(scenario: str, duration: int) -> dict[str, object]:
            return {
                "scenario": scenario,
                "duration_ms": duration,
                "ready_ms": 10,
                "window_states": {
                    "visible-quit": ["VISIBLE"],
                    "close-show-quit": ["VISIBLE", "HIDDEN", "VISIBLE"],
                    "minimized-show-quit": ["MINIMIZED", "VISIBLE"],
                }[scenario],
                "maximum_network_connections": 0,
                "maximum_network_listeners": 0,
                "maximum_descendants": 1,
                "temporary_artifact_residue": 0,
                "mutex_residue": 0,
                "exit_code": 0,
            }

        primary_receipts = [
            receipt(scenario, 30)
            for scenario, count in candidate_verify.SCENARIO_COUNTS.items()
            for _ in range(count)
        ]
        primary = candidate_verify._evidence_value(
            manifest=manifest,
            receipts=primary_receipts,
            configuration_checks=_configuration_checks_fixture(),
            vendor_bytes=123,
            residue_count=0,
        )
        primary_raw = candidate_verify._canonical_bytes(primary)
        contract = {
            "state": "frozen",
            "size": 1,
            "sha256": "b" * 64,
            "verification": {
                "evidence_sha256": candidate_verify.hashlib.sha256(
                    primary_raw
                ).hexdigest()
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "frozen.json"
            supplemental = (
                root / "CALLER-CANARY-supplemental-name.json"
            )
            frozen.write_bytes(primary_raw)
            with (
                mock.patch.object(
                    candidate_verify,
                    "_hold_windows_file",
                    side_effect=lambda _path: nullcontext(),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_validate_identity",
                    return_value=(manifest, contract, 123),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_load_psutil",
                    return_value=object(),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_configuration_checks",
                    return_value=_configuration_checks_fixture(),
                ),
                mock.patch.object(
                    candidate_verify,
                    "_run_once",
                    side_effect=lambda _exe, scenario, **_kwargs: (
                        receipt(scenario, 35),
                        [],
                    ),
                ),
                mock.patch("builtins.print") as output,
            ):
                self.assertEqual(
                    supplemental.resolve(),
                    candidate_verify.verify(
                        executable=root / "candidate.exe",
                        package_manifest=root / "manifest.json",
                        evidence=frozen,
                        supplemental_evidence=supplemental,
                    ),
                )
            printed = "\n".join(
                str(call.args[0]) for call in output.call_args_list
            )
            self.assertIn("evidence_created=true", printed)
            self.assertNotIn(supplemental.name, printed)
            self.assertNotIn(str(root), printed)
            self.assertNotEqual(
                candidate_verify.hashlib.sha256(primary_raw).hexdigest(),
                candidate_verify._sha256(supplemental),
            )
            generated = json.loads(supplemental.read_text(encoding="utf-8"))
            self.assertEqual([], generated["observations"]["blockers"])

    def test_candidate_handle_denies_path_replacement_while_held(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows file-share semantics required")
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.exe"
            replacement = Path(temporary) / "replacement.exe"
            candidate.write_bytes(b"reviewed")
            replacement.write_bytes(b"replacement")
            with candidate_verify._hold_windows_file(candidate):
                with self.assertRaises(OSError):
                    os.replace(replacement, candidate)
            os.replace(replacement, candidate)
            self.assertEqual(b"replacement", candidate.read_bytes())


if __name__ == "__main__":
    unittest.main()
