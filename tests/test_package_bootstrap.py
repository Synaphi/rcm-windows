from __future__ import annotations

from dataclasses import replace
import importlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import socket
import subprocess
import sys
import tempfile
import traceback
import unittest
from unittest import mock

from rcm.bootstrap import (
    BootstrapRequest,
    CompatibilityLauncher,
    Environment,
    ensure_bootstrap_directories,
    plan_bootstrap,
    run_launcher,
    select_deployment,
)
from rcm.identity import (
    DEVELOPMENT_CONFIG_NAMESPACE,
    DEVELOPMENT_MUTEX_NAME,
    VALIDATION_CONFIG_NAMESPACE,
    VALIDATION_MUTEX_NAME,
    PRODUCTION_CONFIG_NAMESPACE,
    PRODUCTION_MUTEX_NAME,
    DeploymentKind,
    identity_for,
    preview_validation_identity,
)
from rcm.config.migrations import SecretMaterialError
from rcm.config.schema import (
    ConfigValidationError,
    canonical_json_bytes,
    default_config,
)
from rcm.config.store import ConfigConflictError, ConfigStore, StoredConfig
from rcm.paths import (
    KnownFolders,
    absolute_local_path,
    join_relative,
    safe_relative_path,
)
from rcm.setup import (
    V1ImportCleanupError,
    V1ImportConflictError,
    V1ImportError,
    apply_v1_import,
    configure_local_node,
    default_v1_config_path,
    prepare_v1_import,
    rollback_v1_import,
)


class RecordingFilesystem:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, bool]] = []

    def mkdir(
        self,
        path: str,
        *,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        self.calls.append((path, parents, exist_ok))


def request_for(
    environment: dict[str, str] | None = None,
    *,
    frozen: bool = False,
) -> BootstrapRequest:
    return BootstrapRequest(
        environment=Environment(environment),
        known_folders=KnownFolders(
            local_app_data=PureWindowsPath(r"C:\Synthetic\LocalAppData")
        ),
        application_root=PureWindowsPath(r"C:\Synthetic\Application"),
        resource_root=PureWindowsPath(r"C:\Synthetic\Bundle"),
        current_binary=PureWindowsPath(r"C:\Synthetic\Application\rcm.exe"),
        frozen=frozen,
    )


def v1_import_source_bytes(*, interval: float = 1.5) -> bytes:
    return canonical_json_bytes({
        "schema_version": 15,
        "head_ip": "192.0.2.10",
        "head_port": 6389,
        "dashboard_port": 8275,
        "this": {
            "ip": "192.0.2.11",
            "mode": "ray",
            "role": "worker",
            "num_cpus": "auto",
        },
        "nodes": [
            {
                "name": "synthetic-head",
                "ip": "192.0.2.10",
                "mode": "ray",
                "role": "head",
                "num_cpus": 8,
                "enabled": True,
            },
            {
                "name": "synthetic-worker",
                "ip": "192.0.2.11",
                "mode": "ray",
                "role": "worker",
                "num_cpus": "auto",
                "enabled": True,
                "rdp_user": "SYNTHETIC_DROPPED_USER",
                "credential_reference": "credential://synthetic-metadata",
            },
        ],
        "metrics_enabled": False,
        "poll_interval": interval,
        "dashboard_stale_grace_sec": 8.0,
        "process_cleanup": {"grace_sec": 4.0},
        "trusted_controller_ids": ["SYNTHETIC_DROPPED_AUTHORITY"],
    })


class PackageBootstrapTests(unittest.TestCase):
    def test_package_and_module_import_do_not_start_or_probe_application(
        self,
    ) -> None:
        forbidden = mock.Mock(
            side_effect=AssertionError("import attempted a live side effect")
        )
        legacy_was_loaded = "ray_monitor" in sys.modules
        desktop_modules_before = {
            name: name in sys.modules
            for name in ("tkinter", "pystray", "PIL.Image", "winreg")
        }
        loaded = {
            name: module
            for name, module in tuple(sys.modules.items())
            if name == "rcm" or name.startswith("rcm.")
        }
        for name in loaded:
            sys.modules.pop(name, None)
        try:
            with (
                mock.patch.object(sys, "dont_write_bytecode", True),
                mock.patch.object(os, "mkdir", forbidden),
                mock.patch.object(os, "makedirs", forbidden),
                mock.patch.object(socket, "socket", forbidden),
                mock.patch.object(subprocess, "Popen", forbidden),
            ):
                package = importlib.import_module("rcm")
                module_entrypoint = importlib.import_module("rcm.__main__")
                ui = importlib.import_module("rcm.ui")
                desktop = importlib.import_module("rcm.desktop")
                windows_desktop = importlib.import_module(
                    "rcm.adapters.windows_desktop"
                )
            self.assertEqual("2.8.3b1", package.__version__)
            self.assertTrue(callable(module_entrypoint.main))
            self.assertTrue(callable(ui.fit_scale))
            self.assertTrue(hasattr(desktop, "DesktopLifecycle"))
            self.assertTrue(hasattr(windows_desktop, "TkDesktopHost"))
            self.assertNotIn("rcm.adapters.windows_admin", sys.modules)
            self.assertNotIn("rcm.adapters.windows_broker", sys.modules)
            forbidden.assert_not_called()
            self.assertEqual(
                legacy_was_loaded,
                "ray_monitor" in sys.modules,
            )
            self.assertEqual(
                desktop_modules_before,
                {
                    name: name in sys.modules
                    for name in desktop_modules_before
                },
            )
        finally:
            for name in tuple(sys.modules):
                if name == "rcm" or name.startswith("rcm."):
                    sys.modules.pop(name, None)
            sys.modules.update(loaded)

    def test_environment_is_copied_and_case_insensitive(self) -> None:
        source = {"rcm_runtime_mode": "development"}
        environment = Environment(source)
        source["rcm_runtime_mode"] = "installed"
        self.assertEqual(
            "development",
            environment.get("RCM_RUNTIME_MODE"),
        )

    def test_deployment_selection_uses_only_injected_facts(self) -> None:
        self.assertIs(
            DeploymentKind.DEVELOPMENT,
            select_deployment(Environment(), frozen=False),
        )
        self.assertIs(
            DeploymentKind.INSTALLED,
            select_deployment(Environment(), frozen=True),
        )
        self.assertIs(
            DeploymentKind.PORTABLE,
            select_deployment(Environment({"RCM_PORTABLE": "1"}), frozen=True),
        )
        self.assertIs(
            DeploymentKind.DEVELOPMENT,
            select_deployment(
                Environment({"RCM_RUNTIME_MODE": "dev"}),
                frozen=True,
            ),
        )

    def test_deployment_selection_rejects_invalid_or_conflicting_flags(
        self,
    ) -> None:
        for values in (
            {"RCM_PORTABLE": "yes"},
            {"RCM_RUNTIME_MODE": "unknown"},
            {
                "RCM_RUNTIME_MODE": "installed",
                "RCM_PORTABLE": "1",
            },
        ):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    select_deployment(Environment(values), frozen=False)

    def test_development_identity_is_separate_from_production(self) -> None:
        development = identity_for(DeploymentKind.DEVELOPMENT)
        installed = identity_for(DeploymentKind.INSTALLED)
        portable = identity_for(DeploymentKind.PORTABLE)

        self.assertEqual(
            DEVELOPMENT_CONFIG_NAMESPACE,
            development.config_namespace,
        )
        self.assertEqual(DEVELOPMENT_MUTEX_NAME, development.mutex_name)
        self.assertFalse(development.production)
        self.assertEqual(
            PRODUCTION_CONFIG_NAMESPACE,
            installed.config_namespace,
        )
        self.assertEqual(PRODUCTION_MUTEX_NAME, installed.mutex_name)
        self.assertTrue(installed.production)
        self.assertEqual(installed.mutex_name, portable.mutex_name)

        validation = preview_validation_identity()
        self.assertFalse(validation.production)
        self.assertEqual(
            VALIDATION_CONFIG_NAMESPACE,
            validation.config_namespace,
        )
        self.assertEqual(VALIDATION_MUTEX_NAME, validation.mutex_name)
        self.assertNotEqual(development.mutex_name, validation.mutex_name)
        self.assertNotEqual(installed.mutex_name, validation.mutex_name)

    def test_installed_plan_uses_local_app_data(self) -> None:
        plan = plan_bootstrap(request_for(frozen=True))
        self.assertIs(DeploymentKind.INSTALLED, plan.identity.deployment)
        self.assertEqual(
            PureWindowsPath(
                r"C:\Synthetic\LocalAppData\RayClusterManager\config.json"
            ),
            plan.paths.config_file,
        )
        self.assertEqual(
            PureWindowsPath(
                r"C:\Synthetic\LocalAppData\RayClusterManager"
                r"\logs\ray_monitor.log"
            ),
            plan.paths.application_log,
        )

    def test_development_plan_uses_separate_namespace(self) -> None:
        plan = plan_bootstrap(request_for())
        self.assertEqual(
            PureWindowsPath(
                r"C:\Synthetic\LocalAppData\RayClusterManager-dev"
            ),
            plan.paths.config_directory,
        )
        self.assertNotEqual(
            PRODUCTION_MUTEX_NAME,
            plan.identity.mutex_name,
        )

    def test_portable_plan_keeps_state_beside_application(self) -> None:
        plan = plan_bootstrap(
            request_for({"RCM_RUNTIME_MODE": "portable"}, frozen=True)
        )
        self.assertEqual(
            PureWindowsPath(r"C:\Synthetic\Application\data"),
            plan.paths.config_directory,
        )
        self.assertEqual(
            PureWindowsPath(r"C:\Synthetic\Application\data\logs"),
            plan.paths.log_directory,
        )
        self.assertEqual(
            PureWindowsPath(
                r"C:\Synthetic\LocalAppData\RayClusterManager\rdp"
            ),
            plan.paths.rdp_directory,
        )

    def test_resource_and_binary_paths_are_explicit_abstractions(self) -> None:
        plan = plan_bootstrap(request_for())
        self.assertEqual(
            PureWindowsPath(r"C:\Synthetic\Application\rcm.exe"),
            plan.paths.current_binary,
        )
        self.assertEqual(
            PureWindowsPath(r"C:\Synthetic\Bundle\assets\help.txt"),
            plan.paths.resource("assets/help.txt"),
        )

    def test_relative_path_rejects_traversal_absolute_unc_and_namespaces(
        self,
    ) -> None:
        rejected = (
            "../secret",
            "assets/../secret",
            "/absolute/item",
            r"C:\Synthetic\absolute\item",
            r"C:drive-relative",
            r"\\synthetic-host\share\item",
            "//synthetic-host/share/item",
            r"\\?\C:\Synthetic\item",
            "\\" * 2 + r".\pipe\synthetic",
            r"\??\C:\Synthetic\item",
            r"\Device\NamedPipe\item",
            "item:stream",
            "assets//item",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    safe_relative_path(value)

    def test_absolute_local_path_rejects_relative_unc_and_traversal(
        self,
    ) -> None:
        for value in (
            "relative/item",
            "../relative/item",
            r"\\synthetic-host\share",
            r"C:\Synthetic\..\Other",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    absolute_local_path(value)
        self.assertEqual(
            PurePosixPath("/synthetic/local"),
            absolute_local_path("/synthetic/local"),
        )

    def test_join_relative_preserves_root_path_flavour(self) -> None:
        self.assertEqual(
            PureWindowsPath(r"C:\Synthetic\Root\assets\item.txt"),
            join_relative(r"C:\Synthetic\Root", "assets/item.txt"),
        )
        self.assertEqual(
            PurePosixPath("/synthetic/base/assets/item.txt"),
            join_relative("/synthetic/base", "assets/item.txt"),
        )

    def test_planning_does_not_apply_directory_operations(self) -> None:
        filesystem = RecordingFilesystem()
        plan = plan_bootstrap(request_for())
        self.assertEqual([], filesystem.calls)
        self.assertEqual(3, len(plan.directories))

    def test_directory_creation_is_an_explicit_fake_filesystem_operation(
        self,
    ) -> None:
        filesystem = RecordingFilesystem()
        plan = plan_bootstrap(request_for())
        ensure_bootstrap_directories(plan, filesystem)
        self.assertEqual(
            [
                (
                    r"C:\Synthetic\LocalAppData\RayClusterManager-dev",
                    True,
                    True,
                ),
                (
                    r"C:\Synthetic\LocalAppData"
                    r"\RayClusterManager-dev\logs",
                    True,
                    True,
                ),
                (
                    r"C:\Synthetic\LocalAppData"
                    r"\RayClusterManager-dev\rdp",
                    True,
                    True,
                ),
            ],
            filesystem.calls,
        )

    def test_directory_failure_is_propagated_without_partial_fallback(
        self,
    ) -> None:
        class ReadOnlyFilesystem(RecordingFilesystem):
            def mkdir(
                self,
                path: str,
                *,
                parents: bool = False,
                exist_ok: bool = False,
            ) -> None:
                super().mkdir(path, parents=parents, exist_ok=exist_ok)
                raise PermissionError("synthetic read-only filesystem")

        filesystem = ReadOnlyFilesystem()
        with self.assertRaisesRegex(PermissionError, "synthetic read-only"):
            ensure_bootstrap_directories(
                plan_bootstrap(request_for()),
                filesystem,
            )
        self.assertEqual(1, len(filesystem.calls))

    def test_v1_import_preserves_source_and_supports_generation_bound_switching(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy-config.json"
            source_path.write_bytes(v1_import_source_bytes())
            source_before = source_path.read_bytes()
            source_mtime = source_path.stat().st_mtime_ns
            config_path = root / "v2" / "config.json"
            store = ConfigStore(config_path)
            baseline = store.save(default_config(), expected_generation=0)

            preview = prepare_v1_import(source_path, store)
            self.assertIn("source_path=<redacted>", repr(preview))
            result = apply_v1_import(preview, store)

            self.assertTrue(result.changed)
            self.assertEqual(2, result.stored.generation)
            self.assertNotIn("synthetic", repr(result).casefold())
            self.assertNotIn(str(source_path), repr(result))
            self.assertFalse(result.stored.config.ray.enabled)
            self.assertEqual(
                "synthetic-worker",
                result.stored.config.nodes.local_node_id,
            )
            self.assertEqual(source_before, source_path.read_bytes())
            self.assertEqual(source_mtime, source_path.stat().st_mtime_ns)
            receipt_path = config_path.with_name(
                config_path.name + ".v1-import-receipt"
            )
            receipt_text = receipt_path.read_text(encoding="utf-8")
            self.assertNotIn(str(source_path), receipt_text)
            self.assertNotIn("synthetic", receipt_text.casefold())
            self.assertNotIn("credential", receipt_text.casefold())

            restored = rollback_v1_import(store)
            self.assertEqual(3, restored.generation)
            self.assertEqual(baseline.config, restored.config)
            self.assertFalse(receipt_path.exists())

            reapplied = apply_v1_import(
                prepare_v1_import(source_path, store),
                store,
            )
            self.assertTrue(reapplied.changed)
            self.assertEqual(4, reapplied.stored.generation)
            final = rollback_v1_import(store)
            self.assertEqual(5, final.generation)
            self.assertEqual(baseline.config, final.config)
            residues = {
                path.name
                for path in config_path.parent.iterdir()
                if path.name.endswith(".tmp") or path.name.endswith(".journal")
            }
            self.assertEqual(set(), residues)

    def test_repeated_identical_v1_import_is_a_generation_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            first = apply_v1_import(
                prepare_v1_import(source_path, store),
                store,
            )
            receipt_path = store.path.with_name(
                store.path.name + ".v1-import-receipt"
            )
            receipt_before = receipt_path.read_bytes()

            repeated = apply_v1_import(
                prepare_v1_import(source_path, store),
                store,
            )

            self.assertFalse(repeated.changed)
            self.assertIsNone(repeated.receipt)
            self.assertEqual(first.stored, repeated.stored)
            self.assertEqual(receipt_before, receipt_path.read_bytes())

    def test_v1_import_rejects_secret_without_echo_or_destination_write(
        self,
    ) -> None:
        marker = "SYNTHETIC_SECRET_MUST_NOT_ECHO"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(canonical_json_bytes({
                "schema_version": 15,
                "password": marker,
            }))
            source_before = source_path.read_bytes()
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            config_before = store.path.read_bytes()

            with self.assertRaises(SecretMaterialError) as captured:
                prepare_v1_import(source_path, store)

            self.assertNotIn(marker, str(captured.exception))
            self.assertNotIn(marker, repr(captured.exception))
            self.assertEqual(source_before, source_path.read_bytes())
            self.assertEqual(config_before, store.path.read_bytes())
            self.assertEqual(baseline, store.load())

    def test_v1_import_filesystem_error_has_no_path_cause_or_traceback(self) -> None:
        marker = "SYNTHETIC_PRIVATE_PATH_MARKER"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / marker / "config.json"
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)

            try:
                prepare_v1_import(missing, store)
            except V1ImportError as exc:
                rendered = "".join(traceback.format_exception(exc))
                self.assertIsNone(exc.__cause__)
                self.assertNotIn(marker, str(exc))
                self.assertNotIn(marker, repr(exc))
                self.assertNotIn(marker, rendered)
            else:
                self.fail("missing source was accepted")
            self.assertEqual(baseline, store.load())

    def test_v1_import_rejects_changed_source_and_destination_after_preview(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)
            source_path.write_bytes(v1_import_source_bytes(interval=2.0))

            with self.assertRaises(V1ImportConflictError):
                apply_v1_import(preview, store)
            self.assertEqual(baseline, store.load())

            stable_preview = prepare_v1_import(source_path, store)
            changed = replace(
                baseline.config,
                app=replace(baseline.config.app, start_minimized=True),
            )
            intervening = store.save(changed, expected_generation=1)
            with self.assertRaises(V1ImportConflictError):
                apply_v1_import(stable_preview, store)
            self.assertEqual(intervening, store.load())

    def test_same_projection_concurrent_writer_is_never_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)
            concurrent: StoredConfig | None = None

            def lose_commit_race(*args: object, **kwargs: object) -> object:
                nonlocal concurrent
                concurrent = ConfigStore(store.path).save(
                    preview.projection.config,
                    expected_generation=1,
                )
                raise ConfigConflictError("synthetic concurrent writer")

            with (
                mock.patch.object(store, "save", side_effect=lose_commit_race),
                self.assertRaisesRegex(V1ImportConflictError, "commit"),
            ):
                apply_v1_import(preview, store)

            self.assertIsNotNone(concurrent)
            self.assertEqual(concurrent, store.load())
            self.assertEqual(2, store.load().generation)
            self.assertFalse(
                store.path.with_name(
                    store.path.name + ".v1-import-receipt"
                ).exists()
            )

    def test_conflict_receipt_cannot_own_same_projection_concurrent_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)

            def lose_commit_race(*args: object, **kwargs: object) -> object:
                ConfigStore(store.path).save(
                    preview.projection.config,
                    expected_generation=1,
                )
                raise ConfigConflictError("synthetic concurrent writer")

            with (
                mock.patch.object(store, "save", side_effect=lose_commit_race),
                mock.patch(
                    "rcm.setup._remove_receipt",
                    side_effect=OSError("synthetic cleanup failure"),
                ),
                self.assertRaises(V1ImportConflictError),
            ):
                apply_v1_import(preview, store)

            concurrent = store.load()
            receipt_path = store.path.with_name(
                store.path.name + ".v1-import-receipt"
            )
            self.assertEqual(2, concurrent.generation)
            self.assertIsNone(concurrent.transaction_id)
            self.assertTrue(receipt_path.exists())
            with self.assertRaisesRegex(
                V1ImportConflictError,
                "changed after",
            ):
                rollback_v1_import(store)
            self.assertEqual(concurrent, store.load())

    def test_io_failure_cannot_rollback_same_projection_concurrent_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)

            def external_commit_then_fail(
                *args: object,
                **kwargs: object,
            ) -> object:
                ConfigStore(store.path).save(
                    preview.projection.config,
                    expected_generation=1,
                )
                raise OSError("synthetic post-external failure")

            with (
                mock.patch.object(
                    store,
                    "save",
                    side_effect=external_commit_then_fail,
                ),
                self.assertRaisesRegex(
                    V1ImportError,
                    "could not be authenticated",
                ),
            ):
                apply_v1_import(preview, store)

            external = store.load()
            self.assertEqual(2, external.generation)
            self.assertEqual(preview.projection.config, external.config)
            self.assertIsNone(external.transaction_id)

    def test_generation_limit_reserves_one_generation_for_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)
            limit = (1 << 63) - 2
            saturated = StoredConfig(
                config=baseline.config,
                generation=limit,
                checksum=baseline.checksum,
            )
            saturated_preview = replace(
                preview,
                destination_generation=limit,
            )

            with (
                mock.patch.object(store, "load", return_value=saturated),
                mock.patch.object(store, "save") as save,
                mock.patch("rcm.setup._write_receipt") as write_receipt,
                self.assertRaisesRegex(V1ImportError, "reserved rollback"),
            ):
                apply_v1_import(saturated_preview, store)

            save.assert_not_called()
            write_receipt.assert_not_called()

    def test_rollback_cleanup_failure_reports_restored_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            apply_v1_import(prepare_v1_import(source_path, store), store)
            receipt_path = store.path.with_name(
                store.path.name + ".v1-import-receipt"
            )

            with (
                mock.patch(
                    "rcm.setup._remove_receipt",
                    side_effect=OSError("synthetic cleanup failure"),
                ),
                self.assertRaises(V1ImportCleanupError) as raised,
            ):
                rollback_v1_import(store)

            restored = store.load()
            self.assertEqual(3, restored.generation)
            self.assertEqual(baseline.config, restored.config)
            self.assertEqual(restored, raised.exception.stored)
            self.assertNotIn(str(source_path), repr(raised.exception))
            self.assertNotIn("synthetic", repr(raised.exception).casefold())
            self.assertTrue(receipt_path.exists())

    def test_v1_import_open_handle_detects_source_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            replacement = root / "replacement.json"
            source_path.write_bytes(v1_import_source_bytes())
            replacement.write_bytes(v1_import_source_bytes(interval=2.0))
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            original_open = os.open
            swapped = False

            def swap_before_open(path: object, flags: int) -> int:
                nonlocal swapped
                if Path(path) == source_path and not swapped:
                    swapped = True
                    os.replace(replacement, source_path)
                return original_open(path, flags)

            with (
                mock.patch("rcm.setup.os.open", side_effect=swap_before_open),
                self.assertRaisesRegex(V1ImportConflictError, "handle opened"),
            ):
                prepare_v1_import(source_path, store)
            self.assertTrue(swapped)
            self.assertEqual(baseline, store.load())

    def test_v1_import_rejects_reparse_and_hardlink_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual.json"
            actual.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            with (
                mock.patch(
                    "rcm.setup._has_reparse_attribute",
                    return_value=True,
                ),
                self.assertRaises(V1ImportError),
            ):
                prepare_v1_import(actual, store)

            hardlink = root / "config-hardlink.json"
            os.link(store.path, hardlink)
            with self.assertRaises(V1ImportError):
                prepare_v1_import(hardlink, store)

    def test_store_temp_hardlink_race_cannot_modify_v1_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            source_before = source_path.read_bytes()
            config_path = root / "v2" / "config.json"
            baseline_store = ConfigStore(config_path)
            baseline = baseline_store.save(
                default_config(),
                expected_generation=0,
            )
            linked = False

            def link_source_into_temp(phase: str) -> None:
                nonlocal linked
                if phase == "backup_durable" and not linked:
                    linked = True
                    os.link(source_path, store.temp_path)

            store = ConfigStore(config_path, phase_hook=link_source_into_temp)
            preview = prepare_v1_import(source_path, store)
            with self.assertRaisesRegex(V1ImportError, "retained"):
                apply_v1_import(preview, store)

            self.assertTrue(linked)
            self.assertEqual(source_before, source_path.read_bytes())
            self.assertEqual(baseline, store.load())
            self.assertFalse(store.temp_path.exists())

    def test_v1_import_receipt_is_strict_and_intervening_save_blocks_rollback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            store.save(default_config(), expected_generation=0)
            imported = apply_v1_import(
                prepare_v1_import(source_path, store),
                store,
            )
            changed = replace(
                imported.stored.config,
                app=replace(imported.stored.config.app, start_minimized=True),
            )
            intervening = store.save(changed, expected_generation=2)
            with self.assertRaises(V1ImportConflictError):
                rollback_v1_import(store)
            self.assertEqual(intervening, store.load())

            receipt_path = store.path.with_name(
                store.path.name + ".v1-import-receipt"
            )
            document = json.loads(receipt_path.read_text(encoding="utf-8"))
            document["unexpected"] = 1
            receipt_path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(V1ImportError):
                rollback_v1_import(store)
            self.assertEqual(intervening, store.load())

    def test_v1_import_receipt_verification_failure_restores_previous_config(
        self,
    ) -> None:
        import rcm.setup as setup_module

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)
            original_loader = setup_module._load_receipt
            loads = 0

            def fail_second_load(target: ConfigStore) -> object:
                nonlocal loads
                loads += 1
                if loads == 2:
                    raise V1ImportError("synthetic receipt failure")
                return original_loader(target)

            with (
                mock.patch(
                    "rcm.setup._load_receipt",
                    side_effect=fail_second_load,
                ),
                self.assertRaisesRegex(V1ImportError, "previous 2.x settings"),
            ):
                apply_v1_import(preview, store)

            restored = store.load()
            self.assertEqual(3, restored.generation)
            self.assertEqual(baseline.config, restored.config)
            self.assertFalse(
                store.path.with_name(
                    store.path.name + ".v1-import-receipt"
                ).exists()
            )
            self.assertFalse(any(
                path.name.endswith(".tmp") or path.name.endswith(".journal")
                for path in store.path.parent.iterdir()
            ))

    def test_v1_import_receipt_preparation_failure_retains_previous_config(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            source_before = source_path.read_bytes()
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)

            with (
                mock.patch(
                    "rcm.setup._write_receipt",
                    side_effect=OSError("synthetic read-only receipt"),
                ),
                self.assertRaisesRegex(V1ImportError, "retained"),
            ):
                apply_v1_import(preview, store)

            self.assertEqual(baseline, store.load())
            self.assertEqual(source_before, source_path.read_bytes())
            self.assertFalse(
                store.path.with_name(
                    store.path.name + ".v1-import-receipt"
                ).exists()
            )

    def test_prepared_receipt_recovers_after_precommit_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)

            with (
                mock.patch.object(store, "save", side_effect=SystemExit(91)),
                self.assertRaises(SystemExit),
            ):
                apply_v1_import(preview, store)

            receipt_path = store.path.with_name(
                store.path.name + ".v1-import-receipt"
            )
            self.assertTrue(receipt_path.exists())
            recovered = rollback_v1_import(store)
            self.assertEqual(baseline, recovered)
            self.assertFalse(receipt_path.exists())

    def test_prepared_receipt_recovers_after_postcommit_process_exit(self) -> None:
        import rcm.setup as setup_module

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            preview = prepare_v1_import(source_path, store)
            original_reader = setup_module._read_source_snapshot
            reads = 0

            def exit_after_commit(path: Path) -> object:
                nonlocal reads
                reads += 1
                if reads == 4:
                    raise SystemExit(92)
                return original_reader(path)

            with (
                mock.patch(
                    "rcm.setup._read_source_snapshot",
                    side_effect=exit_after_commit,
                ),
                self.assertRaises(SystemExit),
            ):
                apply_v1_import(preview, store)

            imported = store.load()
            self.assertEqual(2, imported.generation)
            self.assertNotEqual(baseline.config, imported.config)
            restored = rollback_v1_import(store)
            self.assertEqual(3, restored.generation)
            self.assertEqual(baseline.config, restored.config)

    def test_mapped_remote_drive_source_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            store = ConfigStore(root / "v2" / "config.json")
            baseline = store.save(default_config(), expected_generation=0)
            with (
                self.assertRaisesRegex(V1ImportError, "local drive" if os.name == "nt" else "local absolute file"),
                mock.patch("rcm.setup.os.name", "nt"),
                mock.patch("rcm.setup._windows_drive_type", return_value=4),
            ):
                prepare_v1_import(source_path, store)
            self.assertEqual(baseline, store.load())

            alternate_stream = Path(str(source_path) + ":alternate")
            with (
                mock.patch("rcm.setup.os.name", "nt"),
                self.assertRaisesRegex(V1ImportError, "local absolute"),
            ):
                prepare_v1_import(alternate_stream, store)
            self.assertEqual(baseline, store.load())

    def test_v1_import_interrupted_commit_recovers_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            config_path = root / "v2" / "config.json"
            baseline_store = ConfigStore(config_path)
            baseline = baseline_store.save(default_config(), expected_generation=0)
            fired = False

            def interrupt_once(phase: str) -> None:
                nonlocal fired
                if phase == "target_replaced" and not fired:
                    fired = True
                    raise OSError("synthetic interrupted commit")

            store = ConfigStore(config_path, phase_hook=interrupt_once)
            preview = prepare_v1_import(source_path, store)
            with self.assertRaisesRegex(V1ImportError, "restored"):
                apply_v1_import(preview, store)

            restored = store.load()
            self.assertTrue(fired)
            self.assertEqual(3, restored.generation)
            self.assertEqual(baseline.config, restored.config)
            self.assertFalse(any(
                path.name.endswith(".tmp") or path.name.endswith(".journal")
                for path in store.path.parent.iterdir()
            ))

    def test_default_v1_path_is_constructed_without_probing(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {"APPDATA": r"C:\Synthetic\Roaming"},
                clear=True,
            ),
            mock.patch.object(
                Path,
                "exists",
                side_effect=AssertionError("default path was probed"),
            ),
        ):
            self.assertEqual(
                Path(r"C:\Synthetic\Roaming")
                / "RayClusterManager"
                / "config.json",
                default_v1_config_path(),
            )

    def test_local_setup_requires_explicit_pinned_ray_configuration(self) -> None:
        enabled = configure_local_node(
            default_config(),
            node_id="local-head",
            address="192.0.2.10",
            role="head",
            cpu_count=4,
            monitoring_enabled=True,
            start_minimized=False,
            ray_enabled=True,
            ray_executable_path=(
                r"C:\Synthetic\Python312\Scripts\ray.exe"
            ),
            ray_head_address="192.0.2.10",
        )
        self.assertTrue(enabled.ray.enabled)
        self.assertEqual("local-head", enabled.nodes.local_node_id)
        self.assertEqual(
            r"C:\Synthetic\Python312\Scripts\ray.exe",
            enabled.ray.executable_path,
        )

        preserved = configure_local_node(
            enabled,
            node_id="local-head",
            address="192.0.2.10",
            role="head",
            cpu_count=4,
            monitoring_enabled=True,
            start_minimized=False,
        )
        self.assertEqual(enabled.ray, preserved.ray)

        with self.assertRaisesRegex(
            ConfigValidationError, "ray.executable_path"
        ):
            configure_local_node(
                default_config(),
                node_id="local-head",
                address="192.0.2.10",
                role="head",
                cpu_count=4,
                monitoring_enabled=True,
                start_minimized=False,
                ray_enabled=True,
                ray_executable_path="",
                ray_head_address="192.0.2.10",
            )

    def test_configuration_wizard_acquires_production_singleton_before_io(
        self,
    ) -> None:
        from rcm.setup import run_configuration_wizard

        singleton = mock.Mock()
        singleton.acquire.return_value = None
        with (
            mock.patch(
                "rcm.adapters.windows_desktop.WindowsSingleton",
                return_value=singleton,
            ),
            mock.patch("rcm.setup.host_bootstrap_plan") as host_plan,
            mock.patch("rcm.setup.initialize_runtime_config") as initialize,
        ):
            self.assertEqual(3, run_configuration_wizard())

        identity = singleton.acquire.call_args.args[0]
        self.assertTrue(identity.production)
        self.assertEqual(PRODUCTION_MUTEX_NAME, identity.mutex_name)
        host_plan.assert_not_called()
        initialize.assert_not_called()

    def test_configuration_wizard_reports_import_rollback_cleanup_state(
        self,
    ) -> None:
        import rcm.setup as setup_module

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "config.json"
            source_path = root / "legacy.json"
            source_path.write_bytes(v1_import_source_bytes())
            baseline = ConfigStore(config_path).save(
                default_config(),
                expected_generation=0,
            )
            restored = StoredConfig(
                config=baseline.config,
                generation=3,
                checksum=baseline.checksum,
            )
            plan = mock.Mock()
            plan.paths.config_file = config_path
            lease = mock.Mock()
            singleton = mock.Mock()
            singleton.acquire.return_value = lease
            choice = setup_module._ConfigurationChoice(
                kind="import",
                source_path=source_path,
            )

            with (
                mock.patch(
                    "rcm.adapters.windows_desktop.WindowsSingleton",
                    return_value=singleton,
                ),
                mock.patch("rcm.setup.host_bootstrap_plan", return_value=plan),
                mock.patch(
                    "rcm.setup.initialize_runtime_config",
                    return_value=baseline,
                ),
                mock.patch("rcm.setup._configuration_dialog", return_value=choice),
                mock.patch("rcm.setup.prepare_v1_import", return_value=object()),
                mock.patch("rcm.setup._confirm_v1_import", return_value=True),
                mock.patch(
                    "rcm.setup.apply_v1_import",
                    side_effect=V1ImportCleanupError(restored),
                ),
                mock.patch("rcm.setup._show_configuration_message") as show,
            ):
                self.assertEqual(5, setup_module.run_configuration_wizard())

            message = show.call_args.args[1]
            self.assertIn("restored at generation 3", message)
            self.assertIn("stale rollback receipt", message)
            lease.release.assert_called_once_with()

    def test_compatibility_launcher_imports_legacy_only_when_called(
        self,
    ) -> None:
        calls: list[str] = []
        entrypoint = mock.Mock(return_value=None)
        synthetic_module = type(
            "SyntheticLegacyModule",
            (),
            {"main": staticmethod(entrypoint)},
        )

        def importer(name: str) -> object:
            calls.append(name)
            return synthetic_module

        launcher = CompatibilityLauncher(importer=importer)
        self.assertEqual([], calls)
        self.assertEqual(0, run_launcher(launcher))
        self.assertEqual(["ray_monitor"], calls)
        entrypoint.assert_called_once_with()

    def test_module_main_accepts_an_injected_launcher(self) -> None:
        from rcm.__main__ import main

        launcher = mock.Mock(return_value=17)
        self.assertEqual(17, main(launcher, argv=()))
        launcher.assert_called_once_with()

    def test_module_main_parses_typed_lifecycle_scenarios_lazily(self) -> None:
        from rcm.__main__ import main
        from rcm.desktop import LifecycleScenario

        with mock.patch("rcm.app.main", return_value=0) as desktop:
            self.assertEqual(
                0,
                main(
                    argv=(
                        "--lifecycle-check",
                        "close-show-quit",
                    )
                ),
            )
        desktop.assert_called_once_with(
            start_minimized=False,
            lifecycle_scenario=LifecycleScenario.CLOSE_SHOW_QUIT,
        )
        with self.assertRaisesRegex(ValueError, "unsupported lifecycle"):
            main(argv=("--lifecycle-check", "unknown"))

    def test_module_main_routes_configure_to_the_local_wizard(self) -> None:
        from rcm.__main__ import main

        with mock.patch(
            "rcm.setup.run_configuration_wizard", return_value=19
        ) as configure:
            self.assertEqual(19, main(argv=("--configure",)))
        configure.assert_called_once_with()

        with self.assertRaisesRegex(ValueError, "launcher"):
            main(lambda: 0, argv=("--configure",))

    def test_module_main_routes_guarded_internal_configuration_check(self) -> None:
        from rcm.__main__ import main

        with mock.patch(
            "rcm.setup.run_internal_configuration_check", return_value=23
        ) as check:
            self.assertEqual(
                23,
                main(argv=("--internal-configuration-check",)),
            )
        check.assert_called_once_with()
        with self.assertRaisesRegex(ValueError, "launcher"):
            main(lambda: 0, argv=("--internal-configuration-check",))

    def test_module_main_dispatches_fixed_local_admin_helper_lazily(
        self,
    ) -> None:
        from rcm.__main__ import main
        from rcm.adapters.windows_broker import (
            parse_one_shot_helper_arguments,
        )

        arguments = (
            "--rcm-local-admin-helper",
            "--pipe",
            "rcm-pr07-" + "a" * 32,
            "--challenge",
            "b" * 64,
            "--challenge-expires-at",
            float(130).hex(),
            "--parent-pid",
            "41007",
        )
        applier = object()
        with (
            mock.patch("sys.frozen", False, create=True),
            mock.patch(
                "rcm.adapters.windows_admin.WindowsAdminApplier",
            ) as blocked_applier,
            mock.patch(
                "rcm.adapters.windows_broker.run_one_shot_helper",
            ) as blocked_helper,
            mock.patch(
                "rcm.adapters.windows_broker.parse_one_shot_helper_arguments",
            ) as blocked_parser,
        ):
            self.assertEqual(2, main(argv=arguments))
        blocked_applier.assert_not_called()
        blocked_helper.assert_not_called()
        blocked_parser.assert_not_called()
        with (
            mock.patch("sys.frozen", True, create=True),
            mock.patch.dict(
                "os.environ",
                {"_PYI_APPLICATION_HOME_DIR": "SYNTHETIC_ONEFILE"},
            ),
        ):
            self.assertEqual(2, main(argv=arguments))
        with (
            mock.patch("sys.frozen", True, create=True),
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch(
                "rcm.privilege.LOCAL_ADMIN_ELEVATION_ENABLED",
                True,
            ),
            mock.patch(
                "rcm.adapters.windows_broker."
                "parse_one_shot_helper_arguments",
                wraps=parse_one_shot_helper_arguments,
            ) as parser,
            mock.patch(
                "rcm.adapters.windows_broker.run_one_shot_helper",
                return_value=23,
            ) as helper,
            mock.patch(
                "rcm.adapters.windows_admin.WindowsAdminApplier",
                return_value=applier,
            ) as applier_factory,
        ):
            self.assertEqual(23, main(argv=arguments))

        parser.assert_called_once_with(arguments)
        applier_factory.assert_called_once_with()
        command = helper.call_args.args[0]
        self.assertEqual("rcm-pr07-" + "a" * 32, command.pipe_name)
        helper.assert_called_once_with(command, applier=applier)

    def test_module_main_rejects_launcher_for_local_admin_helper(self) -> None:
        from rcm.__main__ import main

        with self.assertRaisesRegex(ValueError, "local admin helper"):
            main(
                mock.Mock(),
                argv=("--rcm-local-admin-helper",),
            )

    def test_module_main_rejects_unknown_arguments_without_legacy_import(
        self,
    ) -> None:
        from rcm.__main__ import main

        with self.assertRaisesRegex(ValueError, "unsupported arguments"):
            main(argv=("--unknown",))
        self.assertNotIn("ray_monitor", sys.modules)

    def test_foundation_check_validates_bundle_without_side_effects(self) -> None:
        from rcm.foundation_check import foundation_report

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lhm").mkdir()
            records: list[dict[str, object]] = []
            for index in range(10):
                payload = f"synthetic-vendor-{index}".encode("ascii")
                name = f"item-{index}.bin"
                path = root / "lhm" / name
                path.write_bytes(payload)
                records.append(
                    {
                        "source_name": name,
                        "destination": f"lhm/{name}",
                        "kind": "library" if index < 9 else "license",
                        "size": len(payload),
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
            metadata = root / "build-metadata"
            metadata.mkdir()
            (metadata / "vendor-data.json").write_text(
                json.dumps(
                    {"schema_version": 1, "files": records},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            (root / "THIRD_PARTY_NOTICES.md").write_text(
                "Synthetic notice\n",
                encoding="utf-8",
            )
            with mock.patch(
                "rcm.foundation_check._display_facts",
                return_value={"width": 1920, "height": 1080, "dpi": 120},
            ):
                report = foundation_report(
                    resource_root=root,
                    verify_runtime_imports=False,
                )
        self.assertEqual(10, report["vendor_files"])
        self.assertEqual(0, report["network_connections"])
        self.assertEqual(0, report["child_processes"])
        self.assertEqual(
            {
                "socket_attempts": 0,
                "subprocess_attempts": 0,
                "os_system_attempts": 0,
                "startfile_attempts": 0,
            },
            report["denied_side_effect_attempts"],
        )

    def test_launcher_result_must_be_an_exit_code(self) -> None:
        for result in (True, "0", object()):
            with self.subTest(result=result):
                with self.assertRaises(TypeError):
                    run_launcher(lambda: result)


if __name__ == "__main__":
    unittest.main()
