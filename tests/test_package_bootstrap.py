from __future__ import annotations

import importlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import socket
import subprocess
import sys
import tempfile
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
from rcm.paths import (
    KnownFolders,
    absolute_local_path,
    join_relative,
    safe_relative_path,
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
            self.assertEqual("2.8.2a1", package.__version__)
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
        self.assertEqual(2, len(plan.directories))

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
