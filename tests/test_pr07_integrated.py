from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from fake_test_kit.desktop import FakeDesktopHost, FakeShutdownFallback, FakeSingleton
from fake_test_kit.guard import NoLiveAccessGuard
from fake_test_kit.privilege import FakePrivilegeBoundary
from rcm.app import main as run_desktop
from rcm.app import render_state_from_config
from rcm.adapters.windows import compose_local_ray, compose_native_rdp
from rcm.bootstrap import BootstrapRequest, Environment, plan_bootstrap
from rcm.config.store import ConfigConflictError, ConfigStore, StoredConfig
from rcm.paths import KnownFolders
from rcm.setup import (
    _configuration_form_result,
    configure_local_node,
    host_bootstrap_plan,
    initialize_runtime_config,
)
from rcm.config.schema import (
    Node,
    NodesSection,
    config_checksum,
    default_config,
)
from rcm.local_admin import LocalAdminService
from rcm.rdp import RdpLaunchReceipt, RdpService
from rcm.runtime import RuntimeCoordinator
from rcm.ui.app import LocalAdminCommandHandler, RdpCommandHandler, UiApplication
from rcm.ui.state import (
    CommandKind,
    CommandResult,
    ResultStatus,
    Surface,
    UiCommand,
    UiVisibility,
)


class IntegratedHost:
    def __init__(self) -> None:
        self.command: Callable[[UiCommand], None] | None = None
        self.callbacks: dict[int, Callable[[], None]] = {}
        self.rendered = []
        self.visibility = []
        self._token = 0

    def bind(self, command: Callable[[UiCommand], None]) -> None:
        self.command = command

    def render(self, state: object) -> None:
        self.rendered.append(state)

    def set_visibility(self, visibility: UiVisibility) -> None:
        self.visibility.append(visibility)

    def call_later(self, delay_ms: int, callback: Callable[[], None]) -> object:
        self._token += 1
        self.callbacks[self._token] = callback
        return self._token

    def cancel(self, token: object) -> None:
        self.callbacks.pop(int(token), None)

    def run_next(self) -> None:
        token = min(self.callbacks)
        self.callbacks.pop(token)()

    def run(self) -> int:
        return 0

    def quit(self) -> None:
        return None

    def dispose(self) -> None:
        return None


class IntegratedUiTests(unittest.TestCase):
    def test_production_rdp_composition_is_prompt_only_and_runtime_owned(
        self,
    ) -> None:
        class Filesystem:
            def __init__(self) -> None:
                self.files: dict[str, bytes] = {}

            def write_bytes(self, path: str, data: bytes) -> None:
                if path in self.files:
                    raise FileExistsError(path)
                self.files[path] = data

            def unlink(self, path: str, *, missing_ok: bool = False) -> None:
                if path not in self.files and not missing_ok:
                    raise FileNotFoundError(path)
                self.files.pop(path, None)

            def listdir(self, _path: str) -> tuple[str, ...]:
                return tuple(Path(path).name for path in self.files)

        filesystem = Filesystem()
        process = SimpleNamespace(
            pid=41_102,
            terminate=mock.Mock(side_effect=AssertionError("must not terminate")),
            kill=mock.Mock(side_effect=AssertionError("must not kill")),
            wait=mock.Mock(side_effect=AssertionError("must not wait")),
        )
        fallbacks: list[UiCommand] = []
        directory = r"C:\Synthetic\Rdp"
        with (
            mock.patch(
                "rcm.adapters.windows.LocalRdpFilesystem",
                return_value=filesystem,
            ),
            mock.patch("rcm.setup._assert_local_metadata_root"),
        ):
            rdp_handler, runtime = compose_native_rdp(
                directory,
                lambda command: fallbacks.append(command),
            )
            handler = compose_local_ray(default_config(), rdp_handler)
            with (
                mock.patch(
                    "rcm.adapters.windows.WindowsRdpLauncher._mstsc_path",
                    return_value=r"C:\Synthetic\System32\mstsc.exe",
                ),
                mock.patch("sys.platform", "win32"),
                mock.patch("subprocess.Popen", return_value=process) as launch,
                mock.patch(
                    "rcm.adapters.windows_credentials.WindowsCredentialStore.contains",
                    side_effect=AssertionError("credential lookup is forbidden"),
                ) as contains,
                mock.patch(
                    "rcm.adapters.windows_credentials.WindowsCredentialStore.resolve",
                    side_effect=AssertionError("credential lookup is forbidden"),
                ) as resolve,
            ):
                started = runtime.start()
                result = handler(UiCommand(
                    1,
                    CommandKind.OPEN_RDP,
                    (
                        ("address", "192.0.2.20"),
                        ("principal", r"SYNTHETIC\operator"),
                        ("port", 3_389),
                        ("redirect_clipboard", False),
                    ),
                ))
                artifacts = tuple(filesystem.files)
                self.assertEqual("running", started.state)
                self.assertEqual("rdp_opened", result.code)
                self.assertEqual(1, len(artifacts))
                raw = filesystem.files[artifacts[0]]
                decoded = raw.decode("utf-16")
                self.assertIn("prompt for credentials:i:1", decoded)
                self.assertIn("authentication level:i:2", decoded)
                self.assertIn("enablecredsspsupport:i:1", decoded)
                self.assertIn("redirectclipboard:i:0", decoded)
                self.assertNotIn("password", decoded.casefold())
                self.assertNotIn("credential_reference", decoded.casefold())
                launched_argv = launch.call_args.args[0]
                self.assertEqual(
                    r"C:\Synthetic\System32\mstsc.exe",
                    launched_argv[0],
                )
                self.assertEqual(artifacts[0], launched_argv[1])
                self.assertTrue(launch.call_args.kwargs["close_fds"])

                stopped = runtime.stop()

            self.assertEqual("stopped", stopped.state)
            self.assertEqual({}, filesystem.files)
        self.assertEqual([], fallbacks)
        contains.assert_not_called()
        resolve.assert_not_called()
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()

    def test_rdp_command_handler_launches_only_password_free_typed_request(
        self,
    ) -> None:
        class Credentials:
            def contains(self, _reference: object) -> bool:
                raise AssertionError("credential lookup is not expected")

            def resolve(self, _reference: object) -> object:
                raise AssertionError("credential lookup is not expected")

        class Launcher:
            def __init__(self) -> None:
                self.plans = []

            def capability(self) -> object:
                return object()

            def launch(self, plan: object) -> RdpLaunchReceipt:
                self.plans.append(plan)
                return RdpLaunchReceipt(41_101, r"C:\Synthetic\owned.rdp")

            def cleanup(self, _receipt: object) -> None:
                return None

            def cleanup_all(self) -> None:
                return None

        launcher = Launcher()
        service = RdpService(
            credentials=Credentials(),
            launcher=launcher,
            token_factory=lambda: "1" * 32,
        )
        fallbacks: list[UiCommand] = []
        handler = RdpCommandHandler(
            service,
            fallback=lambda command: fallbacks.append(command),
        )

        result = handler(UiCommand(
            1,
            CommandKind.OPEN_RDP,
            (
                ("address", "worker.example"),
                ("principal", ""),
                ("port", 3_390),
                ("redirect_clipboard", True),
            ),
        ))
        handler(UiCommand(2, CommandKind.START))

        self.assertEqual("rdp_opened", result.code)
        self.assertEqual([], [
            field for field in UiCommand.__dataclass_fields__
            if "password" in field
        ])
        self.assertEqual("worker.example:3390", launcher.plans[0].target)
        self.assertTrue(launcher.plans[0].redirect_clipboard)
        self.assertEqual([CommandKind.START], [item.kind for item in fallbacks])

    def test_node_selection_updates_rdp_default_without_service_call(self) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (
                    Node("head", "192.0.2.10", "head"),
                    Node("worker", "192.0.2.20", "worker"),
                ),
                "head",
            ),
        )
        host = IntegratedHost()
        handled: list[UiCommand] = []
        ui = UiApplication(
            host=host,
            command_handler=lambda command: handled.append(command),
            quit_handler=lambda _restart: None,
            initial_state=render_state_from_config(config),
        )
        ui.start()

        host.command(UiCommand(
            1,
            CommandKind.SELECT_NODE,
            (("node_id", "worker"),),
        ))

        self.assertEqual("worker", ui.state.selected_node_id)
        selected = next(
            node for node in ui.state.nodes
            if node.node_id == ui.state.selected_node_id
        )
        self.assertEqual("192.0.2.20", selected.address)
        self.assertEqual([], handled)
        ui.stop()

    def test_disabled_elevation_is_reported_as_secure_packaging_required(
        self,
    ) -> None:
        observer, broker = mock.Mock(), mock.Mock()
        handler = LocalAdminCommandHandler(
            LocalAdminService(observer=observer, broker=broker),
            fallback=lambda _command: None,
        )
        with NoLiveAccessGuard():
            rdp_result = handler(UiCommand(
                1, CommandKind.APPLY_RDP_HOST, (("enabled", True),)))
            firewall_result = handler(UiCommand(
                2, CommandKind.APPLY_PRIVATE_FIREWALL, (("enabled", True),)))
        for result in (rdp_result, firewall_result):
            self.assertEqual("local_admin_unavailable", result.code)
            self.assertIn("Secure administrator packaging", result.message)
        observer.assert_not_called()
        broker.assert_not_called()
        observer.rdp_host_state.assert_not_called()
        observer.private_firewall_state.assert_not_called()
        broker.apply.assert_not_called()

    def test_admin_observation_exception_triggers_typed_rollback(self) -> None:
        boundary = FakePrivilegeBoundary()
        identifiers = iter((f"{value:032x}" for value in range(1, 3)))
        service = LocalAdminService(
            observer=boundary,
            broker=boundary,
            request_id_factory=lambda: next(identifiers),
        )
        handler = LocalAdminCommandHandler(
            service,
            fallback=lambda _command: None,
        )
        with (
            NoLiveAccessGuard() as guard,
            mock.patch(
                "rcm.ui.app.LOCAL_ADMIN_ELEVATION_ENABLED",
                True,
            ),
            mock.patch.object(
                service,
                "verify",
                side_effect=(RuntimeError("synthetic"), True),
            ),
        ):
            result = handler(
                UiCommand(
                    1,
                    CommandKind.APPLY_RDP_HOST,
                    (("enabled", True),),
                )
            )

        self.assertEqual([], guard.violations)
        self.assertEqual("local_admin_verify_rolled_back", result.code)
        self.assertFalse(boundary.rdp.enabled)
        self.assertEqual(2, len(boundary.events))

    def test_desktop_composition_constructs_admin_boundary_without_using_it(
        self,
    ) -> None:
        boundary = FakePrivilegeBoundary()
        host = FakeDesktopHost()
        rdp_runtime = RuntimeCoordinator(())
        rdp_composer = mock.Mock(return_value=(mock.Mock(), rdp_runtime))
        with (
            mock.patch(
                "rcm.adapters.windows_desktop.TkDesktopHost",
                return_value=host,
            ),
            mock.patch(
                "rcm.adapters.windows_desktop.WindowsAutostart",
                return_value=mock.Mock(enabled=lambda _identity: False),
            ),
            mock.patch(
                "rcm.adapters.windows_desktop.WindowsSingleton",
                side_effect=FakeSingleton,
            ),
            mock.patch(
                "rcm.adapters.windows_desktop.ExactOwnedFallback",
                return_value=FakeShutdownFallback(),
            ),
            mock.patch(
                "rcm.adapters.windows_admin.WindowsAdminObserver",
                return_value=boundary,
            ),
            mock.patch(
                "rcm.adapters.windows_broker.WindowsOneShotBroker",
                return_value=boundary,
            ),
            mock.patch(
                "rcm.setup.host_bootstrap_plan",
                return_value=SimpleNamespace(
                    paths=SimpleNamespace(
                        rdp_directory=r"C:\Synthetic\Rdp"
                    )
                ),
            ),
            mock.patch(
                "rcm.setup.initialize_runtime_config",
                return_value=mock.Mock(config=default_config()),
            ),
            mock.patch(
                "rcm.adapters.windows.compose_native_rdp",
                rdp_composer,
            ),
            NoLiveAccessGuard() as guard,
        ):
            result = run_desktop()

        self.assertEqual(0, result)
        self.assertEqual([], guard.violations)
        self.assertEqual([], boundary.events)
        rdp_composer.assert_called_once()

    def test_first_launch_persists_defaults_and_reuses_valid_config(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rcm-config-startup-") as temporary:
            root = Path(temporary).resolve()
            local_app_data = root / "local"
            local_app_data.mkdir()
            plan = plan_bootstrap(BootstrapRequest(
                environment=Environment({}),
                known_folders=KnownFolders(local_app_data=local_app_data),
                application_root=root / "app",
                resource_root=root / "resources",
                current_binary=root / "app" / "python.exe",
                frozen=False,
            ))
            first = initialize_runtime_config(plan)
            self.assertEqual(1, first.generation)
            self.assertTrue(Path(str(plan.paths.config_file)).is_file())
            self.assertTrue(Path(str(plan.paths.log_directory)).is_dir())

            configured = replace(
                first.config,
                nodes=NodesSection(
                    (Node("worker", "192.0.2.20", "worker"),),
                    "worker",
                ),
            )
            saved = ConfigStore(Path(str(plan.paths.config_file))).save(
                configured,
                expected_generation=first.generation,
            )
            second = initialize_runtime_config(plan)

        self.assertEqual(saved, second)
        self.assertEqual("worker", second.config.nodes.local_node_id)

    def test_first_launch_records_installed_and_portable_deployment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rcm-config-modes-") as temporary:
            root = Path(temporary).resolve()
            for values, expected in (
                ({}, "installed"),
                ({"RCM_PORTABLE": "1"}, "portable"),
            ):
                with self.subTest(expected=expected):
                    local_app_data = root / expected / "local"
                    local_app_data.mkdir(parents=True)
                    plan = plan_bootstrap(BootstrapRequest(
                        environment=Environment(values),
                        known_folders=KnownFolders(
                            local_app_data=local_app_data),
                        application_root=root / expected / "app",
                        resource_root=root / expected / "resources",
                        current_binary=root / expected / "app" / "rcm.exe",
                        frozen=True,
                    ))
                    stored = initialize_runtime_config(plan)
                    self.assertEqual(
                        expected,
                        stored.config.app.environment,
                    )

    def test_first_launch_conflict_reloads_strict_winner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rcm-config-race-") as temporary:
            root = Path(temporary).resolve()
            local_app_data = root / "local"
            local_app_data.mkdir()
            plan = plan_bootstrap(BootstrapRequest(
                environment=Environment({}),
                known_folders=KnownFolders(local_app_data=local_app_data),
                application_root=root / "app",
                resource_root=root / "resources",
                current_binary=root / "app" / "rcm.exe",
                frozen=True,
            ))
            initial = default_config()
            winner_config = replace(
                initial,
                app=replace(initial.app, environment="installed"),
            )
            empty = StoredConfig(initial, 0, config_checksum(initial))
            winner = StoredConfig(
                winner_config,
                1,
                config_checksum(winner_config),
            )
            store = mock.Mock()
            store.load.side_effect = (empty, winner)
            store.save.side_effect = ConfigConflictError("synthetic race")
            with mock.patch("rcm.setup.ConfigStore", return_value=store):
                observed = initialize_runtime_config(plan)
        self.assertEqual(winner, observed)
        self.assertEqual(2, store.load.call_count)

    def test_portable_host_plan_fails_closed_without_localappdata(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "per-user LocalAppData"):
                host_bootstrap_plan(
                    Environment({"RCM_PORTABLE": "1"}),
                    frozen=True,
                )

    def test_source_portable_plan_fails_closed_without_localappdata(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "per-user LocalAppData"):
                host_bootstrap_plan(
                    Environment({"RCM_PORTABLE": "1"}),
                    frozen=False,
                )

    def test_host_plan_rejects_mapped_local_metadata_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.dict(
                    "os.environ",
                    {"LOCALAPPDATA": temporary},
                    clear=True,
                ),
                mock.patch(
                    "rcm.setup._windows_drive_type",
                    return_value=4,
                ),
                mock.patch(
                    "rcm.setup._metadata_host_is_windows",
                    return_value=True,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "local application metadata is unavailable",
                ),
            ):
                host_bootstrap_plan(Environment(), frozen=False)

    def test_local_metadata_reparse_alias_is_rejected(self) -> None:
        directory = SimpleNamespace(
            st_mode=__import__("stat").S_IFDIR,
            st_file_attributes=0x400,
        )
        with (
            mock.patch(
                "rcm.setup._metadata_host_is_windows",
                return_value=True,
            ),
            mock.patch("rcm.setup._windows_drive_type", return_value=3),
            mock.patch("rcm.setup.os.stat", return_value=directory),
            self.assertRaisesRegex(
                RuntimeError,
                "local application metadata is unavailable",
            ),
        ):
            from rcm.setup import _assert_local_metadata_root

            _assert_local_metadata_root(Path(r"C:\Synthetic\LocalAppData"))

    def test_local_metadata_accepts_only_a_fixed_drive(self) -> None:
        from rcm.setup import _assert_local_metadata_root

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for drive_type in (0, 1, 2, 4, 5, 6):
                with (
                    self.subTest(drive_type=drive_type),
                    mock.patch(
                        "rcm.setup._metadata_host_is_windows",
                        return_value=True,
                    ),
                    mock.patch(
                        "rcm.setup._windows_drive_type",
                        return_value=drive_type,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError,
                        "local application metadata is unavailable",
                    ),
                ):
                    _assert_local_metadata_root(path)
            with (
                mock.patch(
                    "rcm.setup._metadata_host_is_windows",
                    return_value=True,
                ),
                mock.patch(
                    "rcm.setup._windows_drive_type",
                    return_value=3,
                ),
            ):
                _assert_local_metadata_root(path)

    def test_generated_rdp_child_reparse_is_rejected(self) -> None:
        regular = SimpleNamespace(
            st_mode=__import__("stat").S_IFDIR,
            st_file_attributes=0,
        )
        reparse = SimpleNamespace(
            st_mode=__import__("stat").S_IFDIR,
            st_file_attributes=0x400,
        )

        def inspect(path: object, *, follow_symlinks: bool) -> object:
            self.assertFalse(follow_symlinks)
            return reparse if str(path).casefold().endswith("rdp") else regular

        with (
            mock.patch(
                "rcm.setup._metadata_host_is_windows",
                return_value=True,
            ),
            mock.patch("rcm.setup._windows_drive_type", return_value=3),
            mock.patch("rcm.setup.os.stat", side_effect=inspect),
            self.assertRaisesRegex(
                RuntimeError,
                "local application metadata is unavailable",
            ),
        ):
            from rcm.setup import _assert_local_metadata_root

            _assert_local_metadata_root(
                Path(r"C:\Synthetic\LocalAppData\RayClusterManager\rdp")
            )

    def test_metadata_creation_validates_before_descending_into_namespace(
        self,
    ) -> None:
        from rcm.setup import _ensure_local_metadata_directory

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            namespace = root / "RayClusterManager"
            destination = namespace / "rdp"
            events: list[tuple[str, Path]] = []
            active: list[Path] = []

            @contextmanager
            def lock(path: Path) -> Iterator[None]:
                value = Path(path)
                events.append(("lock-enter", value))
                active.append(value)
                try:
                    yield
                finally:
                    self.assertEqual(value, active.pop())
                    events.append(("lock-exit", value))

            def create(
                path: Path,
                *,
                parents: bool,
                exist_ok: bool,
            ) -> None:
                self.assertFalse(parents)
                self.assertFalse(exist_ok)
                value = Path(path)
                self.assertIn(value.parent, active)
                events.append(("mkdir", value))

            with (
                mock.patch(
                    "rcm.setup._locked_local_metadata_directory",
                    side_effect=lock,
                ),
                mock.patch.object(Path, "mkdir", autospec=True, side_effect=create),
            ):
                _ensure_local_metadata_directory(destination, root)

        self.assertEqual(
            [
                ("lock-enter", root),
                ("mkdir", namespace),
                ("lock-enter", namespace),
                ("mkdir", destination),
                ("lock-enter", destination),
                ("lock-exit", destination),
                ("lock-exit", namespace),
                ("lock-exit", root),
            ],
            events,
        )

    def test_setup_fields_add_then_replace_only_the_local_node(self) -> None:
        original = replace(
            default_config(),
            nodes=NodesSection(
                (Node("remote", "192.0.2.50", "observer"),),
                "",
            ),
        )
        added = configure_local_node(
            original,
            node_id="local-a",
            address="192.0.2.20",
            role="worker",
            cpu_count=8,
            monitoring_enabled=True,
            start_minimized=False,
        )
        replaced_local = configure_local_node(
            added,
            node_id="local-b",
            address="192.0.2.21",
            role="head",
            cpu_count=0,
            monitoring_enabled=False,
            start_minimized=True,
        )

        self.assertEqual(
            ("remote", "local-b"),
            tuple(node.node_id for node in replaced_local.nodes.items),
        )
        self.assertEqual("local-b", replaced_local.nodes.local_node_id)
        self.assertFalse(replaced_local.monitoring.enabled)
        self.assertTrue(replaced_local.app.start_minimized)

    def test_setup_fields_reject_malformed_nodes(self) -> None:
        for node_id, address in (
            ("bad id", "192.0.2.20"),
            ("local-a", "host name"),
        ):
            with self.subTest(node_id=node_id, address=address):
                with self.assertRaises(ValueError):
                    configure_local_node(
                        default_config(),
                        node_id=node_id,
                        address=address,
                        role="worker",
                        cpu_count=0,
                        monitoring_enabled=True,
                        start_minimized=False,
                    )

    def test_setup_form_reports_cross_node_validation_conflicts(self) -> None:
        cases = (
            (
                NodesSection(
                    (Node("remote", "192.0.2.50", "observer"),),
                    "",
                ),
                {"node_id": "REMOTE", "role": "worker"},
            ),
            (
                NodesSection(
                    (Node("remote-head", "192.0.2.50", "head"),),
                    "",
                ),
                {"node_id": "local", "role": "head"},
            ),
        )
        for nodes, fields in cases:
            with self.subTest(fields=fields):
                configured, error = _configuration_form_result(
                    replace(default_config(), nodes=nodes),
                    node_id=fields["node_id"],
                    address="192.0.2.20",
                    role=fields["role"],
                    cpu_count="0",
                    monitoring_enabled=True,
                    start_minimized=False,
                )
                self.assertIsNone(configured)
                self.assertTrue(error)

    def test_two_local_admin_ui_intents_reach_only_the_fake_boundary(self) -> None:
        host = IntegratedHost()
        boundary = FakePrivilegeBoundary()
        identifiers = iter((f"{value:032x}" for value in range(1, 5)))
        service = LocalAdminService(
            observer=boundary,
            broker=boundary,
            request_id_factory=lambda: next(identifiers),
        )
        fallback_calls: list[UiCommand] = []
        handler = LocalAdminCommandHandler(
            service,
            fallback=lambda command: fallback_calls.append(command),
        )

        with (
            NoLiveAccessGuard() as guard,
            mock.patch(
                "rcm.ui.app.LOCAL_ADMIN_ELEVATION_ENABLED",
                True,
            ),
        ):
            ui = UiApplication(
                host=host,
                command_handler=handler,
                quit_handler=lambda _restart: None,
            )
            ui.start()
            self.assertEqual([], boundary.events)
            host.command(
                UiCommand(
                    1,
                    CommandKind.APPLY_RDP_HOST,
                    (("enabled", True), ("require_nla", True)),
                )
            )
            host.command(
                UiCommand(
                    2,
                    CommandKind.APPLY_PRIVATE_FIREWALL,
                    (("enabled", True),),
                )
            )
            ui.stop()

        self.assertEqual([], guard.violations)
        self.assertEqual([], fallback_calls)
        self.assertTrue(boundary.rdp.enabled)
        self.assertTrue(all(rule.value == "enabled" for rule in boundary.firewall.rules))
        self.assertEqual(
            ["rdp_host_apply", "private_firewall_apply"],
            [event[1] for event in boundary.events],
        )
        self.assertEqual(ResultStatus.SUCCEEDED, ui.state.last_result.status)

    def test_fake_only_ui_flow_has_no_live_access(self) -> None:
        config = replace(
            default_config(),
            nodes=NodesSection(
                (
                    Node("head", "192.0.2.10", "head"),
                    Node("worker", "192.0.2.20", "worker"),
                ),
                "head",
            ),
        )
        host = IntegratedHost()
        handled: list[UiCommand] = []
        quits: list[bool] = []

        def handler(command: UiCommand) -> CommandResult:
            handled.append(command)
            return CommandResult(
                command.command_id,
                ResultStatus.SUCCEEDED,
                "synthetic_complete",
                "Complete",
            )

        with NoLiveAccessGuard() as guard:
            ui = UiApplication(
                host=host,
                command_handler=handler,
                quit_handler=quits.append,
                initial_state=render_state_from_config(config),
            )
            ui.start()
            host.command(
                UiCommand(
                    1,
                    CommandKind.OPEN_SURFACE,
                    (("surface", Surface.STATUS.value),),
                )
            )
            host.command(UiCommand(2, CommandKind.START))
            host.command(UiCommand(3, CommandKind.HIDE))
            self.assertEqual(0, len(host.callbacks))
            published = ui.state.evolve(status_message="Snapshot")
            ui.publish(published)
            self.assertEqual(1, len(host.callbacks))
            host.run_next()
            self.assertEqual(0, len(host.callbacks))
            host.command(UiCommand(4, CommandKind.SHOW))
            host.command(UiCommand(5, CommandKind.QUIT))
            ui.stop()

        self.assertEqual([], guard.violations)
        self.assertEqual([2], [command.command_id for command in handled])
        self.assertEqual([False], quits)
        self.assertIn(Surface.STATUS, host.rendered[1].open_surfaces)
        self.assertIn(UiVisibility.HIDDEN, host.visibility)
        self.assertEqual("Snapshot", host.rendered[-3].status_message)


if __name__ == "__main__":
    unittest.main()
