from __future__ import annotations

from collections.abc import Callable
import ctypes
import inspect
import os
from types import SimpleNamespace
from unittest import mock
import unittest

from rcm.adapters import windows_desktop
from rcm.adapters.windows_desktop import (
    ExactOwnedFallback,
    TkDesktopHost,
    WindowsAutostart,
)
from rcm.app import (
    Application,
    ApplicationPorts,
    EXIT_DUPLICATE,
    EXIT_OK,
    EXIT_RESTART,
    main as app_main,
    unavailable_command_handler,
)
from rcm.desktop import (
    DesktopLifecycle,
    DesktopPhase,
    LifecycleAction,
    LifecycleScenario,
    SingletonLease,
    lifecycle_scenario_commands,
)
from rcm.identity import DeploymentKind, identity_for
from rcm.runtime import RuntimeCoordinator, RuntimeUnit
from rcm.ui.scheduler import BoundedEventQueue, PostStatus, UiScheduler
from rcm.ui.state import CommandKind, RenderState, UiCommand, UiVisibility


class FakeHost:
    def __init__(self) -> None:
        self.callbacks: dict[int, tuple[int, Callable[[], None]]] = {}
        self.delays: list[int] = []
        self.cancelled: list[int] = []
        self.rendered: list[RenderState] = []
        self.visibility: list[UiVisibility] = []
        self.command: Callable[[UiCommand], None] | None = None
        self.lifecycle_actions: list[LifecycleAction] = []
        self.run_action: Callable[[], None] | None = None
        self.quit_called = False
        self.disposed = False
        self._token = 0
        self._clock_ms = 0

    def bind(self, command: Callable[[UiCommand], None]) -> None:
        self.command = command

    def lifecycle_action(self, action: LifecycleAction) -> None:
        if not isinstance(action, LifecycleAction):
            raise TypeError("action must be a LifecycleAction")
        self.lifecycle_actions.append(action)
        kind = {
            LifecycleAction.WINDOW_CLOSE: CommandKind.HIDE,
            LifecycleAction.TRAY_SHOW: CommandKind.SHOW,
            LifecycleAction.TRAY_QUIT: CommandKind.QUIT,
        }[action]
        self.command(UiCommand(len(self.lifecycle_actions), kind))

    def render(self, state: RenderState) -> None:
        self.rendered.append(state)

    def set_visibility(self, visibility: UiVisibility) -> None:
        self.visibility.append(visibility)

    def call_later(self, delay_ms: int, callback: Callable[[], None]) -> object:
        self._token += 1
        self.callbacks[self._token] = (self._clock_ms + delay_ms, callback)
        self.delays.append(delay_ms)
        return self._token

    def cancel(self, token: object) -> None:
        value = int(token)
        self.callbacks.pop(value, None)
        self.cancelled.append(value)

    def run_next(self) -> None:
        token = min(
            self.callbacks,
            key=lambda item: (self.callbacks[item][0], item),
        )
        due, callback = self.callbacks.pop(token)
        self._clock_ms = due
        callback()

    def run(self) -> int:
        if self.run_action is not None:
            self.run_action()
        return 0

    def quit(self) -> None:
        self.quit_called = True

    def dispose(self) -> None:
        self.disposed = True


class FakeSingleton:
    def __init__(self, *, duplicate: bool = False) -> None:
        self.duplicate = duplicate
        self.releases = 0

    def acquire(self, identity: object) -> SingletonLease | None:
        if self.duplicate:
            return None
        return SingletonLease("synthetic", self._release)

    def _release(self) -> None:
        self.releases += 1


class FakeComponent:
    def __init__(self, *, resolves: bool = True) -> None:
        self.resolves = resolves
        self.events: list[str] = []

    def start(self, cancellation: object) -> None:
        self.events.append("start")

    def stop(self, timeout_seconds: float) -> None:
        self.events.append("stop")

    def join(self, timeout_seconds: float) -> bool:
        self.events.append("join")
        return self.resolves


class FakeFallback:
    def __init__(self, component: FakeComponent | None = None) -> None:
        self.component = component
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def terminate_owned(
        self,
        names: tuple[str, ...],
        timeout_seconds: float,
    ) -> bool:
        self.calls.append((names, timeout_seconds))
        if self.component is not None:
            self.component.resolves = True
        return True

    __call__ = terminate_owned


class DesktopTests(unittest.TestCase):
    def test_tk_host_exposes_only_the_two_local_admin_apply_intents(
        self,
    ) -> None:
        source = inspect.getsource(TkDesktopHost._build)
        self.assertEqual(1, source.count("CommandKind.APPLY_RDP_HOST"))
        self.assertEqual(
            1,
            source.count("CommandKind.APPLY_PRIVATE_FIREWALL"),
        )
        self.assertIn('(("enabled", True), ("require_nla", True))', source)
        self.assertIn('(("enabled", True),)', source)

    def test_tk_host_construction_is_lazy_and_disposable_without_tk(self) -> None:
        tray_factory = mock.Mock(
            side_effect=AssertionError("tray factory must remain lazy")
        )
        tkinter_loaded = "tkinter" in __import__("sys").modules
        host = TkDesktopHost(tray_factory=tray_factory)
        host.dispose()
        tray_factory.assert_not_called()
        self.assertEqual(
            tkinter_loaded,
            "tkinter" in __import__("sys").modules,
        )

    def test_tk_host_tray_title_uses_stable_ascii_separator(self) -> None:
        host = object.__new__(TkDesktopHost)
        host._guard = SimpleNamespace(assert_current=lambda: None)
        host._ensure_initialized = mock.Mock()
        host._main_view = SimpleNamespace(
            render=lambda _state: SimpleNamespace(
                title="Ray Cluster Manager",
                status="Ready",
                node_lines=(),
            )
        )
        host._title = mock.Mock()
        host._status = mock.Mock()
        host._nodes = mock.Mock()
        host._tray = mock.Mock()
        host._sync_dialogs = mock.Mock()

        host.render(RenderState())

        host._tray.set_title.assert_called_once_with(
            "Ray Cluster Manager - Ready"
        )

    def test_tk_host_lifecycle_actions_use_exact_existing_callbacks(self) -> None:
        host = object.__new__(TkDesktopHost)
        assert_current = mock.Mock()
        host._guard = SimpleNamespace(assert_current=assert_current)
        host._ensure_initialized = mock.Mock()
        host._request_hide = mock.Mock()
        host._tray_show = mock.Mock()
        host._tray_quit = mock.Mock()

        for action in LifecycleAction:
            host.lifecycle_action(action)

        self.assertEqual(3, assert_current.call_count)
        self.assertEqual(3, host._ensure_initialized.call_count)
        host._request_hide.assert_called_once_with()
        host._tray_show.assert_called_once_with()
        host._tray_quit.assert_called_once_with()

    def test_windows_mutex_duplicate_and_release_are_exact(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows adapter contract")
        created: list[str] = []
        closed: list[int] = []

        class Function:
            argtypes = None
            restype = None

            def __init__(self, callback: Callable[..., object]) -> None:
                self.callback = callback

            def __call__(self, *args: object) -> object:
                return self.callback(*args)

        kernel = SimpleNamespace(
            CreateMutexW=Function(
                lambda _security, _owner, name: created.append(name) or 101
            ),
            CloseHandle=Function(
                lambda handle: closed.append(int(handle)) or True
            ),
        )
        with (
            mock.patch.object(ctypes, "WinDLL", return_value=kernel),
            mock.patch.object(ctypes, "set_last_error"),
            mock.patch.object(ctypes, "get_last_error", return_value=0),
        ):
            lease = windows_desktop._acquire_windows_mutex("synthetic")
            self.assertIsNotNone(lease)
            lease.release()
            lease.release()
        self.assertEqual(["synthetic"], created)
        self.assertEqual([101], closed)

        closed.clear()
        with (
            mock.patch.object(ctypes, "WinDLL", return_value=kernel),
            mock.patch.object(ctypes, "set_last_error"),
            mock.patch.object(ctypes, "get_last_error", return_value=183),
        ):
            self.assertIsNone(
                windows_desktop._acquire_windows_mutex("synthetic")
            )
        self.assertEqual([101], closed)

    def test_autostart_uses_one_current_user_value(self) -> None:
        values: dict[str, str] = {}

        class Key:
            def __enter__(self) -> Key:
                return self

            def __exit__(self, *_args: object) -> bool:
                return False

        def query(_key: object, name: str) -> tuple[str, int]:
            try:
                return values[name], 1
            except KeyError:
                raise FileNotFoundError(name) from None

        def delete(_key: object, name: str) -> None:
            try:
                values.pop(name)
            except KeyError:
                raise FileNotFoundError(name) from None

        fake = SimpleNamespace(
            HKEY_CURRENT_USER=object(),
            REG_SZ=1,
            KEY_QUERY_VALUE=2,
            KEY_SET_VALUE=4,
            OpenKey=lambda *_args, **_kwargs: Key(),
            CreateKeyEx=lambda *_args, **_kwargs: Key(),
            QueryValueEx=query,
            SetValueEx=lambda _key, name, _zero, _kind, value: values.__setitem__(
                name, value
            ),
            DeleteValue=delete,
        )
        identity = identity_for(DeploymentKind.DEVELOPMENT)
        adapter = WindowsAutostart()
        with mock.patch.dict("sys.modules", {"winreg": fake}):
            self.assertFalse(adapter.enabled(identity))
            adapter.set_enabled(
                identity,
                enabled=True,
                executable=r"C:\Synthetic\RayClusterManager.exe",
            )
            self.assertTrue(adapter.enabled(identity))
            self.assertEqual(
                '"C:\\Synthetic\\RayClusterManager.exe" --start-minimized',
                values[identity.config_namespace],
            )
            adapter.set_enabled(
                identity,
                enabled=False,
                executable=r"C:\Synthetic\RayClusterManager.exe",
            )
            self.assertFalse(adapter.enabled(identity))

    def test_exact_fallback_rejects_broad_or_duplicate_identity(self) -> None:
        calls: list[tuple[tuple[str, ...], float]] = []
        fallback = ExactOwnedFallback(
            lambda names, timeout: calls.append((names, timeout)) or True
        )
        self.assertTrue(fallback.terminate_owned((), 1.0))
        self.assertEqual([], calls)
        with self.assertRaises(ValueError):
            fallback.terminate_owned(("worker", "worker"), 1.0)
        self.assertTrue(fallback.terminate_owned(("worker",), 0.25))
        self.assertEqual([(("worker",), 0.25)], calls)

    def test_bounded_queue_coalesces_snapshots_and_fails_full(self) -> None:
        queue: BoundedEventQueue[str] = BoundedEventQueue(2)
        self.assertIs(PostStatus.ADDED, queue.post("old", coalesce_key="snapshot"))
        self.assertIs(
            PostStatus.COALESCED,
            queue.post("new", coalesce_key="snapshot"),
        )
        self.assertIs(PostStatus.ADDED, queue.post("result"))
        self.assertIs(PostStatus.FULL, queue.post("overflow"))
        self.assertEqual(("new", "result"), queue.drain())
        self.assertEqual(1, queue.dropped)

    def test_hidden_scheduler_converges_to_no_pending_timer(self) -> None:
        host = FakeHost()
        consumed: list[str] = []
        scheduler = UiScheduler(port=host, consume=consumed.append)
        scheduler.set_visibility(UiVisibility.HIDDEN)
        scheduler.start()
        self.assertEqual(0, len(host.callbacks))
        scheduler.post("snapshot", coalesce_key="snapshot")
        self.assertEqual(1, len(host.callbacks))
        host.run_next()
        self.assertEqual(["snapshot"], consumed)
        self.assertEqual(0, len(host.callbacks))
        scheduler.set_visibility(UiVisibility.VISIBLE)
        self.assertEqual(1, len(host.callbacks))
        scheduler.stop()
        self.assertEqual(0, len(host.callbacks))

    def test_desktop_lifecycle_accepts_only_defined_transitions(self) -> None:
        lifecycle = DesktopLifecycle()
        lifecycle.begin_acquire()
        lifecycle.begin_start()
        lifecycle.running(visibility=UiVisibility.VISIBLE)
        lifecycle.set_visibility(UiVisibility.HIDDEN)
        lifecycle.request_restart()
        lifecycle.begin_shutdown()
        lifecycle.shutdown_complete()
        snapshot = lifecycle.snapshot()
        self.assertIs(DesktopPhase.STOPPED, snapshot.phase)
        self.assertTrue(snapshot.restart_requested)
        self.assertTrue(snapshot.graceful_complete)
        with self.assertRaises(RuntimeError):
            lifecycle.begin_start()

    def test_lifecycle_scenarios_are_typed_and_exact(self) -> None:
        self.assertEqual(
            (1_000,),
            tuple(
                item.delay_ms
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.VISIBLE_QUIT
                )
            ),
        )
        self.assertEqual(
            (LifecycleAction.TRAY_QUIT,),
            tuple(
                item.action
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.VISIBLE_QUIT
                )
            ),
        )
        self.assertEqual(
            (
                LifecycleAction.WINDOW_CLOSE,
                LifecycleAction.TRAY_SHOW,
                LifecycleAction.TRAY_QUIT,
            ),
            tuple(
                item.action
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.CLOSE_SHOW_QUIT
                )
            ),
        )
        self.assertEqual(
            (250, 1_000, 1_750),
            tuple(
                item.delay_ms
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.CLOSE_SHOW_QUIT
                )
            ),
        )
        self.assertEqual(
            (LifecycleAction.TRAY_SHOW, LifecycleAction.TRAY_QUIT),
            tuple(
                item.action
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.MINIMIZED_SHOW_QUIT
                )
            ),
        )
        self.assertEqual(
            (1_000, 1_750),
            tuple(
                item.delay_ms
                for item in lifecycle_scenario_commands(
                    LifecycleScenario.MINIMIZED_SHOW_QUIT
                )
            ),
        )

    def test_application_gracefully_starts_and_stops_exact_units(self) -> None:
        host = FakeHost()
        singleton = FakeSingleton()
        component = FakeComponent()
        runtime = RuntimeCoordinator((RuntimeUnit("monitor", component),))
        application = Application(
            ApplicationPorts(
                identity_for(DeploymentKind.DEVELOPMENT),
                host,
                singleton,
                runtime,
                unavailable_command_handler,
            )
        )
        self.assertEqual(EXIT_OK, application.run())
        self.assertEqual(["start", "stop", "join"], component.events)
        self.assertEqual(1, singleton.releases)
        self.assertTrue(host.disposed)
        self.assertIs(DesktopPhase.STOPPED, application.lifecycle.snapshot().phase)

    def test_duplicate_instance_does_not_start_runtime(self) -> None:
        host = FakeHost()
        runtime = RuntimeCoordinator(())
        application = Application(
            ApplicationPorts(
                identity_for(DeploymentKind.INSTALLED),
                host,
                FakeSingleton(duplicate=True),
                runtime,
                unavailable_command_handler,
            )
        )
        self.assertEqual(EXIT_DUPLICATE, application.run())
        self.assertTrue(host.disposed)
        self.assertEqual((), runtime.snapshot().active)

    def test_restart_is_state_only_and_returns_supervisor_exit_code(self) -> None:
        host = FakeHost()
        host.run_action = lambda: host.command(
            UiCommand(1, CommandKind.RESTART)
        )
        application = Application(
            ApplicationPorts(
                identity_for(DeploymentKind.DEVELOPMENT),
                host,
                FakeSingleton(),
                RuntimeCoordinator(()),
                unavailable_command_handler,
            )
        )
        self.assertEqual(EXIT_RESTART, application.run())
        self.assertTrue(host.quit_called)
        self.assertTrue(application.lifecycle.snapshot().restart_requested)

    def test_packaged_lifecycle_scenario_uses_exact_host_actions(self) -> None:
        host = FakeHost()

        def drive() -> None:
            for _index in range(20):
                if host.quit_called:
                    return
                host.run_next()
            raise AssertionError("lifecycle scenario did not terminate")

        host.run_action = drive
        application = Application(
            ApplicationPorts(
                identity_for(DeploymentKind.DEVELOPMENT),
                host,
                FakeSingleton(),
                RuntimeCoordinator(()),
                unavailable_command_handler,
            )
        )
        self.assertEqual(
            EXIT_OK,
            application.run(
                lifecycle_scenario=LifecycleScenario.CLOSE_SHOW_QUIT
            ),
        )
        self.assertIn(UiVisibility.HIDDEN, host.visibility)
        self.assertGreaterEqual(host.visibility.count(UiVisibility.VISIBLE), 2)
        self.assertTrue(host.quit_called)
        self.assertEqual(
            [
                LifecycleAction.WINDOW_CLOSE,
                LifecycleAction.TRAY_SHOW,
                LifecycleAction.TRAY_QUIT,
            ],
            host.lifecycle_actions,
        )

    def test_lifecycle_composition_avoids_live_config_and_admin_ports(
        self,
    ) -> None:
        with (
            mock.patch("rcm.app.Application") as application,
            mock.patch(
                "rcm.adapters.windows_desktop.WindowsAutostart"
            ) as autostart,
            mock.patch(
                "rcm.adapters.windows_admin.WindowsAdminObserver"
            ) as admin_observer,
            mock.patch(
                "rcm.adapters.windows_broker.WindowsOneShotBroker"
            ) as broker,
            mock.patch("rcm.local_admin.LocalAdminService") as local_admin,
        ):
            application.return_value.run.return_value = EXIT_OK
            self.assertEqual(
                EXIT_OK,
                app_main(
                    lifecycle_scenario=LifecycleScenario.VISIBLE_QUIT
                ),
            )
        autostart.return_value.enabled.assert_not_called()
        admin_observer.assert_not_called()
        broker.assert_not_called()
        local_admin.assert_not_called()
        ports = application.call_args.args[0]
        self.assertIs(unavailable_command_handler, ports.command_handler)
        self.assertFalse(
            application.call_args.kwargs[
                "initial_state"
            ].settings.autostart
        )

    def test_bounded_fallback_receives_only_owned_component_names(self) -> None:
        host = FakeHost()
        component = FakeComponent(resolves=False)
        fallback = FakeFallback(component)
        runtime = RuntimeCoordinator((RuntimeUnit("owned-worker", component),))
        application = Application(
            ApplicationPorts(
                identity_for(DeploymentKind.DEVELOPMENT),
                host,
                FakeSingleton(),
                runtime,
                unavailable_command_handler,
                fallback,
            ),
            shutdown_timeout_seconds=0,
            fallback_timeout_seconds=0.25,
        )
        self.assertEqual(EXIT_OK, application.run())
        self.assertEqual([(("owned-worker",), 0.25)], fallback.calls)
        self.assertEqual((), runtime.snapshot().active)
        snapshot = application.lifecycle.snapshot()
        self.assertTrue(snapshot.fallback_used)
        self.assertIs(DesktopPhase.STOPPED, snapshot.phase)


if __name__ == "__main__":
    unittest.main()
