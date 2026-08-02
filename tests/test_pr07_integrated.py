from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import unittest
from unittest import mock

from fake_test_kit.desktop import FakeDesktopHost, FakeShutdownFallback, FakeSingleton
from fake_test_kit.guard import NoLiveAccessGuard
from fake_test_kit.privilege import FakePrivilegeBoundary
from rcm.app import main as run_desktop
from rcm.app import render_state_from_config
from rcm.config.schema import Node, NodesSection, default_config
from rcm.local_admin import LocalAdminService
from rcm.ui.app import LocalAdminCommandHandler, UiApplication
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
            NoLiveAccessGuard() as guard,
        ):
            result = run_desktop()

        self.assertEqual(0, result)
        self.assertEqual([], guard.violations)
        self.assertEqual([], boundary.events)

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
