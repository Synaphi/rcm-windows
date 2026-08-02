"""Dependency-injected RCM 2.x desktop composition root."""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

from .config.schema import Config, default_config
from .desktop import (
    DesktopHost,
    DesktopLifecycle,
    DesktopPhase,
    LifecycleScenario,
    ShutdownFallback,
    SingletonLease,
    SingletonPort,
    lifecycle_scenario_commands,
)
from .identity import ApplicationIdentity
from .runtime import RuntimeCoordinator, RuntimeShutdownError
from .ui.app import CommandHandler, LocalAdminCommandHandler, UiApplication
from .ui.state import (
    CommandResult,
    LifecyclePhase,
    NodeRenderState,
    RenderState,
    ResultStatus,
    SettingsRenderState,
    UiCommand,
    UiVisibility,
)


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_DUPLICATE = 3
EXIT_RESTART = 75
@dataclass(frozen=True, slots=True)
class ApplicationPorts:
    identity: ApplicationIdentity
    host: DesktopHost
    singleton: SingletonPort
    runtime: RuntimeCoordinator
    command_handler: CommandHandler
    fallback: ShutdownFallback | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ApplicationIdentity):
            raise TypeError("identity must be an ApplicationIdentity")
        if not isinstance(self.runtime, RuntimeCoordinator):
            raise TypeError("runtime must be a RuntimeCoordinator")
        if not callable(self.command_handler):
            raise TypeError("command_handler must be callable")


class Application:
    def __init__(
        self,
        ports: ApplicationPorts,
        *,
        initial_state: RenderState = RenderState(),
        shutdown_timeout_seconds: float = 5.0,
        fallback_timeout_seconds: float = 2.0,
    ) -> None:
        if not isinstance(ports, ApplicationPorts):
            raise TypeError("ports must be ApplicationPorts")
        for name, value in (
            ("shutdown_timeout_seconds", shutdown_timeout_seconds),
            ("fallback_timeout_seconds", fallback_timeout_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError(f"{name} must be finite and non-negative")
        self._ports = ports
        self._initial = initial_state
        self._shutdown_timeout = float(shutdown_timeout_seconds)
        self._fallback_timeout = float(fallback_timeout_seconds)
        self._lifecycle = DesktopLifecycle()
        self._lease: SingletonLease | None = None
        self._ui: UiApplication | None = None
        self._restart = False
        self._forced = False

    @property
    def lifecycle(self) -> DesktopLifecycle:
        return self._lifecycle
    def run(
        self,
        *,
        start_minimized: bool = False,
        lifecycle_scenario: LifecycleScenario | None = None,
    ) -> int:
        if type(start_minimized) is not bool:
            raise TypeError("start_minimized must be a bool")
        if lifecycle_scenario is not None and not isinstance(
            lifecycle_scenario, LifecycleScenario
        ):
            raise TypeError("lifecycle_scenario must be typed")
        start_minimized |= (
            lifecycle_scenario is LifecycleScenario.MINIMIZED_SHOW_QUIT
        )
        self._lifecycle.begin_acquire()
        self._lease = self._ports.singleton.acquire(self._ports.identity)
        if self._lease is None:
            self._lifecycle.fail("duplicate_instance")
            self._ports.host.dispose()
            return EXIT_DUPLICATE
        result = EXIT_ERROR
        try:
            self._lifecycle.begin_start()
            self._ports.runtime.start()
            self._ui = UiApplication(
                host=self._ports.host,
                command_handler=self._ports.command_handler,
                quit_handler=self._request_exit,
                initial_state=self._initial.evolve(
                    lifecycle=LifecyclePhase.STARTING,
                ),
            )
            visibility = (
                UiVisibility.MINIMIZED
                if start_minimized
                else UiVisibility.VISIBLE
            )
            self._ui.start(start_minimized=start_minimized)
            for scheduled in lifecycle_scenario_commands(lifecycle_scenario):
                self._ports.host.call_later(
                    scheduled.delay_ms,
                    lambda action=scheduled.action: (
                        self._ports.host.lifecycle_action(action)
                    ),
                )
            self._lifecycle.running(visibility=visibility)
            host_result = self._ports.host.run()
            result = self._normalize_host_result(host_result)
        except Exception:
            self._lifecycle.fail("desktop_run_error")
            result = EXIT_ERROR
        finally:
            if not self._shutdown():
                result = EXIT_ERROR
        return EXIT_RESTART if self._restart and result == EXIT_OK else result
    def _request_exit(self, restart: bool) -> None:
        if type(restart) is not bool:
            raise TypeError("restart must be a bool")
        self._restart = restart
        if restart:
            self._lifecycle.request_restart()
        self._ports.host.quit()
    def _shutdown(self) -> bool:
        success = True
        phase = self._lifecycle.snapshot().phase
        if phase in {
            DesktopPhase.STARTING,
            DesktopPhase.RUNNING,
            DesktopPhase.RESTARTING,
        }:
            self._lifecycle.begin_shutdown()
        try:
            self._ports.runtime.stop(self._shutdown_timeout)
        except RuntimeShutdownError:
            active = self._ports.runtime.snapshot().active
            fallback = self._ports.fallback
            self._forced = bool(
                active
                and fallback is not None
                and fallback(active, self._fallback_timeout) is not False
            )
            success = self._forced
            if self._forced:
                try:
                    self._ports.runtime.stop(0)
                    success = not self._ports.runtime.snapshot().active
                except RuntimeShutdownError:
                    success = False
        except Exception:
            success = False
        try:
            if self._ui is not None:
                self._ui.stop(forced=self._forced)
            self._ports.host.dispose()
        except Exception:
            success = False
        try:
            if self._lease is not None:
                self._lease.release()
                self._lease = None
        except Exception:
            success = False
        current = self._lifecycle.snapshot().phase
        if current is DesktopPhase.STOPPING and success:
            self._lifecycle.shutdown_complete(fallback_used=self._forced)
        elif not success:
            self._lifecycle.fail("shutdown_failed")
        return success
    @staticmethod
    def _normalize_host_result(value: int | None) -> int:
        if value is None:
            return EXIT_OK
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("desktop host result must be an integer or None")
        return value
def render_state_from_config(
    config: Config,
    *,
    autostart: bool = False,
) -> RenderState:
    if not isinstance(config, Config):
        raise TypeError("config must be a Config")
    nodes = tuple(
        NodeRenderState(
            node.node_id,
            node.node_id,
            node.role,
            "configured" if node.enabled else "disabled",
        )
        for node in config.nodes.items
    )
    selected = nodes[0].node_id if nodes else ""
    return RenderState(
        nodes=nodes,
        selected_node_id=selected,
        settings=SettingsRenderState(
            config.ui.theme,
            config.ui.scale_percent,
            config.ui.compact_view,
            config.app.start_minimized,
            autostart,
            config.monitoring.interval_ms,
        ),
    )
def unavailable_command_handler(command: UiCommand) -> CommandResult:
    if not isinstance(command, UiCommand):
        raise TypeError("command must be a UiCommand")
    return CommandResult(
        command.command_id,
        ResultStatus.FAILED,
        "service_unavailable",
        "This operation is not configured.",
    )
def main(
    *,
    start_minimized: bool = False,
    lifecycle_scenario: LifecycleScenario | None = None,
) -> int:
    import os
    import sys

    from .adapters.windows_desktop import (
        ExactOwnedFallback,
        TkDesktopHost,
        WindowsAutostart,
        WindowsSingleton,
    )
    from .adapters.windows_admin import WindowsAdminObserver
    from .adapters.windows_broker import WindowsOneShotBroker
    from .bootstrap import Environment, select_deployment
    from .identity import identity_for, preview_validation_identity
    from .local_admin import LocalAdminService

    environment = Environment(
        {
            key: os.environ[key]
            for key in ("RCM_RUNTIME_MODE", "RCM_PORTABLE")
            if key in os.environ
        }
    )
    identity = (
        preview_validation_identity()
        if lifecycle_scenario is not None
        else identity_for(
            select_deployment(
                environment,
                frozen=bool(getattr(sys, "frozen", False)),
            )
        )
    )
    config = default_config()
    if lifecycle_scenario is not None:
        autostart = False
        command_handler = unavailable_command_handler
    else:
        autostart = WindowsAutostart().enabled(identity)
        local_admin = LocalAdminService(
            observer=WindowsAdminObserver(), broker=WindowsOneShotBroker())
        command_handler = LocalAdminCommandHandler(
            local_admin, fallback=unavailable_command_handler)
    ports = ApplicationPorts(
        identity=identity,
        host=TkDesktopHost(),
        singleton=WindowsSingleton(),
        runtime=RuntimeCoordinator(()),
        command_handler=command_handler,
        fallback=ExactOwnedFallback(lambda names, _timeout: not names),
    )
    return Application(
        ports,
        initial_state=render_state_from_config(config, autostart=autostart),
    ).run(
        start_minimized=start_minimized or config.app.start_minimized,
        lifecycle_scenario=lifecycle_scenario,
    )
