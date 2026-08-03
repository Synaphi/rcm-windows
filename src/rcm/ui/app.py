"""UI-thread reducer and command dispatcher for the desktop presentation."""

from __future__ import annotations

from collections.abc import Callable

from ..core import RejectedError, UnavailableError, UnsupportedError
from ..desktop import DesktopHost, UiThreadGuard
from ..local_admin import LocalAdminService
from ..privilege import LOCAL_ADMIN_ELEVATION_ENABLED, PrivilegeStatus
from ..rdp import RdpRequest, RdpService
from .scheduler import PostStatus, UiScheduler
from .state import (
    CommandKind,
    CommandResult,
    LifecyclePhase,
    RenderState,
    ResultEvent,
    ResultStatus,
    SnapshotEvent,
    Surface,
    UiCommand,
    UiEvent,
    UiVisibility,
    reduce_event,
)


CommandHandler = Callable[[UiCommand], CommandResult | None]
QuitHandler = Callable[[bool], None]


class RdpCommandHandler:
    """Launch only typed, password-free native RDP requests."""

    def __init__(self, service: RdpService, *, fallback: CommandHandler) -> None:
        if not isinstance(service, RdpService) or not callable(fallback):
            raise TypeError("RDP handler dependencies are invalid")
        self._service = service
        self._fallback = fallback

    def __call__(self, command: UiCommand) -> CommandResult | None:
        if not isinstance(command, UiCommand):
            raise TypeError("command must be a UiCommand")
        if command.kind is not CommandKind.OPEN_RDP:
            return self._fallback(command)
        try:
            request = RdpRequest(
                address=command.field("address"),
                principal=command.field("principal", ""),
                port=command.field("port", 3_389),
                redirect_clipboard=command.field("redirect_clipboard", False),
            )
        except (TypeError, ValueError):
            return CommandResult(
                command.command_id,
                ResultStatus.FAILED,
                "rdp_request_invalid",
                "Check the Remote Desktop address, user name, and port.",
            )
        try:
            self._service.launch(request)
        except (RejectedError, UnavailableError, UnsupportedError):
            return CommandResult(
                command.command_id,
                ResultStatus.FAILED,
                "rdp_unavailable",
                "Windows Remote Desktop could not be opened.",
            )
        return CommandResult(
            command.command_id,
            ResultStatus.SUCCEEDED,
            "rdp_opened",
            "Windows Remote Desktop was opened.",
        )


class LocalAdminCommandHandler:
    """Expose only the two approved local-admin intents to the UI."""

    _KINDS = {
        CommandKind.APPLY_RDP_HOST,
        CommandKind.APPLY_PRIVATE_FIREWALL,
    }

    def __init__(
        self,
        service: LocalAdminService,
        *,
        fallback: CommandHandler,
    ) -> None:
        if not isinstance(service, LocalAdminService) or not callable(fallback):
            raise TypeError("local admin handler dependencies are invalid")
        self._service = service
        self._fallback = fallback

    def __call__(self, command: UiCommand) -> CommandResult | None:
        if not isinstance(command, UiCommand):
            raise TypeError("command must be a UiCommand")
        if command.kind not in self._KINDS:
            return self._fallback(command)
        if not LOCAL_ADMIN_ELEVATION_ENABLED:
            return CommandResult(
                command.command_id, ResultStatus.FAILED,
                "local_admin_unavailable",
                "Secure administrator packaging is required.")
        enabled = command.field("enabled")
        if type(enabled) is not bool:
            raise ValueError("local admin command requires an enabled bool")
        if command.kind is CommandKind.APPLY_RDP_HOST:
            require_nla = command.field("require_nla", True)
            if type(require_nla) is not bool:
                raise ValueError("RDP host command requires a require_nla bool")
            plan = self._service.plan_rdp_host(
                enabled,
                require_nla=require_nla,
            )
        else:
            plan = self._service.plan_private_firewall(enabled)
        receipt = self._service.apply(plan)
        if receipt.status is PrivilegeStatus.CANCELLED:
            return CommandResult(
                command.command_id,
                ResultStatus.CANCELLED,
                "local_admin_cancelled",
                "Administrator approval was cancelled.",
            )
        if not receipt.ok:
            return CommandResult(
                command.command_id,
                ResultStatus.FAILED,
                "local_admin_apply_failed",
                "The local administrator operation failed.",
            )
        try:
            verified = self._service.verify(plan)
        except Exception:
            verified = False
        if verified:
            return CommandResult(
                command.command_id,
                ResultStatus.SUCCEEDED,
                "local_admin_applied",
                "The local administrator setting was verified.",
            )
        try:
            rollback = self._service.rollback(plan)
            restored = rollback.ok and self._service.verify(
                plan, rolled_back=True)
        except Exception:
            restored = False
        return CommandResult(
            command.command_id,
            ResultStatus.FAILED,
            (
                "local_admin_verify_rolled_back"
                if restored
                else "local_admin_rollback_failed"
            ),
            (
                "Verification failed and the prior setting was restored."
                if restored
                else "Verification and rollback failed."
            ),
        )


class UiApplication:
    def __init__(
        self,
        *,
        host: DesktopHost,
        command_handler: CommandHandler,
        quit_handler: QuitHandler,
        initial_state: RenderState = RenderState(),
        thread_guard: UiThreadGuard | None = None,
        maximum_queue: int = 1_024,
    ) -> None:
        if not callable(command_handler) or not callable(quit_handler):
            raise TypeError("UI handlers must be callable")
        if not isinstance(initial_state, RenderState):
            raise TypeError("initial_state must be a RenderState")
        self._host = host
        self._command_handler = command_handler
        self._quit_handler = quit_handler
        self._state = initial_state
        self._guard = UiThreadGuard() if thread_guard is None else thread_guard
        self._scheduler = UiScheduler[UiEvent](
            port=host,
            consume=self._consume,
            maximum_queue=maximum_queue,
        )
        self._started = False
        host.bind(self.dispatch)

    @property
    def state(self) -> RenderState:
        return self._state

    @property
    def scheduler(self) -> UiScheduler[UiEvent]:
        return self._scheduler

    def start(self, *, start_minimized: bool = False) -> None:
        self._guard.assert_current()
        if self._started:
            raise RuntimeError("UI application is already started")
        visibility = (
            UiVisibility.MINIMIZED if start_minimized else UiVisibility.VISIBLE
        )
        self._state = self._state.evolve(
            lifecycle=LifecyclePhase.RUNNING,
            visibility=visibility,
        )
        self._host.set_visibility(visibility)
        self._scheduler.set_visibility(visibility)
        self._scheduler.start()
        self._started = True
        self._render()

    def stop(self, *, forced: bool = False) -> None:
        self._guard.assert_current()
        if not self._started:
            return
        self._scheduler.stop()
        self._state = self._state.evolve(
            lifecycle=LifecyclePhase.STOPPED,
            busy=False,
            forced_shutdown=forced,
        )
        self._render()
        self._started = False

    def publish(self, state: RenderState) -> PostStatus:
        if not isinstance(state, RenderState):
            raise TypeError("state must be a RenderState")
        return self._scheduler.post(
            SnapshotEvent(state),
            coalesce_key="render_snapshot",
        )

    def post_result(self, result: CommandResult) -> PostStatus:
        if not isinstance(result, CommandResult):
            raise TypeError("result must be a CommandResult")
        status = self._scheduler.post(ResultEvent(result))
        if status is PostStatus.FULL:
            raise RuntimeError("UI result queue is full")
        return status

    def dispatch(self, command: UiCommand) -> None:
        self._guard.assert_current()
        if not self._started:
            raise RuntimeError("UI application is not started")
        if not isinstance(command, UiCommand):
            raise TypeError("command must be a UiCommand")
        if self._dispatch_local(command):
            return
        self._state = self._state.evolve(busy=True)
        self._render()
        try:
            result = self._command_handler(command)
        except Exception:
            result = CommandResult(
                command.command_id,
                ResultStatus.FAILED,
                "command_failed",
                "The operation failed.",
            )
        if result is not None:
            if (
                not isinstance(result, CommandResult)
                or result.command_id != command.command_id
            ):
                result = CommandResult(
                    command.command_id,
                    ResultStatus.FAILED,
                    "invalid_result",
                    "The operation returned an invalid result.",
                )
            self._consume(ResultEvent(result))

    def _dispatch_local(self, command: UiCommand) -> bool:
        visibility_by_kind = {
            CommandKind.SHOW: UiVisibility.VISIBLE,
            CommandKind.HIDE: UiVisibility.HIDDEN,
            CommandKind.MINIMIZE: UiVisibility.MINIMIZED,
        }
        visibility = visibility_by_kind.get(command.kind)
        if visibility is not None:
            self._set_visibility(visibility)
            return True
        if command.kind in {CommandKind.OPEN_SURFACE, CommandKind.CLOSE_SURFACE}:
            self._change_surface(command)
            return True
        if command.kind is CommandKind.SELECT_NODE:
            self._select_node(command)
            return True
        if command.kind in {CommandKind.QUIT, CommandKind.RESTART}:
            restarting = command.kind is CommandKind.RESTART
            self._state = self._state.evolve(
                lifecycle=(
                    LifecyclePhase.RESTARTING
                    if restarting
                    else LifecyclePhase.STOPPING
                ),
                busy=True,
            )
            self._render()
            self._quit_handler(restarting)
            return True
        return False

    def _select_node(self, command: UiCommand) -> None:
        node_id = command.field("node_id")
        if type(node_id) is not str or node_id not in {
            node.node_id for node in self._state.nodes
        }:
            raise ValueError("node selection requires a rendered node identifier")
        self._state = self._state.evolve(selected_node_id=node_id)
        self._render()

    def _set_visibility(self, visibility: UiVisibility) -> None:
        self._state = self._state.evolve(visibility=visibility)
        self._host.set_visibility(visibility)
        self._scheduler.set_visibility(visibility)
        self._render()

    def _change_surface(self, command: UiCommand) -> None:
        raw = command.field("surface")
        try:
            surface = Surface(raw)
        except (TypeError, ValueError):
            raise ValueError("surface command requires a valid surface") from None
        opened = list(self._state.open_surfaces)
        if command.kind is CommandKind.OPEN_SURFACE:
            if surface is not Surface.MAIN and surface not in opened:
                opened.append(surface)
            active = surface
        else:
            if surface in opened:
                opened.remove(surface)
            active = Surface.MAIN
        self._state = self._state.evolve(
            active_surface=active,
            open_surfaces=tuple(opened),
        )
        self._render()

    def _consume(self, event: UiEvent) -> None:
        self._guard.assert_current()
        self._state = reduce_event(self._state, event).evolve(
            queue_depth=self._scheduler.queue_depth,
            dropped_events=self._scheduler.dropped,
        )
        self._render()

    def _render(self) -> None:
        self._guard.assert_current()
        self._host.render(self._state)
