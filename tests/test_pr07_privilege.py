from __future__ import annotations

from collections.abc import Callable
import json
import threading
import unittest
from unittest import mock

from fake_test_kit.guard import NoLiveAccessGuard
from rcm.adapters.local import (
    LocalPrivilegeDetector,
    OneShotHelperCommand,
)
from rcm.adapters.windows_broker import (
    WindowsOneShotBroker,
    WindowsRunAsLauncher,
    _Win32PipeClient,
    _Win32PipeServer,
    _same_executable_process,
    parse_one_shot_helper_arguments,
    run_one_shot_helper,
)
from rcm.privilege import (
    BrokerRequestEnvelope,
    CHALLENGE_LIFETIME_SECONDS,
    HELPER_EXIT_SECONDS,
    LOCAL_ADMIN_ELEVATION_ENABLED,
    MAX_BROKER_REQUEST_BYTES,
    OPERATION_DEADLINE_SECONDS,
    FirewallRuleState,
    IntegrityLevel,
    PrivateFirewallApply,
    PrivilegeReceipt,
    PrivilegeRequest,
    PrivilegeSnapshot,
    PrivilegeStatus,
    PrivilegedOperation,
    RdpHostApply,
    decode_broker_request,
    encode_broker_receipt,
    encode_broker_request,
)


REQUEST_ID = "1" * 32
CHALLENGE = "2" * 64


def _request() -> PrivilegeRequest:
    return PrivilegeRequest(
        REQUEST_ID,
        PrivilegedOperation.RDP_HOST_APPLY,
        RdpHostApply(True, True),
    )


class _FakeHandle:
    pid = 41_007

    def __init__(self, exit_code: int | None = 0) -> None:
        self.exit_code = exit_code
        self.waits: list[float] = []
        self.aborts = 0
        self.bound_client_pid: int | None = None
        self.closed = False

    def wait(self, timeout_seconds: float) -> int | None:
        self.waits.append(timeout_seconds)
        return self.exit_code

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.aborts += 1

    def bind_client_pid(self, pid: int) -> None:
        self.bound_client_pid = pid


class _FakeLauncher:
    def __init__(self, handle: _FakeHandle | None = None) -> None:
        self.handle = handle or _FakeHandle()
        self.commands: list[OneShotHelperCommand] = []

    def launch(self, command: OneShotHelperCommand) -> _FakeHandle:
        self.commands.append(command)
        return self.handle


class _FakeServer:
    name = "rcm-pr07-" + "3" * 32

    def __init__(self) -> None:
        self.envelopes: list[BrokerRequestEnvelope] = []
        self.closed = False

    def exchange(
        self,
        request: bytes,
        *,
        client_pid_validator: Callable[[int], None],
        timeout_seconds: float,
    ) -> bytes:
        client_pid_validator(41_007)
        self.timeout_seconds = timeout_seconds
        envelope = BrokerRequestEnvelope.from_dict(
            json.loads(request.decode("ascii"))
        )
        self.envelopes.append(envelope)
        return encode_broker_receipt(
            PrivilegeReceipt(
                envelope.request.request_id,
                envelope.request.operation,
                PrivilegeStatus.SUCCEEDED,
                "local_admin.applied",
                changed=True,
                verified=True,
            )
        )

    def close(self) -> None:
        self.closed = True


class _BrokerPipeFactory:
    def __init__(self) -> None:
        self.created_names: list[str] = []
        self.instance = _FakeServer()

    def server(self, name: str) -> _FakeServer:
        self.created_names.append(name)
        self.instance.name = name
        return self.instance


class _FakeClient:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.responses: list[bytes] = []
        self.closed = False

    def receive(
        self,
        *,
        expected_server_pid: int,
        timeout_seconds: float,
    ) -> bytes:
        self.expected_server_pid = expected_server_pid
        self.timeout_seconds = timeout_seconds
        return self.payload

    def send(self, response: bytes) -> None:
        self.responses.append(response)

    def close(self) -> None:
        self.closed = True


class _HelperPipeFactory:
    def __init__(self, client: _FakeClient) -> None:
        self.instance = client
        self.names: list[str] = []

    def client(self, name: str) -> _FakeClient:
        self.names.append(name)
        return self.instance


class _FakeApplier:
    def __init__(self) -> None:
        self.requests: list[PrivilegeRequest] = []

    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt:
        self.requests.append(request)
        return PrivilegeReceipt(
            request.request_id,
            request.operation,
            PrivilegeStatus.SUCCEEDED,
            "local_admin.applied",
            changed=True,
            verified=True,
        )


class _FakeTimer:
    def __init__(
        self,
        delay: float,
        callback: Callable[[], None],
        events: list[str],
    ) -> None:
        self.delay = delay
        self.callback = callback
        self.events = events
        self.daemon = False

    def start(self) -> None:
        self.events.append("started")

    def cancel(self) -> None:
        self.events.append("cancelled")


class PrivilegeContractTests(unittest.TestCase):
    def test_medium_integrity_is_the_non_elevated_default(self) -> None:
        snapshot = PrivilegeSnapshot()
        self.assertEqual(IntegrityLevel.MEDIUM, snapshot.integrity)
        self.assertFalse(snapshot.administrator_member)
        self.assertFalse(snapshot.elevated)
        with self.assertRaises(ValueError):
            PrivilegeSnapshot(IntegrityLevel.MEDIUM, elevated=True)
        detector = LocalPrivilegeDetector(probe=lambda: snapshot)
        with NoLiveAccessGuard():
            self.assertEqual(snapshot, detector.detect())

    def test_onefile_elevation_capability_is_fail_closed(self) -> None:
        self.assertFalse(LOCAL_ADMIN_ELEVATION_ENABLED)
        pipes, launcher = _BrokerPipeFactory(), _FakeLauncher()
        broker = WindowsOneShotBroker(pipe_factory=pipes, launcher=launcher)
        with NoLiveAccessGuard():
            receipt = broker.apply(_request())
        self.assertEqual(
            "local_admin.secure_packaging_required",
            receipt.code,
        )
        self.assertEqual([], pipes.created_names)
        self.assertEqual([], launcher.commands)
        command = OneShotHelperCommand(
            "rcm-pr07-" + "f" * 32, CHALLENGE, 130.0, 41_005)
        with (
            mock.patch("sys.frozen", True, create=True),
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch("ctypes.WinDLL", create=True) as win_dll,
            self.assertRaisesRegex(RuntimeError, "secure one-folder"),
        ):
            WindowsRunAsLauncher().launch(command)
        win_dll.assert_not_called()

    def test_semantic_operation_set_is_exactly_two(self) -> None:
        self.assertEqual(
            {
                "rdp_host_apply",
                "private_firewall_apply",
            },
            {operation.value for operation in PrivilegedOperation},
        )
        self.assertEqual(2, len(PrivilegedOperation))
        self.assertEqual(
            (FirewallRuleState.ENABLED,) * 3,
            PrivateFirewallApply.enabled().rules,
        )
        with self.assertRaises(ValueError):
            PrivateFirewallApply((FirewallRuleState.ENABLED,) * 2)

    def test_request_schema_rejects_unknown_action_and_fields(self) -> None:
        request = _request()
        raw = request.to_dict()
        raw["operation"] = "generic_exec"
        with self.assertRaisesRegex(ValueError, "not allowed"):
            PrivilegeRequest.from_dict(raw)
        raw = request.to_dict()
        raw["arbitrary_path"] = "SYNTHETIC_CANARY"
        with self.assertRaisesRegex(ValueError, "invalid schema") as caught:
            PrivilegeRequest.from_dict(raw)
        self.assertNotIn("SYNTHETIC_CANARY", str(caught.exception))
        with self.assertRaises(ValueError):
            RdpHostApply(True, False)

    def test_envelope_enforces_size_challenge_and_time_bounds(self) -> None:
        envelope = BrokerRequestEnvelope(
            CHALLENGE,
            10.0,
            40.0,
            130.0,
            _request(),
        )
        payload = encode_broker_request(envelope)
        self.assertLessEqual(len(payload), MAX_BROKER_REQUEST_BYTES)
        decoded = decode_broker_request(
            payload,
            expected_challenge=CHALLENGE,
            now=39.0,
        )
        self.assertEqual(_request(), decoded.request)
        with self.assertRaises(ValueError):
            decode_broker_request(
                payload,
                expected_challenge="4" * 64,
                now=20.0,
            )
        with self.assertRaises(TimeoutError):
            decode_broker_request(
                payload,
                expected_challenge=CHALLENGE,
                now=40.001,
            )
        with self.assertRaises(ValueError):
            decode_broker_request(
                b"x" * (MAX_BROKER_REQUEST_BYTES + 1),
                expected_challenge=CHALLENGE,
                now=20.0,
            )
        with self.assertRaises(ValueError):
            BrokerRequestEnvelope(
                CHALLENGE,
                10.0,
                40.001,
                130.0,
                _request(),
            )
        with self.assertRaises(ValueError):
            BrokerRequestEnvelope(
                CHALLENGE,
                10.0,
                40.0,
                130.001,
                _request(),
            )

    def test_one_shot_broker_binds_helper_pid_deadlines_and_exit(self) -> None:
        pipes = _BrokerPipeFactory()
        launcher = _FakeLauncher()
        tokens = iter(("4" * 64, "5" * 32))
        broker = WindowsOneShotBroker(
            pipe_factory=pipes,
            launcher=launcher,
            clock=lambda: 100.0,
            token_factory=lambda _length: next(tokens),
            parent_pid=lambda: 41_006,
        )

        with (
            NoLiveAccessGuard(),
            mock.patch(
                "rcm.adapters.windows_broker."
                "LOCAL_ADMIN_ELEVATION_ENABLED",
                True,
            ),
        ):
            receipt = broker.apply(_request())

        self.assertTrue(receipt.ok)
        self.assertEqual(41_007, launcher.handle.bound_client_pid)
        self.assertEqual(
            OPERATION_DEADLINE_SECONDS,
            pipes.instance.timeout_seconds,
        )
        self.assertEqual([HELPER_EXIT_SECONDS], launcher.handle.waits)
        self.assertEqual(0, launcher.handle.aborts)
        self.assertTrue(launcher.handle.closed)
        self.assertTrue(pipes.instance.closed)
        command = launcher.commands[0]
        self.assertEqual(41_006, command.parent_pid)
        self.assertEqual(130.0, command.challenge_expires_at)
        envelope = pipes.instance.envelopes[0]
        self.assertEqual(
            CHALLENGE_LIFETIME_SECONDS,
            envelope.challenge_expires_at - envelope.issued_at,
        )
        self.assertEqual(
            OPERATION_DEADLINE_SECONDS,
            envelope.operation_deadline - envelope.issued_at,
        )

    def test_helper_serves_one_request_and_closes_without_live_access(self) -> None:
        envelope = BrokerRequestEnvelope(
            CHALLENGE,
            100.0,
            130.0,
            220.0,
            _request(),
        )
        client = _FakeClient(encode_broker_request(envelope))
        pipes = _HelperPipeFactory(client)
        applier = _FakeApplier()
        command = OneShotHelperCommand(
            "rcm-pr07-" + "6" * 32,
            CHALLENGE,
            130.0,
            41_005,
        )
        job_events: list[str] = []
        timer_events: list[str] = []

        with NoLiveAccessGuard():
            exit_code = run_one_shot_helper(
                command,
                applier=applier,
                pipe_factory=pipes,
                clock=lambda: 110.0,
                privilege_probe=lambda: PrivilegeSnapshot(
                    IntegrityLevel.HIGH,
                    administrator_member=True,
                    elevated=True,
                ),
                job_guard=lambda: job_events.append("armed") or object(),
                timer_factory=lambda delay, callback: _FakeTimer(
                    delay, callback, timer_events),
            )

        self.assertEqual(0, exit_code)
        self.assertEqual(["armed"], job_events)
        self.assertEqual(
            ["started", "cancelled", "started", "cancelled"],
            timer_events,
        )
        self.assertEqual([_request()], applier.requests)
        self.assertEqual(41_005, client.expected_server_pid)
        self.assertTrue(client.closed)
        self.assertEqual(1, len(client.responses))

        blocked = run_one_shot_helper(
            command,
            applier=applier,
            pipe_factory=pipes,
            clock=lambda: 110.0,
            privilege_probe=PrivilegeSnapshot,
            job_guard=lambda: object(),
        )
        self.assertEqual(2, blocked)
        self.assertEqual(1, len(applier.requests))

    def test_helper_rejects_future_and_cli_mismatched_challenges(self) -> None:
        far_future = OneShotHelperCommand(
            "rcm-pr07-" + "8" * 32,
            CHALLENGE,
            1_000.0,
            41_005,
        )
        applier = _FakeApplier()
        self.assertEqual(
            2,
            run_one_shot_helper(
                far_future,
                applier=applier,
                pipe_factory=_HelperPipeFactory(_FakeClient(b"unused")),
                clock=lambda: 110.0,
                privilege_probe=lambda: PrivilegeSnapshot(
                    IntegrityLevel.HIGH,
                    administrator_member=True,
                    elevated=True,
                ),
                job_guard=lambda: object(),
            ),
        )
        mismatched = BrokerRequestEnvelope(
            CHALLENGE,
            100.0,
            129.0,
            220.0,
            _request(),
        )
        client = _FakeClient(encode_broker_request(mismatched))
        command = OneShotHelperCommand(
            "rcm-pr07-" + "9" * 32,
            CHALLENGE,
            130.0,
            41_005,
        )
        self.assertEqual(
            4,
            run_one_shot_helper(
                command,
                applier=applier,
                pipe_factory=_HelperPipeFactory(client),
                clock=lambda: 110.0,
                privilege_probe=lambda: PrivilegeSnapshot(
                    IntegrityLevel.HIGH,
                    administrator_member=True,
                    elevated=True,
                ),
                job_guard=lambda: object(),
            ),
        )
        self.assertEqual([], applier.requests)
        self.assertTrue(client.closed)

    def test_broker_timeout_aborts_only_the_exact_helper(self) -> None:
        pipes = _BrokerPipeFactory()
        pipes.instance.exchange = mock.Mock(side_effect=TimeoutError("synthetic"))
        launcher = _FakeLauncher()
        tokens = iter(("a" * 64, "b" * 32))
        broker = WindowsOneShotBroker(
            pipe_factory=pipes,
            launcher=launcher,
            clock=lambda: 100.0,
            token_factory=lambda _length: next(tokens),
            parent_pid=lambda: 41_006,
        )

        with (
            NoLiveAccessGuard(),
            mock.patch(
                "rcm.adapters.windows_broker."
                "LOCAL_ADMIN_ELEVATION_ENABLED",
                True,
            ),
        ):
            receipt = broker.apply(_request())

        self.assertEqual(PrivilegeStatus.FAILED, receipt.status)
        self.assertEqual(1, launcher.handle.aborts)
        self.assertTrue(launcher.handle.closed)

    def test_helper_rejects_an_attacker_owned_pipe_server(self) -> None:
        class _Process:
            def is_running(self) -> bool:
                return True

            def exe(self) -> str:
                return "synthetic-attacker.exe"

            def username(self) -> str:
                return "SYNTHETIC\\operator"

        fake_psutil = type(
            "_Psutil",
            (),
            {"Process": staticmethod(lambda _pid=None: _Process())},
        )
        with (
            mock.patch.dict("sys.modules", {"psutil": fake_psutil}),
            mock.patch(
                "rcm.adapters.windows_broker.os.path.samefile",
                return_value=False,
            ) as samefile,
        ):
            self.assertFalse(_same_executable_process(41_005))
        samefile.assert_called_once()
        source = __import__("inspect").getsource(_Win32PipeClient.receive)
        self.assertIn(
            "_same_executable_process(int(server_pid.value))",
            source,
        )

    def test_pipe_timeout_cancels_and_joins_worker_before_handle_close(
        self,
    ) -> None:
        server = object.__new__(_Win32PipeServer)
        server._handle = 71
        server._worker = None
        server._close_requested = False
        release = threading.Event()
        server._exchange_connected = (
            lambda _request, _validator, _result: release.wait(1.0)
        )

        def cancel(thread: threading.Thread) -> None:
            self.assertTrue(thread.is_alive())
            release.set()

        with (
            mock.patch(
                "rcm.adapters.windows_broker._cancel_synchronous_io",
                side_effect=cancel,
            ),
            self.assertRaises(TimeoutError),
        ):
            server.exchange(
                b"synthetic",
                client_pid_validator=lambda _pid: None,
                timeout_seconds=0.001,
            )
        assert server._worker is not None
        self.assertFalse(server._worker.is_alive())
        kernel32 = mock.Mock()
        with mock.patch(
            "rcm.adapters.windows_broker._kernel32",
            return_value=kernel32,
        ):
            server.close()
        kernel32.CloseHandle.assert_called_once_with(71)

    def test_helper_parser_and_same_executable_launcher_are_fixed(self) -> None:
        command = OneShotHelperCommand(
            "rcm-pr07-" + "7" * 32,
            CHALLENGE,
            130.0,
            41_004,
        )
        parsed = parse_one_shot_helper_arguments(command.arguments())
        self.assertEqual(command, parsed)
        self.assertIsNone(parse_one_shot_helper_arguments(("--normal",)))
        with self.assertRaises(ValueError):
            parse_one_shot_helper_arguments(
                ("--rcm-local-admin-helper", "--generic-exec")
            )
        with (
            mock.patch("sys.frozen", False, create=True),
            self.assertRaisesRegex(
                RuntimeError,
                "secure one-folder application",
            ),
        ):
            WindowsRunAsLauncher().launch(command)
        with (
            mock.patch("sys.frozen", True, create=True),
            mock.patch.dict(
                "os.environ",
                {"_PYI_APPLICATION_HOME_DIR": "SYNTHETIC_ONEFILE"},
            ),
            self.assertRaisesRegex(RuntimeError, "secure one-folder"),
        ):
            WindowsRunAsLauncher().launch(command)

if __name__ == "__main__":
    unittest.main()
