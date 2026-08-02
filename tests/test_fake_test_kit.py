from __future__ import annotations

import asyncio
from collections.abc import Iterator, MutableMapping
from contextlib import ExitStack
import json
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import fake_test_kit.guard as guard_module
from fake_test_kit import (
    DEFAULT_TEST_SEED,
    DeterministicFakeTestKit,
    FakeClock,
    FakeCredentialStore,
    FakeFilesystem,
    FakeHttpResponse,
    FakeHttpTransport,
    FakeProcessTable,
    FakeSensor,
    FakeSensorReading,
    ForbiddenLiveAccessError,
    NoLiveAccessGuard,
    synthetic_nodes,
)


EXPECTED_SCENARIO_FINGERPRINT_INTEGER = (
    0xD9902798593DCE7E487A46B4C5D8C4E7C4BA4562324862425D35C40DCCE4A0D8
)


class _SyntheticEnvironment(MutableMapping[object, object]):
    def __init__(
        self,
        backing: dict[str, str],
        *,
        bytes_mode: bool,
    ) -> None:
        self._backing = backing
        self._bytes_mode = bytes_mode

    @staticmethod
    def _key(value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("ascii").upper()
        if isinstance(value, str):
            return value.upper()
        raise TypeError("synthetic environment keys must be strings or bytes")

    @staticmethod
    def _value(value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("ascii")
        if isinstance(value, str):
            return value
        raise TypeError("synthetic environment values must be strings or bytes")

    def __getitem__(self, key: object) -> object:
        value = self._backing[self._key(key)]
        return value.encode("ascii") if self._bytes_mode else value

    def __setitem__(self, key: object, value: object) -> None:
        self._backing[self._key(key)] = self._value(value)

    def __delitem__(self, key: object) -> None:
        del self._backing[self._key(key)]

    def __iter__(self) -> Iterator[object]:
        for key in self._backing:
            yield key.encode("ascii") if self._bytes_mode else key

    def __len__(self) -> int:
        return len(self._backing)


def _synthetic_environment_pair(
) -> tuple[_SyntheticEnvironment, _SyntheticEnvironment]:
    backing = {
        key: f"synthetic-environment-{index:02d}"
        for index, key in enumerate(
            sorted(guard_module.FORBIDDEN_USER_ENVIRONMENT_KEYS)
        )
    }
    return (
        _SyntheticEnvironment(backing, bytes_mode=False),
        _SyntheticEnvironment(backing, bytes_mode=True),
    )


def _synthetic_process_target() -> None:
    return None


def _unexpected_process_launch() -> None:
    raise AssertionError("guard regression attempted a real process launch")


def _unexpected_live_primitive(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("guard regression reached a live OS primitive")


class DeterministicFakeTestKitTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        (
            self.synthetic_environment,
            self.synthetic_environment_bytes,
        ) = _synthetic_environment_pair()
        self.environment_stack = ExitStack()
        self.addCleanup(self.environment_stack.close)
        self.environment_stack.enter_context(
            mock.patch.object(os, "environ", self.synthetic_environment)
        )
        if hasattr(os, "environb"):
            self.environment_stack.enter_context(
                mock.patch.object(
                    os,
                    "environb",
                    self.synthetic_environment_bytes,
                )
            )

    def exercise_scenario(self) -> tuple[dict[str, object], str, int]:
        kit = DeterministicFakeTestKit(
            seed=DEFAULT_TEST_SEED,
            node_count=8,
        )
        with kit:
            kit.clock.sleep(0.25)
            kit.clock.advance(2)

            kit.filesystem.write_text(
                "/state/config.json",
                '{"mode":"synthetic"}\n',
                create_parents=True,
            )
            kit.filesystem.write_text(
                "/state/config.next",
                '{"mode":"replacement"}\n',
            )
            kit.filesystem.replace(
                "/state/config.next",
                "/state/config.json",
            )

            process = kit.processes.spawn(
                "synthetic-worker",
                ("--mode", "fixture"),
            )
            kit.processes.terminate(process.pid, exit_code=0)

            kit.credentials.set(
                "synthetic-target",
                "synthetic-principal",
                "fixture-value",
            )
            self.assertEqual(
                "synthetic-principal",
                kit.credentials.get("synthetic-target").principal,
            )

            kit.http.register(
                "GET",
                "/health",
                FakeHttpResponse(200, {"status": "ok"}),
            )
            response = kit.http.request("GET", "/health")
            self.assertEqual({"status": "ok"}, response.json_data)

            head = kit.nodes[0]
            worker = kit.nodes[1]
            kit.ray.start_head(head.node_id)
            kit.ray.join_worker(worker.node_id, head_id=head.node_id)
            kit.ray.stop(worker.node_id)

            first_sensor = kit.sensor.sample(head.node_id)
            second_sensor = kit.sensor.sample(head.node_id)
            self.assertEqual(
                first_sensor.temperature + 1,
                second_sensor.temperature,
            )

            snapshot = kit.snapshot()
            fingerprint = kit.fingerprint()
            resources_before_close = kit.resource_count()

        self.assertTrue(kit.closed)
        self.assertFalse(kit.guard.active)
        self.assertEqual(0, kit.resource_count())
        return snapshot, fingerprint, resources_before_close

    def test_fixed_seed_scenario_is_identical_three_times(self) -> None:
        runs = [self.exercise_scenario() for _ in range(3)]
        first_snapshot, first_fingerprint, first_resources = runs[0]
        self.assertGreater(first_resources, 0)
        self.assertEqual(
            EXPECTED_SCENARIO_FINGERPRINT_INTEGER,
            int(first_fingerprint, 16),
        )
        for snapshot, fingerprint, resources in runs[1:]:
            self.assertEqual(first_snapshot, snapshot)
            self.assertEqual(first_fingerprint, fingerprint)
            self.assertEqual(first_resources, resources)
        pristine_first = DeterministicFakeTestKit(
            seed=DEFAULT_TEST_SEED,
            node_count=8,
        )
        pristine_second = DeterministicFakeTestKit(
            seed=DEFAULT_TEST_SEED,
            node_count=8,
        )
        try:
            self.assertEqual(
                pristine_first.fingerprint(),
                pristine_second.fingerprint(),
            )
        finally:
            pristine_first.close()
            pristine_second.close()
        json.dumps(first_snapshot, sort_keys=True)

    def test_different_seed_changes_the_fingerprint(self) -> None:
        first = DeterministicFakeTestKit(seed=1, node_count=8)
        second = DeterministicFakeTestKit(seed=2, node_count=8)
        try:
            self.assertNotEqual(first.fingerprint(), second.fingerprint())
        finally:
            first.close()
            second.close()
        self.assertEqual(0, first.resource_count())
        self.assertEqual(0, second.resource_count())

    def test_synthetic_node_factory_supports_only_1_8_32(self) -> None:
        for count in (1, 8, 32):
            with self.subTest(count=count):
                first = synthetic_nodes(count, seed=DEFAULT_TEST_SEED)
                second = synthetic_nodes(count, seed=DEFAULT_TEST_SEED)
                self.assertEqual(first, second)
                self.assertEqual(count, len(first))
                self.assertEqual("head", first[0].role)
                self.assertEqual(
                    count - 1,
                    sum(node.role == "worker" for node in first),
                )
                self.assertEqual(
                    count,
                    len({node.node_id for node in first}),
                )
        for invalid in (0, 2, 7, 9, 31, 33, True):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    synthetic_nodes(invalid, seed=DEFAULT_TEST_SEED)

    def test_fake_clock_is_integer_nanosecond_deterministic(self) -> None:
        clock = FakeClock(seed=3)
        initial = clock.now()
        clock.sleep(0.125)
        clock.advance(1.5)
        self.assertEqual(1_625_000_000, clock.monotonic_ns())
        self.assertEqual(1.625, clock.monotonic())
        self.assertGreater(clock.now(), initial)
        with self.assertRaises(ValueError):
            clock.advance(-1)
        with self.assertRaises(ValueError):
            clock.advance(0.0000000001)
        for invalid_duration in ("1", None, True, float("inf")):
            with self.subTest(invalid_duration=invalid_duration):
                with self.assertRaises(ValueError):
                    clock.advance(invalid_duration)

    def test_fake_filesystem_never_uses_the_host_filesystem(self) -> None:
        filesystem = FakeFilesystem()
        filesystem.mkdir("/state")
        filesystem.write_text("/state/item.txt", "synthetic\n")
        self.assertEqual("synthetic\n", filesystem.read_text("/state/item.txt"))
        self.assertEqual(("item.txt",), filesystem.listdir("/state"))
        self.assertTrue(filesystem.exists("/state/item.txt"))
        with self.assertRaises(ValueError):
            filesystem.write_text("relative.txt", "synthetic")
        slash = "/"
        backslash = "\\"
        for rejected in (
            slash * 2 + "synthetic-host/share",
            backslash * 2 + "synthetic-host" + backslash + "share",
            backslash * 2
            + "?"
            + backslash
            + "C:"
            + backslash
            + "state"
            + backslash
            + "item.txt",
            backslash * 2
            + "."
            + backslash
            + "pipe"
            + backslash
            + "synthetic",
            backslash
            + "??"
            + backslash
            + "C:"
            + backslash
            + "state"
            + backslash
            + "item.txt",
            backslash
            + "Device"
            + backslash
            + "NamedPipe"
            + backslash
            + "synthetic",
        ):
            with self.subTest(rejected=rejected):
                with self.assertRaises(ValueError):
                    filesystem.exists(rejected)
        filesystem.write_text(
            r"\portable\item.bin",
            "synthetic",
            create_parents=True,
        )
        self.assertTrue(filesystem.exists("/portable/item.bin"))
        with self.assertRaises(ValueError):
            filesystem.write_bytes("/state/not-bytes.bin", 3)
        filesystem.write_text("/collision", "synthetic")
        with self.assertRaises(NotADirectoryError):
            filesystem.write_text(
                "/collision/child.txt",
                "synthetic",
                create_parents=True,
            )
        with self.assertRaises(NotADirectoryError):
            filesystem.mkdir("/collision/child", parents=True)
        filesystem.mkdir("/destination")
        with self.assertRaises(IsADirectoryError):
            filesystem.replace("/state/item.txt", "/destination")
        filesystem.unlink("/state/item.txt")
        filesystem.clear()
        self.assertEqual(0, filesystem.resource_count())

    def test_fake_process_table_never_spawns_a_real_process(self) -> None:
        table = FakeProcessTable(seed=DEFAULT_TEST_SEED)
        first = table.spawn("synthetic-one")
        second = table.spawn("synthetic-two", ("--fixture",))
        self.assertEqual(first.pid + 1, second.pid)
        self.assertEqual(2, len(table.running()))
        table.terminate(first.pid, exit_code=7)
        self.assertEqual(1, len(table.running()))
        self.assertEqual(7, table.get(first.pid).exit_code)
        for invalid_name in (None, 3, True, ""):
            with self.subTest(invalid_name=invalid_name):
                with self.assertRaises(ValueError):
                    table.spawn(invalid_name)
        for invalid_arguments in (["--fixture"], ("--fixture", 3), "value"):
            with self.subTest(invalid_arguments=invalid_arguments):
                with self.assertRaises(ValueError):
                    table.spawn("synthetic-invalid", invalid_arguments)
        for invalid_exit_code in (False, 1.5, "1"):
            with self.subTest(invalid_exit_code=invalid_exit_code):
                with self.assertRaises(ValueError):
                    table.terminate(second.pid, exit_code=invalid_exit_code)
        table.clear()
        self.assertEqual(0, table.resource_count())

    def test_fake_credential_snapshot_never_contains_raw_record_data(
        self,
    ) -> None:
        store = FakeCredentialStore()
        target = "synthetic-target"
        principal = "synthetic-principal"
        fixture_value = "fixture-value"
        store.set(target, principal, fixture_value)
        self.assertEqual(fixture_value, store.get(target).value)
        with self.assertRaises(ValueError):
            store.set(target, principal, "replacement-value")
        store.set(
            target,
            "replacement-principal",
            "replacement-value",
            overwrite=True,
        )
        serialized = json.dumps(store.snapshot(), sort_keys=True)
        for raw_record_data in (
            target,
            principal,
            fixture_value,
            "replacement-principal",
            "replacement-value",
            "sha256",
        ):
            self.assertNotIn(raw_record_data, serialized)
        self.assertIn("credential-001", serialized)
        self.assertTrue(store.delete(target))
        self.assertNotIn(target, store._references)
        store.clear()
        self.assertEqual(0, store.resource_count())

    def test_fake_http_transport_accepts_routes_without_hosts_or_ports(
        self,
    ) -> None:
        transport = FakeHttpTransport()
        transport.register(
            "POST",
            "/metrics?sample=1",
            FakeHttpResponse(202, {"accepted": True}),
        )
        response = transport.request(
            "post",
            "/metrics?sample=1",
            json_data={"value": 1},
        )
        self.assertEqual(202, response.status)
        with self.assertRaises(ValueError):
            transport.request("GET", "synthetic-host/path")
        with self.assertRaises(ValueError):
            transport.request("GET", "//synthetic-host/path")
        with self.assertRaises(LookupError):
            transport.request("GET", "/unregistered")
        for invalid_status in (True, 200.5, "200", None):
            with self.subTest(invalid_status=invalid_status):
                with self.assertRaises(ValueError):
                    FakeHttpResponse(invalid_status)
        transport.clear()
        self.assertEqual(0, transport.resource_count())

    def test_fake_sensor_repeats_the_last_sample(self) -> None:
        sensor = FakeSensor()
        sensor.set_series(
            "node-001",
            (
                FakeSensorReading(40, 10),
                FakeSensorReading(41, 20),
            ),
        )
        self.assertEqual(40, sensor.sample("node-001").temperature)
        self.assertEqual(41, sensor.sample("node-001").temperature)
        self.assertEqual(41, sensor.sample("node-001").temperature)
        with self.assertRaises(ValueError):
            sensor.set_series(
                "node-001",
                (FakeSensorReading(42, 30),),
            )
        sensor.set_series(
            "node-001",
            (FakeSensorReading(42, 30),),
            replace=True,
        )
        for invalid_reading in (
            (40.5, 10),
            (40, 10.5),
            (True, 10),
            (40, False),
        ):
            with self.subTest(invalid_reading=invalid_reading):
                with self.assertRaises(ValueError):
                    FakeSensorReading(*invalid_reading)
        sensor.clear()
        self.assertEqual(0, sensor.resource_count())

    def test_audit_hook_installation_fails_closed_when_probe_is_lost(
        self,
    ) -> None:
        saved_installed = guard_module._AUDIT_HOOK_INSTALLED
        saved_generation = guard_module._AUDIT_PROBE_GENERATION
        try:
            guard_module._AUDIT_HOOK_INSTALLED = False
            with (
                mock.patch.object(sys, "addaudithook", return_value=None),
                mock.patch.object(sys, "audit", return_value=None),
            ):
                with self.assertRaisesRegex(RuntimeError, "self-probe failed"):
                    guard_module._ensure_audit_hook()
            self.assertFalse(guard_module._AUDIT_HOOK_INSTALLED)
        finally:
            guard_module._AUDIT_HOOK_INSTALLED = saved_installed
            guard_module._AUDIT_PROBE_GENERATION = saved_generation

    def test_no_live_access_guard_blocks_environment_process_and_socket(
        self,
    ) -> None:
        environment_alias = os.environ
        guard = NoLiveAccessGuard()
        environment_getitem_alias = environment_alias.__getitem__
        synthetic_environment_key = next(
            (
                key
                for key in sorted(
                    guard_module.FORBIDDEN_USER_ENVIRONMENT_KEYS
                )
                if key not in environment_alias
            ),
            None,
        )
        synthetic_environment_value = "synthetic-guard-value"
        if synthetic_environment_key is not None:
            environment_alias[synthetic_environment_key] = (
                synthetic_environment_value
            )
            self.addCleanup(
                environment_alias.pop,
                synthetic_environment_key,
                None,
            )
        environment_presence = {
            key: key in environment_alias
            for key in guard_module.FORBIDDEN_USER_ENVIRONMENT_KEYS
        }
        environment_bytes_alias = getattr(
            os,
            "environb",
            self.synthetic_environment_bytes,
        )
        environment_bytes_getitem_alias = (
            environment_bytes_alias.__getitem__
        )
        safe_targets = [
            (subprocess, "Popen", (("synthetic-command",),), {}),
            (
                subprocess,
                "run",
                (("synthetic-command",),),
                {"check": True},
            ),
            (
                subprocess,
                "check_output",
                (("synthetic-command",),),
                {},
            ),
            (os, "system", ("synthetic-command",), {}),
            (socket, "socket", (), {}),
            (
                socket,
                "create_connection",
                (("192.0.2.1", 9),),
                {},
            ),
            (
                asyncio,
                "create_subprocess_exec",
                ("synthetic-command",),
                {},
            ),
            (
                asyncio,
                "create_subprocess_shell",
                ("synthetic-command",),
                {},
            ),
        ]
        if hasattr(socket, "socketpair"):
            safe_targets.append((socket, "socketpair", (), {}))
        with ExitStack() as sentinels:
            for owner, name, _args, _kwargs in safe_targets:
                sentinels.enter_context(
                    mock.patch.object(
                        owner,
                        name,
                        _unexpected_live_primitive,
                    )
                )
            with guard:
                self.assertIs(os.environ, environment_alias)
                for owner, name, args, kwargs in safe_targets:
                    current = getattr(owner, name)
                    self.assertIsNot(current, _unexpected_live_primitive)
                    with self.subTest(safe_target=f"{owner.__name__}.{name}"):
                        with self.assertRaises(ForbiddenLiveAccessError):
                            current(*args, **kwargs)

                for key in sorted(
                    guard_module.FORBIDDEN_USER_ENVIRONMENT_KEYS
                ):
                    with self.subTest(environment_key=key):
                        with self.assertRaises(ForbiddenLiveAccessError):
                            environment_alias[key]
                        with self.assertRaises(ForbiddenLiveAccessError):
                            environment_alias[key] = "synthetic"
                        with self.assertRaises(ForbiddenLiveAccessError):
                            del environment_alias[key]
                        with self.assertRaises(KeyError):
                            environment_getitem_alias(key)
                with self.assertRaises(ForbiddenLiveAccessError):
                    environment_bytes_alias[b"HOME"]
                with self.assertRaises(KeyError):
                    environment_bytes_getitem_alias(b"HOME")

                audit_events = (
                    "os.exec",
                    "os.putenv",
                    "os.startfile",
                    "os.startfile/2",
                    "os.system",
                    "os.unsetenv",
                    "socket.__new__",
                    "socket.getaddrinfo",
                    "socket.gethostbyname",
                    "socket.gethostname",
                    "socket.sendmsg",
                    "socket.sendto",
                    "subprocess.Popen",
                )
                for event in audit_events:
                    with self.subTest(audit_event=event):
                        with self.assertRaises(ForbiddenLiveAccessError):
                            sys.audit(event)
        if synthetic_environment_key is not None:
            self.assertEqual(
                synthetic_environment_value,
                environment_alias[synthetic_environment_key],
            )
        self.assertEqual(
            environment_presence,
            {
                key: key in environment_alias
                for key in guard_module.FORBIDDEN_USER_ENVIRONMENT_KEYS
            },
        )
        self.assertGreater(len(guard.violations), 0)
        self.assertFalse(guard.active)
        self.assertEqual(0, guard.resource_count())

    def test_guard_entry_restores_environment_after_partial_strip_failure(
        self,
    ) -> None:
        class SyntheticEnvironment(dict[str, str]):
            pass

        environment = SyntheticEnvironment(
            {
                "APPDATA": "synthetic-appdata",
                "HOME": "synthetic-home",
                "SAFE": "synthetic-safe",
            }
        )
        expected = dict(environment)
        with mock.patch.object(guard_module.os, "environ", environment):
            guard = NoLiveAccessGuard()
            original_delitem = guard._environment_delitem
            deletion_count = 0

            def fail_second_deletion(
                source: object,
                key: object,
            ) -> None:
                nonlocal deletion_count
                deletion_count += 1
                if deletion_count == 2:
                    raise OSError("synthetic environment deletion failure")
                original_delitem(source, key)

            guard._environment_delitem = fail_second_deletion
            with self.assertRaisesRegex(
                OSError,
                "synthetic environment deletion failure",
            ):
                guard.__enter__()
            self.assertEqual(expected, environment)
            self.assertEqual([], guard._saved_environment)
            self.assertFalse(guard.active)
            self.assertEqual(0, guard.resource_count())

    def test_guard_exit_retries_partial_environment_restore_failure(
        self,
    ) -> None:
        class SyntheticEnvironment(dict[str, str]):
            pass

        environment = SyntheticEnvironment(
            {
                "APPDATA": "synthetic-appdata",
                "HOME": "synthetic-home",
                "SAFE": "synthetic-safe",
            }
        )
        expected = dict(environment)
        with mock.patch.object(guard_module.os, "environ", environment):
            guard = NoLiveAccessGuard()
            guard.__enter__()
            original_setitem = guard._environment_setitem
            restoration_count = 0

            def fail_second_restoration(
                destination: object,
                key: object,
                value: object,
            ) -> None:
                nonlocal restoration_count
                restoration_count += 1
                if restoration_count == 2:
                    raise OSError("synthetic environment restoration failure")
                original_setitem(destination, key, value)

            guard._environment_setitem = fail_second_restoration
            guard.__exit__(None, None, None)
            self.assertGreaterEqual(restoration_count, 3)
            self.assertEqual(expected, environment)
            self.assertEqual([], guard._saved_environment)
            self.assertFalse(guard.active)
            self.assertEqual(0, guard.resource_count())

    def test_guard_reports_unresolved_environment_restore_resources(
        self,
    ) -> None:
        class SyntheticEnvironment(dict[str, str]):
            pass

        environment = SyntheticEnvironment(
            {
                "APPDATA": "synthetic-appdata",
                "HOME": "synthetic-home",
                "SAFE": "synthetic-safe",
            }
        )
        expected = dict(environment)
        with mock.patch.object(guard_module.os, "environ", environment):
            guard = NoLiveAccessGuard()
            guard.__enter__()
            original_setitem = guard._environment_setitem

            def fail_every_restoration(
                _destination: object,
                _key: object,
                _value: object,
            ) -> None:
                raise OSError("synthetic permanent restoration failure")

            guard._environment_setitem = fail_every_restoration
            with self.assertRaisesRegex(
                RuntimeError,
                "could not restore environment",
            ):
                guard.__exit__(None, None, None)
            self.assertEqual(2, guard.resource_count())
            self.assertEqual({"SAFE": "synthetic-safe"}, environment)
            self.assertFalse(guard.active)

            guard._environment_setitem = original_setitem
            guard._restore_forbidden_environment()
            self.assertEqual(expected, environment)
            self.assertEqual(0, guard.resource_count())

    def test_prebound_process_start_is_blocked_for_every_context(
        self,
    ) -> None:
        for method in multiprocessing.get_all_start_methods():
            with self.subTest(start_method=method):
                context = multiprocessing.get_context(method)
                process_class = context.Process
                with mock.patch.object(
                    process_class,
                    "_Popen",
                    staticmethod(_unexpected_process_launch),
                ):
                    process = process_class(target=_synthetic_process_target)
                    start_alias = process.start
                    with NoLiveAccessGuard():
                        with self.assertRaises(ForbiddenLiveAccessError):
                            start_alias()
                    self.assertIsNone(process._popen)

    def test_prebound_private_popen_is_blocked_for_every_context(
        self,
    ) -> None:
        for method in multiprocessing.get_all_start_methods():
            with self.subTest(start_method=method):
                self.assertIn(
                    method,
                    guard_module._MULTIPROCESSING_POPEN_BY_START_METHOD,
                )
                context = multiprocessing.get_context(method)
                process_class = context.Process
                popen_module = (
                    guard_module._MULTIPROCESSING_POPEN_BY_START_METHOD[
                        method
                    ]
                )
                with mock.patch.object(
                    popen_module,
                    "Popen",
                    _unexpected_live_primitive,
                ):
                    process = process_class(target=_synthetic_process_target)
                    popen_alias = process_class._Popen
                    with NoLiveAccessGuard():
                        with self.assertRaises(ForbiddenLiveAccessError):
                            popen_alias(process)
                    self.assertIsNone(process._popen)

    def test_prebound_alias_coverage_uses_safe_synthetic_audit_events(
        self,
    ) -> None:
        captured_aliases = (
            subprocess.Popen,
            subprocess.run,
            os.system,
            socket.socket,
            socket.create_connection,
        )
        if hasattr(os, "startfile"):
            captured_aliases += (os.startfile,)
        with NoLiveAccessGuard():
            for event in (
                "subprocess.Popen",
                "os.system",
                "os.startfile",
                "os.startfile/2",
                "socket.__new__",
                "socket.connect",
            ):
                with self.subTest(event=event):
                    with self.assertRaises(ForbiddenLiveAccessError):
                        sys.audit(event)
        self.assertTrue(all(callable(alias) for alias in captured_aliases))

    def test_no_live_access_guards_cannot_overlap(self) -> None:
        first = NoLiveAccessGuard()
        second = NoLiveAccessGuard()
        with first:
            with self.assertRaisesRegex(RuntimeError, "must not overlap"):
                second.__enter__()
            self.assertFalse(second.active)
            self.assertEqual(0, second.resource_count())
        self.assertFalse(first.active)
        self.assertEqual(0, first.resource_count())

    def test_guard_and_temporary_resources_cleanup_after_exception(
        self,
    ) -> None:
        original_socket = socket.socket
        original_popen = subprocess.Popen
        original_environment = os.environ
        kit = DeterministicFakeTestKit(
            seed=DEFAULT_TEST_SEED,
            node_count=1,
        )
        temporary_path = None
        with self.assertRaisesRegex(RuntimeError, "synthetic stop"):
            with tempfile.TemporaryDirectory(
                prefix="rcm-synthetic-"
            ) as directory:
                temporary_path = Path(directory)
                (temporary_path / "marker.txt").write_text(
                    "synthetic\n",
                    encoding="utf-8",
                )
                with kit:
                    kit.filesystem.write_text(
                        "/state/item.txt",
                        "synthetic\n",
                        create_parents=True,
                    )
                    raise RuntimeError("synthetic stop")
        self.assertIsNotNone(temporary_path)
        self.assertFalse(temporary_path.exists())
        self.assertIs(socket.socket, original_socket)
        self.assertIs(subprocess.Popen, original_popen)
        self.assertIs(os.environ, original_environment)
        self.assertTrue(kit.closed)
        self.assertEqual(0, kit.resource_count())


if __name__ == "__main__":
    unittest.main()
