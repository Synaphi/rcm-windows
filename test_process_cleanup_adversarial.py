"""Adversarial safety tests for the local residual-process cleanup engine.

All termination paths are mocked.  The suite intentionally constructs
ambiguous, reused, protected, connected, and stale process identities so a
future refactor cannot turn resource usage alone into authority to kill.
"""
from __future__ import annotations

import ast
from dataclasses import replace
import inspect
import threading
import unittest
from unittest import mock

import process_cleanup as pc


NOW = 2_000_000_000.0
MIB = 1024 * 1024


def make_record(
        pid: int,
        command: tuple[str, ...],
        *,
        name: str = "node.exe",
        ppid: int = 900_000,
        age_sec: float = 2 * 24 * 3600,
        cpu_pct: float = 6.0,
        memory_bytes: int = 300 * MIB,
        exe_path: str | None = None,
        cwd: str = r"C:\Synthetic\adversarial-sample",
        protected_reason: str = "",
        connections: tuple[pc.ConnectionRecord, ...] = (),
        visible_window: bool = False,
) -> pc.ProcessRecord:
    """Build a complete synthetic record without consulting the host."""
    executable = exe_path or rf"C:\Synthetic\{name}"
    record = pc.ProcessRecord(
        pid=pid,
        ppid=ppid,
        create_time=NOW - age_sec,
        name=name,
        exe_path=executable,
        cmdline=command,
        safe_command=pc.redact_command_line(command),
        command_fingerprint=pc.command_fingerprint(command),
        username=r"SYNTHETIC\tester",
        session_id=1,
        cwd=cwd,
        cpu_pct=cpu_pct,
        memory_bytes=memory_bytes,
        visible_window=visible_window,
        connections=connections,
        protected_reason=protected_reason,
    )
    record.workload = pc.recognize_workload(command, name)
    record.project_root = cwd
    return record


def evaluate(*records: pc.ProcessRecord,
             policy: pc.CleanupPolicy | None = None
             ) -> list[pc.CleanupCandidate]:
    return pc.evaluate_records(
        {record.pid: record for record in records},
        policy or pc.CleanupPolicy(),
        now_epoch=NOW,
        scanned_monotonic=500.0,
    )


class WorkloadRecognitionTests(unittest.TestCase):
    def test_recommendable_recognizers_are_not_astro_or_project_specific(
            self) -> None:
        cases = (
            ("vite-dev", ("node", "vite", "--host", "127.0.0.1"), "node.exe"),
            ("next-dev", ("node", "next", "dev", "-p", "3100"), "node.exe"),
            ("python-http", ("python", "-m", "http.server", "8000"),
             "python.exe"),
            ("uvicorn-dev", ("uvicorn", "sample:app", "--reload"),
             "python.exe"),
        )
        for offset, (kind, command, name) in enumerate(cases, start=1):
            with self.subTest(kind=kind):
                record = make_record(1000 + offset, command, name=name)
                self.assertEqual(record.workload.kind, kind)
                self.assertTrue(record.workload.recommendable)
                candidates = evaluate(record)
                self.assertEqual(len(candidates), 1)
                self.assertEqual(
                    candidates[0].classification, pc.CLASS_RECOMMENDED)
                self.assertEqual(candidates[0].workload_kind, kind)

    def test_sensitive_development_runtimes_are_review_only(self) -> None:
        cases = (
            ("jupyter", ("python", "-m", "jupyter", "lab"), "python.exe"),
            ("gradle-dev", ("gradle", "bootRun"), "java.exe"),
            ("dotnet-watch", ("dotnet", "watch", "run"), "dotnet.exe"),
        )
        for offset, (kind, command, name) in enumerate(cases, start=1):
            with self.subTest(kind=kind):
                record = make_record(1100 + offset, command, name=name)
                self.assertEqual(record.workload.kind, kind)
                self.assertFalse(record.workload.recommendable)
                candidate = evaluate(record)[0]
                self.assertEqual(candidate.classification, pc.CLASS_REVIEW)
                self.assertFalse(candidate.recommended)

    def test_unknown_heavy_orphan_never_becomes_recommended(self) -> None:
        record = make_record(
            1201, ("mystery-worker", "--serve"),
            name="mystery-worker.exe", cpu_pct=25.0, memory_bytes=2 * 1024 * MIB)
        self.assertFalse(record.workload.recognized)
        candidate = evaluate(record)[0]
        self.assertEqual(candidate.classification, pc.CLASS_REVIEW)
        self.assertFalse(candidate.recommended)
        self.assertIn("parent process is gone", candidate.reasons)

    def test_tool_name_as_an_unrelated_argument_is_not_recognized(self) -> None:
        cases = (
            (("python", "worker.py", "vite", "production"), "python.exe"),
            (("npm", "test", "--", "vite"), "node.exe"),
            (("npm", "run", "lint", "--", "vite"), "node.exe"),
        )
        for command, name in cases:
            with self.subTest(command=command):
                self.assertFalse(
                    pc.recognize_workload(command, name).recognized)


class ClassificationSafetyTests(unittest.TestCase):
    def test_active_connection_downgrades_a_recommendable_workload(self) -> None:
        connection = pc.ConnectionRecord(
            status="ESTABLISHED",
            local_ip="127.0.0.1",
            local_port=5173,
            remote_ip="127.0.0.1",
            remote_port=50123,
        )
        record = make_record(
            1301, ("node", "vite", "--host", "127.0.0.1"),
            connections=(connection,))
        candidate = evaluate(record)[0]
        self.assertTrue(candidate.active_connection)
        self.assertEqual(candidate.classification, pc.CLASS_REVIEW)
        self.assertIn("active network connection", candidate.reasons)

    def test_half_open_remote_connection_also_downgrades(self) -> None:
        connection = pc.ConnectionRecord(
            status="SYN_SENT",
            local_ip="127.0.0.1",
            local_port=5173,
            remote_ip="127.0.0.1",
            remote_port=50123,
        )
        candidate = evaluate(make_record(
            1302, ("node", "vite", "--host", "127.0.0.1"),
            connections=(connection,)))[0]
        self.assertEqual(candidate.classification, pc.CLASS_REVIEW)
        self.assertTrue(candidate.active_connection)

    def test_wildcard_listener_is_never_recommended(self) -> None:
        listener = pc.ConnectionRecord(
            status="LISTEN", local_ip="0.0.0.0", local_port=4321)
        candidate = evaluate(make_record(
            1303, ("node", "astro", "dev", "--host", "0.0.0.0"),
            connections=(listener,)))[0]
        self.assertEqual(candidate.classification, pc.CLASS_REVIEW)
        self.assertTrue(candidate.active_connection)
        self.assertIn("non-local network listener", candidate.reasons)

    def test_recent_duplicate_workloads_are_never_recommended(self) -> None:
        command = ("node", "next", "dev", "-p", "3100")
        first = make_record(1310, command, age_sec=60)
        second = make_record(1311, command, age_sec=60)
        candidates = evaluate(first, second)
        self.assertTrue(candidates)
        self.assertTrue(all(not item.recommended for item in candidates))

    def test_overlapping_parent_and_child_candidates_are_deduplicated(
            self) -> None:
        parent = make_record(
            1320, ("mystery-worker", "--serve"),
            name="mystery.exe", cpu_pct=20.0)
        child = make_record(
            1321, ("node", "vite", "--host", "127.0.0.1"),
            ppid=parent.pid)
        candidates = evaluate(parent, child)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(
            set(candidates[0].member_pids), {parent.pid, child.pid})
        self.assertEqual(candidates[0].classification, pc.CLASS_REVIEW)

    def test_live_interactive_parent_prevents_auto_recommendation(self) -> None:
        parent = make_record(
            1330, ("cmd.exe", "/k"),
            name="cmd.exe", visible_window=True, cpu_pct=0.0)
        parent.protected_reason = "visible or foreground application"
        child = make_record(
            1331, ("node", "vite", "--host", "127.0.0.1"),
            ppid=parent.pid)
        candidate = evaluate(parent, child)[0]
        self.assertEqual(candidate.classification, pc.CLASS_REVIEW)

    def test_protected_descendant_protects_the_entire_candidate_tree(self) -> None:
        root = make_record(1401, ("node", "vite", "--host", "127.0.0.1"))
        child = make_record(
            1402,
            ("esbuild", "--service=0.25.0"),
            name="esbuild.exe",
            ppid=root.pid,
            age_sec=root.age_sec - 2,
            cpu_pct=1.0,
            protected_reason="Windows service",
        )
        candidate = evaluate(root, child)[0]
        self.assertEqual(candidate.member_pids, (root.pid, child.pid))
        self.assertEqual(candidate.classification, pc.CLASS_PROTECTED)
        self.assertEqual(candidate.protected_reason, "Windows service")

    def test_ignored_exact_fingerprint_is_protected(self) -> None:
        record = make_record(1501, ("uvicorn", "sample:app", "--reload"))
        policy = pc.CleanupPolicy(
            ignored_fingerprints=frozenset({record.command_fingerprint}))
        candidate = evaluate(record, policy=policy)[0]
        self.assertEqual(candidate.classification, pc.CLASS_PROTECTED)
        self.assertEqual(candidate.protected_reason, "ignored exact workload")

    def test_reused_parent_pid_is_not_adopted_as_the_candidate_root(self) -> None:
        child = make_record(
            1601, ("uvicorn", "sample:app"), ppid=1600, age_sec=2 * 24 * 3600)
        # This process was created long after the child, so PID 1600 is a
        # recycled PID rather than the child's real parent.
        recycled_parent = make_record(
            1600, ("cmd.exe", "/c", "unrelated"),
            name="cmd.exe",
            ppid=4,
            age_sec=60,
            cpu_pct=0.0,
            memory_bytes=5 * MIB,
        )
        candidates = evaluate(child, recycled_parent)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].root.pid, child.pid)
        self.assertIn("parent process is gone", candidates[0].reasons)

    def test_exact_duplicate_siblings_remain_separate_identity_groups(
            self) -> None:
        command = ("node", "next", "dev", "-p", "3100")
        first = make_record(1701, command)
        second = make_record(1702, command)
        candidates = evaluate(first, second)
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            {candidate.member_pids for candidate in candidates},
            {(first.pid,), (second.pid,)},
        )
        self.assertEqual(len({candidate.group_id for candidate in candidates}), 2)
        self.assertTrue(all(
            "exact duplicate workload" in candidate.reasons
            for candidate in candidates))


class PrivacyTests(unittest.TestCase):
    def test_display_command_redacts_common_secret_forms(self) -> None:
        command = (
            "tool",
            "--token=synthetic-test-token",
            "--password",
            "hunter2",
        "https://synthetic-user:synthetic-test-password@localhost/run?api_key=synthetic-test-key&x=1",
            "credential=synthetic-test-value",
        )
        safe = pc.redact_command_line(command)
        for secret in (
                "synthetic-test-token", "hunter2", "alice", "urlsecret", "ABC123",
                "keepout"):
            self.assertNotIn(secret, safe)
        self.assertGreaterEqual(safe.count("<redacted>"), 5)

    def test_fingerprint_stays_exact_even_when_display_is_redacted(self) -> None:
        first = ("tool", "--token=first")
        second = ("tool", "--token=second")
        self.assertEqual(
            pc.redact_command_line(first), pc.redact_command_line(second))
        self.assertNotEqual(
            pc.command_fingerprint(first), pc.command_fingerprint(second))

    def test_argv_boundaries_prevent_multiword_secret_leaks(self) -> None:
        safe = pc.redact_command_line(
            ("app", "--token", "super secret", "--header",
             "Authorization: Bearer ABC DEF"))
        self.assertNotIn("super secret", safe)
        self.assertNotIn("ABC", safe)
        self.assertNotIn("DEF", safe)

    def test_environment_and_generic_uri_secrets_are_redacted(self) -> None:
        safe = pc.redact_command_line((
            "app",
            "OPENAI_API_KEY=sk-live-secret",
            "GH_TOKEN=token-value",
            "DATABASE_URL=postgres://user:pass@host/db",
        ))
        for secret in ("sk-live-secret", "token-value", "user", "pass"):
            self.assertNotIn(secret, safe)

    def test_split_authorization_header_is_redacted(self) -> None:
        safe = pc.redact_command_line(
            ("app", "--header", "Authorization:", "Bearer", "ABC123"))
        self.assertNotIn("ABC123", safe)


class ScanCancellationTests(unittest.TestCase):
    def test_presignalled_scan_cancellation_stops_after_first_snapshot(
            self) -> None:
        cancel = threading.Event()
        cancel.set()
        with mock.patch.object(
                pc, "_snapshot_once", return_value=({}, [])) as snapshot:
            result = pc.scan_processes(
                pc.CleanupPolicy(sample_sec=0.05), cancel_event=cancel)
        self.assertTrue(result.cancelled)
        self.assertEqual(snapshot.call_count, 1)
        self.assertEqual(result.candidates, [])

    def test_scan_without_cancel_event_still_observes_sample_interval(
            self) -> None:
        with (
            mock.patch.object(
                pc, "_snapshot_once", side_effect=[({}, []), ({}, [])])
            as snapshot,
            mock.patch.object(pc.time, "sleep") as sleep,
        ):
            result = pc.scan_processes(pc.CleanupPolicy(sample_sec=0.05))
        self.assertFalse(result.cancelled)
        self.assertEqual(snapshot.call_count, 2)
        sleep.assert_called_once_with(0.05)

    def test_incomplete_safety_enumeration_returns_no_candidates(self) -> None:
        record = make_record(
            2101, ("node", "vite", "--host", "127.0.0.1"))
        snapshots = [
            ({record.pid: record}, []),
            ({record.pid: record},
             ["network connection enumeration failed"]),
        ]
        with mock.patch.object(pc, "_snapshot_once", side_effect=snapshots):
            result = pc.scan_processes(pc.CleanupPolicy(sample_sec=0.05))
        self.assertEqual(result.candidates, [])
        self.assertTrue(result.errors)


class TerminationSafetyTests(unittest.TestCase):
    @staticmethod
    def candidate(pid: int = 2001) -> pc.CleanupCandidate:
        record = make_record(pid, ("node", "vite", "--host", "127.0.0.1"))
        return replace(
            evaluate(record)[0],
            scanned_monotonic=pc.time.monotonic(),
        )

    def test_stale_scan_is_refused_before_any_live_or_process_call(self) -> None:
        candidate = replace(
            self.candidate(),
            scanned_monotonic=pc.time.monotonic() - 120,
        )
        policy = pc.CleanupPolicy(result_max_age_sec=1.0, grace_sec=0.1)
        with (
            mock.patch.object(pc, "_live_safety_block") as live_check,
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates([candidate], policy)
        self.assertEqual(report.items[0].status, "Skipped")
        self.assertIn("stale", report.items[0].message)
        live_check.assert_not_called()
        process.assert_not_called()

    def test_live_identity_drift_is_refused_without_termination(self) -> None:
        candidate = self.candidate(2101)
        with (
            mock.patch.object(
                pc, "_live_safety_block",
                return_value="PID 2101 identity changed"),
            mock.patch.object(pc, "_identity_matches") as identity_check,
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates(
                [candidate], pc.CleanupPolicy(grace_sec=0.1))
        self.assertIn("identity changed", report.items[0].message)
        identity_check.assert_not_called()
        process.assert_not_called()

    def test_new_child_after_scan_blocks_the_whole_group(self) -> None:
        root = make_record(
            2150, ("node", "vite", "--host", "127.0.0.1"))
        candidate = replace(
            evaluate(root)[0], scanned_monotonic=pc.time.monotonic())
        new_child = make_record(
            2151, ("helper", "--new"), name="helper.exe",
            ppid=root.pid, cpu_pct=0.0, memory_bytes=MIB)
        fresh = {root.pid: root, new_child.pid: new_child}
        with (
            mock.patch.object(pc, "_snapshot_once", return_value=(fresh, [])),
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates(
                [candidate], pc.CleanupPolicy(grace_sec=0.1))
        self.assertTrue(report.items[0].status.startswith("Skipped"))
        self.assertIn("new child", report.items[0].message)
        process.assert_not_called()

    def test_pid_reuse_after_live_snapshot_is_refused(self) -> None:
        candidate = self.candidate(2201)
        with (
            mock.patch.object(pc, "_live_safety_block", return_value=""),
            mock.patch.object(pc, "_identity_matches", return_value=False),
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates(
                [candidate], pc.CleanupPolicy(grace_sec=0.1))
        self.assertIn("identities no longer match", report.items[0].message)
        process.assert_not_called()

    def test_protected_candidate_is_refused_before_live_checks(self) -> None:
        candidate = replace(
            self.candidate(2301),
            classification=pc.CLASS_PROTECTED,
            protected_reason="Windows service",
        )
        with (
            mock.patch.object(pc, "_live_safety_block") as live_check,
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates([candidate])
        self.assertEqual(report.items[0].status, "Skipped")
        self.assertEqual(report.items[0].message, "Windows service")
        live_check.assert_not_called()
        process.assert_not_called()

    def test_info_candidate_is_refused_by_the_engine(self) -> None:
        candidate = replace(
            self.candidate(2350), classification=pc.CLASS_INFO)
        with (
            mock.patch.object(pc, "_live_safety_block") as live_check,
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates([candidate])
        self.assertEqual(report.items[0].status, "Skipped")
        live_check.assert_not_called()
        process.assert_not_called()

    def test_presignalled_termination_cancellation_calls_nothing(self) -> None:
        cancel = threading.Event()
        cancel.set()
        with (
            mock.patch.object(pc, "_live_safety_block") as live_check,
            mock.patch.object(pc.psutil, "Process") as process,
        ):
            report = pc.terminate_candidates(
                [self.candidate(2401)], cancel_event=cancel)
        self.assertTrue(report.cancelled)
        self.assertEqual(report.items, [])
        live_check.assert_not_called()
        process.assert_not_called()

    def test_selecting_one_exact_duplicate_never_terminates_its_sibling(
            self) -> None:
        command = ("node", "next", "dev", "-p", "3100")
        first = make_record(2501, command)
        sibling = make_record(2502, command)
        candidates = evaluate(first, sibling)
        selected = replace(
            next(item for item in candidates if item.root.pid == first.pid),
            scanned_monotonic=pc.time.monotonic(),
        )
        ended: set[int] = set()
        invoked: list[tuple[str, int]] = []

        class FakeProcess:
            def __init__(self, pid: int):
                self.pid = pid

            def terminate(self) -> None:
                invoked.append(("terminate", self.pid))
                ended.add(self.pid)

            def kill(self) -> None:
                invoked.append(("kill", self.pid))
                ended.add(self.pid)

        def identity_matches(identity: pc.ProcessIdentity) -> bool:
            return identity.pid not in ended

        with (
            mock.patch.object(pc, "_live_safety_block", return_value=""),
            mock.patch.object(
                pc, "_identity_matches", side_effect=identity_matches),
            mock.patch.object(
                pc.psutil, "Process", side_effect=lambda pid: FakeProcess(pid)),
        ):
            report = pc.terminate_candidates(
                [selected], pc.CleanupPolicy(grace_sec=0.1))

        self.assertEqual(report.items[0].status, "Ended")
        self.assertEqual(invoked, [("terminate", first.pid)])
        self.assertNotIn(sibling.pid, ended)

    def test_termination_implementation_has_no_broad_shell_kill_api(
            self) -> None:
        source = inspect.getsource(pc.terminate_candidates)
        self.assertNotIn("taskkill", source.casefold())
        tree = ast.parse(source)
        forbidden_names = {"system", "popen", "run", "call", "check_call"}
        observed = {
            node.func.attr.casefold()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(observed.isdisjoint(forbidden_names))


if __name__ == "__main__":
    unittest.main(verbosity=2)
