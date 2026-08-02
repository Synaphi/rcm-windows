from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "characterization_contract.json"
PROBE_PATH = ROOT / "tests" / "legacy_characterization_probe.py"
PROBE_SEEDS = ("0", "1", "4294967295")
PROBE_TIMEOUT_SECONDS = 60
CONTRACT_KEYS = (
    "config_migration",
    "endpoints",
    "ray_commands",
    "rdp",
    "cleanup",
    "update_order",
    "singleton_shutdown",
    "ui_geometry_dpi",
    "safety",
)
PRODUCTION_PATHS = (
    "process_cleanup.py",
    "process_cleanup_ui.py",
    "ray_monitor.py",
    "release_info.py",
    "sensor_poller.py",
    "status_board_content.py",
    "temps_server.py",
    "windows_credentials.py",
)
SAFE_PROBE_ERROR_TYPES = {
    "AssertionError",
    "AttributeError",
    "FileNotFoundError",
    "ImportError",
    "KeyError",
    "ModuleNotFoundError",
    "NameError",
    "OSError",
    "RuntimeError",
    "SystemExit",
    "TypeError",
    "ValueError",
}
SAFE_PROBE_DIAGNOSTIC_PATHS = frozenset(
    (*PRODUCTION_PATHS, "tests/legacy_characterization_probe.py")
)
PROBE_DIAGNOSTIC_MARKER = "RCM_SYNTHETIC_PROBE_ERROR_V1"


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_fixture() -> dict[str, object]:
    return json.loads(
        FIXTURE_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object,
    )


def _minimal_child_environment(root: Path, seed: str) -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC")
        if key in os.environ
    }
    environment.update(
        {
            "APPDATA": str(root / "appdata"),
            "LOCALAPPDATA": str(root / "localappdata"),
            "USERPROFILE": str(root / "profile"),
            "HOME": str(root / "profile"),
            "TEMP": str(root / "temp"),
            "TMP": str(root / "temp"),
            "RCM_CHARACTERIZATION_ROOT": str(root),
            "RCM_SKIP_UAC_FOR_TESTS": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": seed,
        }
    )
    return environment


def _stream_evidence(text: str) -> str:
    payload = text.encode("utf-8", errors="surrogatepass")
    return (
        f"bytes={len(payload)},"
        f"sha256={hashlib.sha256(payload).hexdigest()}"
    )


def _probe_command(emulate_missing_windll: bool) -> list[str]:
    compatibility_setup = ""
    if emulate_missing_windll:
        compatibility_setup = (
            "import ctypes\n"
            "if hasattr(ctypes, 'WinDLL'):\n"
            "    delattr(ctypes, 'WinDLL')\n"
        )
    diagnostic_wrapper = (
        "import json, pathlib, sys\n"
        f"_root = pathlib.Path({json.dumps(str(ROOT))}).resolve()\n"
        f"_probe = pathlib.Path({json.dumps(str(PROBE_PATH))}).resolve()\n"
        f"_marker = {json.dumps(PROBE_DIAGNOSTIC_MARKER)}\n"
        f"{compatibility_setup}"
        "def _emit_probe_error(_exc):\n"
        "    _frames = []\n"
        "    _traceback = _exc.__traceback__\n"
        "    while _traceback is not None:\n"
        "        try:\n"
        "            _relative = pathlib.Path("
        "_traceback.tb_frame.f_code.co_filename).resolve()"
        ".relative_to(_root).as_posix()\n"
        "        except ValueError:\n"
        "            pass\n"
        "        else:\n"
        "            _frames.append([_relative, _traceback.tb_lineno])\n"
        "        _traceback = _traceback.tb_next\n"
        "    _payload = {\n"
        "        'marker': _marker,\n"
        "        'error_type': type(_exc).__name__,\n"
        "        'frames': _frames,\n"
        "    }\n"
        "    sys.stderr.write(json.dumps("
        "_payload, ensure_ascii=True, sort_keys=True, separators=(',', ':')))\n"
        "    raise SystemExit(1)\n"
        "_source = _probe.read_bytes()\n"
        "_code = compile(_source, str(_probe), 'exec')\n"
        "sys.path[0] = str(_probe.parent)\n"
        "_globals = {\n"
        "    '__name__': '__main__',\n"
        "    '__file__': str(_probe),\n"
        "    '__package__': None,\n"
        "    '__cached__': None,\n"
        "}\n"
        "try:\n"
        "    exec(_code, _globals)\n"
        "except SystemExit as _exc:\n"
        "    if _exc.code in (None, 0):\n"
        "        raise\n"
        "    _emit_probe_error(_exc)\n"
        "except BaseException as _exc:\n"
        "    _emit_probe_error(_exc)\n"
    )
    return [sys.executable, "-B", "-c", diagnostic_wrapper]


def _safe_probe_diagnostic(stderr: str) -> str:
    try:
        payload = json.loads(stderr, object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, ValueError):
        return ""
    if (
        not isinstance(payload, dict)
        or set(payload) != {"marker", "error_type", "frames"}
        or payload.get("marker") != PROBE_DIAGNOSTIC_MARKER
    ):
        return ""
    error_type = payload.get("error_type")
    if error_type not in SAFE_PROBE_ERROR_TYPES:
        error_type = "UnknownError"
    frames = payload.get("frames")
    if not isinstance(frames, list) or not frames or len(frames) > 32:
        return ""
    safe_frames: list[tuple[str, int]] = []
    for frame in frames:
        if (
            not isinstance(frame, list)
            or len(frame) != 2
            or not isinstance(frame[0], str)
            or isinstance(frame[1], bool)
            or not isinstance(frame[1], int)
            or frame[1] < 1
            or frame[1] > 1_000_000
        ):
            return ""
        if frame[0] in SAFE_PROBE_DIAGNOSTIC_PATHS:
            safe_frames.append((frame[0], frame[1]))
    if not safe_frames:
        return ""
    path, line = safe_frames[-1]
    return f", detail={error_type}@{path}:{line}"


def _run_probe(
        seed: str,
        expected_digest: str,
        *,
        emulate_missing_windll: bool = False,
) -> tuple[dict[str, object], str, bool]:
    sandbox_path: Path | None = None
    with tempfile.TemporaryDirectory(
            prefix="rcm-pr04-characterization-") as temporary:
        sandbox_path = Path(temporary)
        for name in ("appdata", "localappdata", "profile", "temp"):
            (sandbox_path / name).mkdir()
        try:
            result = subprocess.run(
                _probe_command(emulate_missing_windll),
                cwd=ROOT,
                env=_minimal_child_environment(sandbox_path, seed),
                text=True,
                encoding="utf-8",
                errors="strict",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "isolated characterization probe timed out "
                f"(seed={seed}, timeout={PROBE_TIMEOUT_SECONDS})"
            ) from None
        except UnicodeError:
            raise AssertionError(
                "isolated characterization probe output was not UTF-8 "
                f"(seed={seed})"
            ) from None
        except OSError:
            raise AssertionError(
                "isolated characterization probe could not start "
                f"(seed={seed})"
            ) from None
        if result.returncode != 0:
            diagnostic = _safe_probe_diagnostic(result.stderr)
            raise AssertionError(
                "isolated characterization probe failed "
                f"(seed={seed}, exit={result.returncode}, "
                f"stderr-{_stream_evidence(result.stderr)}{diagnostic})"
            )
        if result.stderr:
            raise AssertionError(
                "isolated characterization probe wrote stderr "
                f"(seed={seed}, {_stream_evidence(result.stderr)})"
            )
        canonical = result.stdout.strip()
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if digest != expected_digest:
            raise AssertionError(
                "isolated characterization probe snapshot SHA-256 mismatch "
                f"(seed={seed}, {_stream_evidence(canonical)})"
            )
        try:
            snapshot = json.loads(
                canonical,
                object_pairs_hook=_strict_object,
            )
        except (json.JSONDecodeError, ValueError):
            raise AssertionError(
                "isolated characterization probe emitted invalid JSON "
                f"(seed={seed}, {_stream_evidence(canonical)})"
            ) from None
    assert sandbox_path is not None
    return snapshot, digest, not sandbox_path.exists()


def _production_digests() -> dict[str, str]:
    return {
        relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        for relative in PRODUCTION_PATHS
    }


class LegacyCharacterizationContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.fixture = _load_fixture()
        cls.production_before = _production_digests()
        cls.runs = [
            _run_probe(seed, cls.fixture["snapshot_sha256"])
            for seed in PROBE_SEEDS
        ]
        cls.production_after = _production_digests()
        cls.snapshot = cls.runs[0][0]

    def test_probe_is_cross_process_deterministic_and_cleans_sandbox(
            self) -> None:
        snapshots = [snapshot for snapshot, _digest, _clean in self.runs]
        digests = [digest for _snapshot, digest, _clean in self.runs]
        cleanup = [clean for _snapshot, _digest, clean in self.runs]
        self.assertEqual(1, len({
            json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
            for snapshot in snapshots
        }))
        self.assertEqual(
            [self.fixture["snapshot_sha256"]] * len(PROBE_SEEDS),
            digests,
        )
        self.assertEqual([True] * len(PROBE_SEEDS), cleanup)

    def test_probe_runs_without_ctypes_windll(self) -> None:
        snapshot, digest, clean = _run_probe(
            "0",
            self.fixture["snapshot_sha256"],
            emulate_missing_windll=True,
        )
        self.assertEqual(self.snapshot, snapshot)
        self.assertEqual(self.fixture["snapshot_sha256"], digest)
        self.assertTrue(clean)

    def test_probe_failure_diagnostics_do_not_echo_child_data(self) -> None:
        untrusted = "SYNTHETIC_UNTRUSTED_CHILD_DETAIL"
        cases = (
            {
                "result": subprocess.CompletedProcess(
                    ["UNTRUSTED_COMMAND"],
                    7,
                    stdout="",
                    stderr=untrusted,
                ),
                "side_effect": None,
                "expected": "exit=7",
            },
            {
                "result": subprocess.CompletedProcess(
                    ["UNTRUSTED_COMMAND"],
                    0,
                    stdout="{}",
                    stderr=untrusted,
                ),
                "side_effect": None,
                "expected": "wrote stderr",
            },
            {
                "result": subprocess.CompletedProcess(
                    ["UNTRUSTED_COMMAND"],
                    0,
                    stdout=untrusted,
                    stderr="",
                ),
                "side_effect": None,
                "expected": "snapshot SHA-256 mismatch",
            },
            {
                "result": subprocess.CompletedProcess(
                    ["UNTRUSTED_COMMAND"],
                    0,
                    stdout=json.dumps({"detail": untrusted}),
                    stderr="",
                ),
                "side_effect": None,
                "expected": "snapshot SHA-256 mismatch",
            },
            {
                "result": None,
                "side_effect": subprocess.TimeoutExpired(
                    ["UNTRUSTED_COMMAND"],
                    PROBE_TIMEOUT_SECONDS,
                    stderr=untrusted,
                ),
                "expected": "timed out",
            },
            {
                "result": None,
                "side_effect": OSError(untrusted),
                "expected": "could not start",
            },
            {
                "result": None,
                "side_effect": UnicodeDecodeError(
                    "utf-8",
                    b"\xff",
                    0,
                    1,
                    untrusted,
                ),
                "expected": "was not UTF-8",
            },
        )
        for case in cases:
            with self.subTest(expected=case["expected"]):
                with mock.patch.object(
                    subprocess,
                    "run",
                    return_value=case["result"],
                    side_effect=case["side_effect"],
                ):
                    with self.assertRaises(AssertionError) as caught:
                        _run_probe("0", self.fixture["snapshot_sha256"])
                diagnostic = str(caught.exception)
                self.assertIn(case["expected"], diagnostic)
                self.assertNotIn(untrusted, diagnostic)
                self.assertNotIn("UNTRUSTED_COMMAND", diagnostic)
        safe_payload = json.dumps(
            {
                "marker": PROBE_DIAGNOSTIC_MARKER,
                "error_type": "RuntimeError",
                "frames": [
                    ["tests/legacy_characterization_probe.py", 101],
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual(
            ", detail=RuntimeError@tests/legacy_characterization_probe.py:101",
            _safe_probe_diagnostic(safe_payload),
        )
        unsafe_payload = json.dumps(
            {
                "marker": PROBE_DIAGNOSTIC_MARKER,
                "error_type": untrusted,
                "frames": [[untrusted, 101]],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertEqual("", _safe_probe_diagnostic(unsafe_payload))

    def test_config_load_and_migration_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["config_migration"],
            self.snapshot["config_migration"],
        )

    def test_health_and_metrics_schema_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["endpoints"],
            self.snapshot["endpoints"],
        )

    def test_ray_start_join_stop_command_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["ray_commands"],
            self.snapshot["ray_commands"],
        )

    def test_rdp_target_user_port_file_and_launch_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["rdp"],
            self.snapshot["rdp"],
        )

    def test_cleanup_classification_and_stale_preflight_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["cleanup"],
            self.snapshot["cleanup"],
        )

    def test_worker_first_head_last_update_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["update_order"],
            self.snapshot["update_order"],
        )

    def test_singleton_and_shutdown_observable_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["singleton_shutdown"],
            self.snapshot["singleton_shutdown"],
        )

    def test_compact_ui_geometry_and_dpi_contract(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["ui_geometry_dpi"],
            self.snapshot["ui_geometry_dpi"],
        )

    def test_probe_reports_zero_live_or_source_mutation(self) -> None:
        self.assertEqual(
            self.fixture["contracts"]["safety"],
            self.snapshot["safety"],
        )
        self.assertEqual([], self.snapshot["safety"]["audit_blocks"])
        self.assertEqual(self.production_before, self.production_after)

    def test_legacy_suite_inventory_is_exact(self) -> None:
        actual = []
        expected_by_path = {
            item["path"]: item
            for item in self.fixture["legacy_suite_inventory"]
        }
        for path in sorted(ROOT.glob("test_*.py")):
            tree = ast.parse(
                path.read_text(encoding="utf-8"),
                filename=path.name,
            )
            count = sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_")
                for node in ast.walk(tree)
            )
            expected = expected_by_path.get(path.name)
            self.assertIsNotNone(
                expected,
                f"unclassified legacy test file: {path.name}",
            )
            actual.append(
                {
                    "path": path.name,
                    "test_functions": count,
                    "execution_class": expected["execution_class"],
                }
            )
        self.assertEqual(self.fixture["legacy_suite_inventory"], actual)
        self.assertEqual(18, len(actual))
        self.assertEqual(153, sum(item["test_functions"] for item in actual))

    def test_source_text_assertions_are_preserved_and_marked_for_replacement(
            self) -> None:
        record = self.fixture["source_text_assertions"]
        self.assertEqual(
            "PRESERVED_PENDING_BEHAVIOR_REPLACEMENT",
            record["status"],
        )
        self.assertEqual(
            "PR-05-through-PR-25-service-and-ui-extraction",
            record["replacement_boundary"],
        )
        for relative in record["files"]:
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertTrue(
                any(marker in text for marker in (
                    "inspect.getsource",
                    "open(rm.__file__",
                    "open(wc.__file__",
                    "RayClusterManager.spec",
                    "self_update_helper.ps1",
                )),
                relative,
            )

    def test_isolated_source_smoke_passes_and_packaged_smoke_is_deferred(
            self) -> None:
        matrix = self.fixture["smoke_matrix"]
        self.assertEqual("PASS", matrix["isolated_source_child"]["status"])
        self.assertEqual("NOT_RUN", matrix["packaged_executable"]["status"])
        self.assertIn(
            "does not authorize build",
            matrix["packaged_executable"]["reason"],
        )

    def test_fixture_is_canonical_synthetic_and_complete(self) -> None:
        self.assertEqual(1, self.fixture["schema_version"])
        self.assertEqual(
            "frozen-sanitized-1.x",
            self.fixture["baseline"],
        )
        self.assertEqual(
            set(CONTRACT_KEYS),
            set(self.fixture["contracts"]),
        )
        raw = FIXTURE_PATH.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("utf-8")
        for forbidden in (
            "10.0.",
            "10.1.",
            "100.64.",
            "\\Users\\",
            "/home/",
            "secret-value",
            "credential_blob",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
