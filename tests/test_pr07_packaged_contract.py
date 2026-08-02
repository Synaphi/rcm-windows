from __future__ import annotations

import ast
from dataclasses import fields
import importlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from rcm.adapters import windows_admin
from fake_test_kit.guard import NoLiveAccessGuard
from rcm.adapters.windows_credentials import CredentialMetadata
from rcm.privilege import (
    CHALLENGE_LIFETIME_SECONDS,
    HELPER_EXIT_SECONDS,
    MAX_BROKER_REQUEST_BYTES,
    OPERATION_DEADLINE_SECONDS,
    PrivilegedOperation,
)


ROOT = Path(__file__).parents[1]
PRODUCTION_PATHS = (
    "src/rcm/privilege.py",
    "src/rcm/local_admin.py",
    "src/rcm/replacement.py",
    "src/rcm/adapters/local.py",
    "src/rcm/adapters/windows_broker.py",
    "src/rcm/adapters/windows_admin.py",
    "src/rcm/adapters/windows_credentials.py",
)
MODULES = (
    "rcm.privilege",
    "rcm.local_admin",
    "rcm.replacement",
    "rcm.adapters.local",
    "rcm.adapters.windows_broker",
    "rcm.adapters.windows_admin",
    "rcm.adapters.windows_credentials",
)


class PackagedPrivilegeContractTests(unittest.TestCase):
    def test_firewall_cmdlets_use_trusted_module_and_sanitized_environment(
        self,
    ) -> None:
        completed = SimpleNamespace(returncode=0, stdout="absent\n" * 3)
        with (
            NoLiveAccessGuard(),
            mock.patch.object(
                windows_admin._WindowsPrivateFirewallPolicy,
                "_executable",
                return_value=(
                    r"C:\Windows\System32\WindowsPowerShell"
                    r"\v1.0\powershell.exe"
                ),
            ),
            mock.patch("subprocess.run", return_value=completed) as run,
        ):
            result = windows_admin._WindowsPrivateFirewallPolicy._run()

        self.assertEqual(("absent",) * 3, result)
        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertIsInstance(argv, tuple)
        self.assertEqual(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            argv[0],
        )
        self.assertIn(
            r"Modules\NetSecurity\NetSecurity.psd1",
            argv[-1],
        )
        self.assertNotIn("Get-NetFirewallRule", argv[-1].replace(
            r"NetSecurity\Get-NetFirewallRule", ""))
        self.assertEqual(
            {"SystemRoot", "WINDIR", "PSModulePath"},
            set(options["env"]),
        )
        self.assertIs(False, options["shell"])
        self.assertEqual(15, options["timeout"])

    def test_owned_production_manifest_is_exact_and_import_safe(self) -> None:
        self.assertEqual(7, len(PRODUCTION_PATHS))
        for relative in PRODUCTION_PATHS:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file())
        modules = [importlib.import_module(name) for name in MODULES]
        with NoLiveAccessGuard():
            for module in modules:
                with self.subTest(module=module.__name__):
                    self.assertIs(module, importlib.import_module(module.__name__))

    def test_import_dependencies_have_no_ui_network_or_ray_runtime(self) -> None:
        forbidden = {"tkinter", "socket", "requests", "ray"}
        for relative in PRODUCTION_PATHS:
            tree = ast.parse(
                (ROOT / relative).read_text(encoding="utf-8"),
                filename=relative,
            )
            imported: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(
                        alias.name.split(".", 1)[0] for alias in node.names
                    )
                elif (
                    isinstance(node, ast.ImportFrom)
                    and node.level == 0
                    and node.module
                ):
                    imported.add(node.module.split(".", 1)[0])
            self.assertEqual(set(), imported & forbidden, relative)

    def test_privileged_semantics_and_broker_limits_are_frozen(self) -> None:
        self.assertEqual(
            (
                "rdp_host_apply",
                "private_firewall_apply",
            ),
            tuple(item.value for item in PrivilegedOperation),
        )
        self.assertEqual(65_536, MAX_BROKER_REQUEST_BYTES)
        self.assertEqual(30.0, CHALLENGE_LIFETIME_SECONDS)
        self.assertEqual(120.0, OPERATION_DEADLINE_SECONDS)
        self.assertEqual(5.0, HELPER_EXIT_SECONDS)

    def test_pipe_is_local_exclusive_explicit_dacl_and_pid_bound(self) -> None:
        source = (ROOT / "src/rcm/adapters/windows_broker.py").read_text(
            encoding="utf-8"
        )
        local_pipe_marker = chr(92) * 2 + "." + chr(92) + "pipe"
        required = (
            local_pipe_marker,
            "CreateNamedPipeW",
            "D:P(A;;GA;;;",
            "0x00080000",
            "0x00000008",
            "GetNamedPipeClientProcessId",
            "GetNamedPipeServerProcessId",
            "SECURITY_IDENTIFICATION",
        )
        for marker in required:
            with self.subTest(marker=marker):
                if marker == "SECURITY_IDENTIFICATION":
                    self.assertIn("0x00110000", source)
                else:
                    self.assertIn(marker, source)
        self.assertNotIn("AF_INET", source)
        self.assertNotIn("AF_INET6", source)
        self.assertNotIn("0.0.0.0", source)

    def test_fixed_admin_process_launch_is_tuple_only_and_shell_false(self) -> None:
        admin_tree = ast.parse(
            (
                ROOT / "src/rcm/adapters/windows_admin.py"
            ).read_text(encoding="utf-8")
        )
        fixed_calls = [
            node for node in ast.walk(admin_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr == "run"
        ]
        self.assertEqual(1, len(fixed_calls))
        self.assertIsInstance(fixed_calls[0].args[0], ast.Tuple)
        fixed_shell = next(
            keyword.value for keyword in fixed_calls[0].keywords
            if keyword.arg == "shell"
        )
        self.assertIsInstance(fixed_shell, ast.Constant)
        self.assertIs(False, fixed_shell.value)
        all_source = "\n".join(
            (ROOT / relative).read_text(encoding="utf-8")
            for relative in PRODUCTION_PATHS
        )
        self.assertNotIn("shell=True", all_source)
        self.assertNotIn("os.system", all_source)

    def test_replacement_has_no_effect_or_privileged_action(self) -> None:
        source = (ROOT / "src/rcm/replacement.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual({"re"}, imported)
        for forbidden in (
            "subprocess",
            "ctypes",
            "winreg",
            "PrivilegeRequest",
            "PrivilegedOperation",
            "ShellExecute",
            "replace(",
            "unlink(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_credential_public_metadata_has_no_secret_value_field_or_logging(self) -> None:
        self.assertEqual(
            {"reference", "present", "principal_matches"},
            {field.name for field in fields(CredentialMetadata)},
        )
        source = (
            ROOT / "src/rcm/adapters/windows_credentials.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "print":
                forbidden_calls.append(node)
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {
                    "debug",
                    "info",
                    "warning",
                    "error",
                    "exception",
                    "critical",
                }
            ):
                forbidden_calls.append(node)
        self.assertEqual([], forbidden_calls)
        self.assertNotIn("logging", source)

    def test_new_functions_stay_bounded(self) -> None:
        for relative in PRODUCTION_PATHS:
            tree = ast.parse(
                (ROOT / relative).read_text(encoding="utf-8"),
                filename=relative,
            )
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    length = (node.end_lineno or node.lineno) - node.lineno + 1
                    with self.subTest(path=relative, function=node.name):
                        self.assertLessEqual(length, 120)


if __name__ == "__main__":
    unittest.main()
