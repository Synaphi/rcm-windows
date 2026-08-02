from __future__ import annotations

import copy
from contextlib import redirect_stdout
import io
import tempfile
from pathlib import Path
import unittest

from scripts import check_bundle_manifest as bundle


class BundleManifestTests(unittest.TestCase):
    def test_repository_bundle_and_import_policy_are_exact(self) -> None:
        issues, blockers = bundle.validate_repository()
        self.assertEqual([], issues)
        tracked = bundle.parse_json_strict(
            (bundle.ROOT / bundle.BUNDLE_PATH).read_text(encoding="utf-8")
        )
        expected_blockers = {
            "not_built": [
                "candidate_not_built",
                "packaged_lifecycle_not_run",
            ],
            "built_unverified": ["packaged_lifecycle_not_run"],
            "frozen": [],
        }
        self.assertEqual(
            expected_blockers[tracked["candidate"]["state"]],
            blockers,
        )
        self.assertIs(
            False,
            tracked["candidate"]["local_admin_elevation_enabled"],
        )

    def test_bundle_allowlist_rejects_glob_absolute_external_and_duplicate(
        self,
    ) -> None:
        rejected = (
            "../outside",
            "/absolute",
            r"C:\Synthetic\absolute",
            r"\\synthetic-host\share",
            "src/**/*.json",
            "src/rcm/[ab].json",
            "src\\rcm\\data.json",
            ".git/config",
            "src/rcm/__pycache__/item",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(bundle.safe_relative_path(value))
        paths, issues = bundle._exact_safe_paths(
            ["src/rcm/data.json", "src/rcm/data.json"],
            label="synthetic allowlist",
        )
        self.assertEqual(
            ["src/rcm/data.json", "src/rcm/data.json"],
            paths,
        )
        self.assertTrue(issues)

    def test_unlisted_package_data_and_symlink_like_candidate_are_rejected(
        self,
    ) -> None:
        baseline = bundle.parse_json_strict(
            (bundle.ROOT / bundle.BUNDLE_PATH).read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory(prefix="rcm-bundle-test-") as temporary:
            root = Path(temporary)
            package = root / "src" / "rcm"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "data.json").write_text("{}\n", encoding="utf-8")
            (root / "THIRD_PARTY_NOTICES.md").write_text(
                "# Synthetic\n",
                encoding="utf-8",
            )
            issues, _ = bundle.bundle_data_issues(baseline, root=root)
        self.assertTrue(
            any("exactly equal" in issue for issue in issues),
            issues,
        )

        mutated = copy.deepcopy(baseline)
        mutated["candidate"]["state"] = "frozen"
        mutated["candidate"]["file"] = "../outside"
        mutated["candidate"]["size"] = 1
        mutated["candidate"]["sha256"] = "0" * 64
        mutated["candidate"]["public_source_snapshot_sha256"] = "0" * 64
        mutated["candidate"]["package_manifest_sha256"] = "0" * 64
        mutated["candidate"]["verification"]["passed_cycles"] = 100
        mutated["candidate"]["verification"]["evidence_sha256"] = "0" * 64
        mutated["candidate"]["blockers"] = []
        issues, _ = bundle.bundle_data_issues(mutated, root=bundle.ROOT)
        self.assertTrue(issues)

    def test_import_scanner_allows_stdlib_and_rcm_only_by_default(
        self,
    ) -> None:
        safe = "import json\nfrom rcm import identity\nfrom . import local\n"
        issues, dynamic = bundle.python_import_issues(
            safe,
            module_depth=2,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertEqual([], issues)
        self.assertEqual([], dynamic)

        external_issues, _ = bundle.python_import_issues(
            "import unreviewed_dependency\n",
            module_depth=1,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertTrue(external_issues)
        escape_issues, _ = bundle.python_import_issues(
            "from ...outside import value\n",
            module_depth=2,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertTrue(escape_issues)

    def test_dynamic_imports_are_detected_through_common_aliases(self) -> None:
        cases = (
            "import importlib as loader\nloader.import_module('synthetic')\n",
            "from importlib import import_module as load\nload('synthetic')\n",
        )
        for text in cases:
            with self.subTest(text=text.splitlines()[0]):
                issues, dynamic = bundle.python_import_issues(
                    text,
                    module_depth=1,
                    allowed_roots={"rcm"},
                    forbidden_calls={"__import__"},
                )
                self.assertEqual([], issues)
                self.assertEqual(["importlib.import_module"], dynamic)
        issues, _ = bundle.python_import_issues(
            "__import__('synthetic')\n",
            module_depth=1,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertTrue(issues)

    def test_dynamic_import_policy_rejects_builtins_and_assignment_bypasses(
        self,
    ) -> None:
        forbidden_cases = (
            "import builtins\nbuiltins.__import__('synthetic')\n",
            "from builtins import __import__ as load\nload('synthetic')\n",
            (
                "import builtins as runtime\n"
                "load = runtime.__import__\n"
                "load('synthetic')\n"
            ),
            (
                "import builtins\n"
                "getattr(builtins, '__import__')('synthetic')\n"
            ),
            (
                "import builtins\n"
                "builtins.__dict__['__import__']('synthetic')\n"
            ),
            (
                "import builtins\n"
                "g = getattr\n"
                "g(builtins, '__import__')('synthetic')\n"
            ),
            (
                "import builtins\n"
                "vars(builtins)['__import__']('synthetic')\n"
            ),
            (
                "import builtins\n"
                "getattr(builtins, '__' + 'import__')('synthetic')\n"
            ),
            "vars(__builtins__)['__import__']('synthetic')\n",
        )
        for text in forbidden_cases:
            with self.subTest(text=text.splitlines()[0]):
                issues, _ = bundle.python_import_issues(
                    text,
                    module_depth=1,
                    allowed_roots={"rcm"},
                    forbidden_calls={"__import__"},
                )
                self.assertTrue(issues)

        assigned = (
            "import importlib\n"
            "load = importlib.import_module\n"
            "load('synthetic.one')\n"
            "load('synthetic.two')\n"
        )
        issues, dynamic = bundle.python_import_issues(
            assigned,
            module_depth=1,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertEqual([], issues)
        self.assertEqual(
            ["importlib.import_module", "importlib.import_module"],
            dynamic,
        )
        reflected = (
            "import importlib\n"
            "load = getattr(importlib, 'import_module')\n"
            "load('synthetic')\n"
        )
        reflected_issues, reflected_dynamic = bundle.python_import_issues(
            reflected,
            module_depth=1,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertEqual([], reflected_issues)
        self.assertEqual(["importlib.import_module"], reflected_dynamic)
        reflected_alias = (
            "import importlib\n"
            "g = getattr\n"
            "load = g(importlib, 'import_' + 'module')\n"
            "load('synthetic')\n"
        )
        alias_issues, alias_dynamic = bundle.python_import_issues(
            reflected_alias,
            module_depth=1,
            allowed_roots={"rcm"},
            forbidden_calls={"__import__"},
        )
        self.assertEqual([], alias_issues)
        self.assertEqual(["importlib.import_module"], alias_dynamic)

    def test_import_policy_exception_is_path_and_count_exact(self) -> None:
        baseline = bundle.parse_json_strict(
            (bundle.ROOT / bundle.IMPORT_POLICY_PATH).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            [],
            bundle.import_policy_issues(baseline, root=bundle.ROOT),
        )
        for mutation in (
            ("count", 2),
            ("path", "src/rcm/other.py"),
            ("call", "__import__"),
        ):
            mutated = copy.deepcopy(baseline)
            mutated["allowed_dynamic_import_calls"][0][mutation[0]] = mutation[1]
            with self.subTest(mutation=mutation[0]):
                self.assertTrue(
                    bundle.import_policy_issues(mutated, root=bundle.ROOT)
                )

    def test_duplicate_packaging_json_key_is_rejected(self) -> None:
        baseline = (bundle.ROOT / bundle.BUNDLE_PATH).read_text(
            encoding="utf-8"
        )
        mutated = baseline.replace(
            '"schema_version": 4,',
            '"schema_version": 0,\n  "schema_version": 4,',
            1,
        )
        with self.assertRaises(ValueError):
            bundle.parse_json_strict(mutated)

    def test_structure_and_required_frozen_gate_follow_candidate_state(
        self,
    ) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, bundle.main([]))
        self.assertIn("PASS:", output.getvalue())
        tracked = bundle.parse_json_strict(
            (bundle.ROOT / bundle.BUNDLE_PATH).read_text("utf-8")
        )
        frozen = tracked["candidate"]["state"] == "frozen"
        self.assertEqual(not frozen, "NOT RUN:" in output.getvalue())

        required_output = io.StringIO()
        with redirect_stdout(required_output):
            self.assertEqual(
                0 if frozen else 1,
                bundle.main(["--require-frozen-candidate"]),
            )
        self.assertIn("PASS:", required_output.getvalue())
        self.assertEqual(not frozen, "FAIL:" in required_output.getvalue())


if __name__ == "__main__":
    unittest.main()
