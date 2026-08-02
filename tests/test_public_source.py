from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "check_public_source.py"
EXPORTER_PATH = ROOT / "scripts" / "export_public_source.py"
HAS_STAGING_EXPORTER = (
    EXPORTER_PATH.is_file()
    and (ROOT / "policy/public-export-source-map.json").is_file()
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


checker = load_module("rcm_public_source_checker", CHECKER_PATH)
exporter = (
    load_module("rcm_public_source_exporter", EXPORTER_PATH)
    if HAS_STAGING_EXPORTER
    else None
)


class PublicTreeMixin:
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory(prefix="rcm-public-test-")
        if HAS_STAGING_EXPORTER:
            cls.public_root = Path(cls._temporary.name) / "source"
            cls.export_result = exporter.export_tree(
                cls.public_root,
                root=ROOT,
                require_clean=False,
                verify=True,
            )
        else:
            cls.public_root = ROOT
            cls.export_result = None

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def copy_public_tree(self) -> Path:
        destination = Path(self._temporary.name) / self.id().replace(".", "-")
        allowlist, issues = checker.load_allowlist(self.public_root)
        self.assertEqual([], issues)
        for relative in allowlist:
            source = self.public_root / Path(relative)
            target = destination / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return destination


class PublicSourceContractTests(PublicTreeMixin, unittest.TestCase):
    def test_public_tree_passes_exact_contract(self) -> None:
        self.assertEqual([], checker.validate_public_tree(self.public_root))
        allowlist, issues = checker.load_allowlist(self.public_root)
        self.assertEqual([], issues)
        self.assertEqual(160, len(allowlist))
        self.assertEqual(
            checker.EXPECTED_PATH_DIGEST,
            checker._path_digest(allowlist),
        )

    def test_public_tree_has_no_private_staging_contract(self) -> None:
        forbidden = {
            ".github/CODEOWNERS",
            ".github/workflows/repository-policy.yml",
            "policy/private-staging-exclusions.txt",
            "policy/public-export-source-map.json",
            "policy/repository-governance.json",
            "scripts/check_repository_policy.py",
            "scripts/export_public_source.py",
            "tests/test_repository_policy.py",
        }
        for relative in forbidden:
            self.assertFalse((self.public_root / Path(relative)).exists(), relative)
        self.assertTrue((self.public_root / "AGENTS.md").is_file())
        self.assertFalse((self.public_root / "AGENTS.public.md").exists())

    def test_canonical_apache_license_is_exact(self) -> None:
        data = (self.public_root / "LICENSE").read_bytes()
        self.assertEqual(checker.EXPECTED_LICENSE_BYTES, len(data))
        self.assertEqual(
            checker.EXPECTED_LICENSE_SHA256,
            __import__("hashlib").sha256(data).hexdigest(),
        )

    def test_unknown_and_missing_paths_fail_closed(self) -> None:
        tree = self.copy_public_tree()
        (tree / "unexpected.txt").write_text("synthetic\n", encoding="utf-8")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("unexpected public source path" in item for item in issues))
        (tree / "unexpected.txt").unlink()
        (tree / "LICENSE").unlink()
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("missing public source path" in item for item in issues))

    def test_license_and_private_marker_mutations_fail(self) -> None:
        tree = self.copy_public_tree()
        license_path = tree / "LICENSE"
        license_path.write_bytes(license_path.read_bytes() + b"mutation\n")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("LICENSE" in item for item in issues))

        tree = self.copy_public_tree()
        marker = "Synaphi" + "/" + "RayClusterManager"
        with (tree / "README.md").open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(marker + "\n")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("staging repository marker" in item for item in issues))

        tree = self.copy_public_tree()
        with (tree / "README.md").open(
            "a", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write("audit object " + ("a" * 40) + "\n")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("Git object identity" in item for item in issues))

    def test_python_credentials_addresses_and_comments_fail(self) -> None:
        tree = self.copy_public_tree()
        field = "token"
        payload = f'AUDIT_{field.upper()} = "audit-nonpublic-value"\n'
        with (tree / "src/rcm/core.py").open(
            "a", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(payload)
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("sensitive assignment" in item for item in issues))

        tree = self.copy_public_tree()
        private_address = bytes(
            (49, 48, 46, 50, 51, 46, 52, 53, 46, 54, 55)
        ).decode("ascii")
        with (tree / "tests/test_pr06_core.py").open(
            "a", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(f'AUDIT_ADDRESS = "{private_address}"\n')
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("private address" in item for item in issues))

        tree = self.copy_public_tree()
        private_comment = "# audit address " + bytes(
            (49, 57, 50, 46, 49, 54, 56, 46, 55, 46, 57, 10)
        ).decode("ascii")
        with (tree / "src/rcm/core.py").open(
            "a", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(private_comment)
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("comment" in item for item in issues))

    def test_python_sensitive_forms_match_the_deny_vocabulary(self) -> None:
        value = "audit-nonpublic-value"
        field_a, field_b, field_c, field_d = (
            "token", "credential", "host", "password"
        )
        mutations = {
            "token assignment": f'AUDIT_{field_a.upper()} = "{value}"\n',
            "credential assignment": (
                f'AUDIT_{field_b.upper()} = "{value}"\n'
            ),
            "host assignment": f'AUDIT_{field_c.upper()} = "{value}"\n',
            "function default": (
                f'def audit_probe({field_d}="{value}"):\n    pass\n'
            ),
            "call keyword": f'audit_probe({field_a}="{value}")\n',
            "sensitive comment": f"# {field_d} = {value}\n",
            "sensitive string": (
                f'payload = "{field_b} = {value}"\n'
            ),
        }
        extended_names = (
            "_".join((field_a, "value")),
            "_".join((field_d, "value")),
            "_".join((field_d, "hash")),
            "_".join((field_b, "ref")),
            "_".join((field_c, "name")),
            "_".join(("remote", field_c, "name")),
            "_".join(("username", "value")),
        )
        for name in extended_names:
            mutations[f"extended name {name}"] = f'{name} = "{value}"\n'
        for name in (
            "-".join((field_a, "value")),
            "-".join((field_c, "name")),
            "-".join(("api", "key")),
        ):
            mutations[f"mapping key {name}"] = (
                f'payload = {{"{name}": "{value}"}}\n'
            )
        slash = chr(92)
        forward = chr(47)
        absolute_paths = (
            "C:" + slash + "Audit" + slash + "secret",
            "R:" + slash + "audit" + slash + "node",
            slash * 2 + "audit-server" + slash + "audit-share",
            forward + "root" + forward + "audit",
        )
        for path in absolute_paths:
            mutations[f"absolute path {path}"] = f"payload = {path!r}\n"
        for label, source in mutations.items():
            with self.subTest(label=label):
                self.assertTrue(
                    checker._python_literal_issues("src/rcm/core.py", source)
                )
        for source in (
            'host = "localhost"\n',
            'password = "disabled"\n',
            'user = "synthetic-operator"\n',
            f"payload = {('R:' + slash + 'synthetic' + slash + 'node')!r}\n",
            f"payload = {('C:' + slash + 'Windows')!r}\n",
            f"payload = {('C:' + slash + 'Windows' + slash + 'Temp')!r}\n",
            f"payload = {(slash * 2 + '.' + slash + 'pipe' + slash)!r}\n",
            f"payload = {(slash * 2 + '.' + slash + 'pipe' + slash + 'rcm-control')!r}\n",
            f"payload = {(slash * 2 + 'example' + slash + 'share')!r}\n",
            f"payload = {(forward + 'root' + forward + 'synthetic')!r}\n",
        ):
            with self.subTest(safe=source.strip()):
                self.assertEqual(
                    [], checker._python_literal_issues("src/rcm/core.py", source)
                )

    def test_deny_policy_removal_fails_closed(self) -> None:
        tree = self.copy_public_tree()
        (tree / "policy/public-export-deny-patterns.txt").write_text(
            "# intentionally empty mutation\n",
            encoding="utf-8",
            newline="\n",
        )
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("deny policy" in item for item in issues))

    def test_git_inventory_reports_untracked_and_ignored_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rcm-public-git-") as temporary:
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True
            )
            (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            (root / "unknown.txt").write_text("unknown\n", encoding="utf-8")
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            (root / ".env").write_text("ignored\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "--", "tracked.txt", ".gitignore"],
                cwd=root,
                check=True,
            )
            files, issues = checker._git_inventory(root)
            self.assertIn("unknown.txt", files)
            self.assertIn(".env", files)
            self.assertTrue(any("untracked" in item for item in issues))

    def test_denied_archive_and_symlink_fail(self) -> None:
        tree = self.copy_public_tree()
        archive = tree / "dist" / "candidate.zip"
        archive.parent.mkdir()
        archive.write_bytes(b"synthetic")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("deny policy" in item for item in issues))

        tree = self.copy_public_tree()
        link = tree / "README-link.md"
        try:
            link.symlink_to(tree / "README.md")
        except OSError:
            self.skipTest("symlink creation is unavailable on this runner")
        issues = checker.validate_public_tree(tree)
        self.assertTrue(any("symlink" in item for item in issues))


@unittest.skipUnless(HAS_STAGING_EXPORTER, "private staging exporter is absent")
class PrivateStagingExporterTests(unittest.TestCase):
    def test_partition_mapping_and_two_exports_are_exact(self) -> None:
        destinations, exclusions, mapping = exporter.validate_staging_contract(
            ROOT,
            require_clean=False,
        )
        self.assertEqual(160, len(destinations))
        self.assertEqual(20, len(exclusions))
        self.assertEqual({"AGENTS.md": "AGENTS.public.md"}, mapping)
        with tempfile.TemporaryDirectory(prefix="rcm-export-pair-") as temporary:
            first = exporter.export_tree(
                Path(temporary) / "first",
                root=ROOT,
                require_clean=False,
            )
            second = exporter.export_tree(
                Path(temporary) / "second",
                root=ROOT,
                require_clean=False,
            )
            self.assertEqual(first.byte_tree_digest, second.byte_tree_digest)
            self.assertEqual(
                (ROOT / "AGENTS.public.md").read_bytes(),
                (first.destination / "AGENTS.md").read_bytes(),
            )
            for relative in exclusions:
                if relative in mapping:
                    continue
                self.assertFalse((first.destination / Path(relative)).exists())

    def test_destination_must_be_new_and_external(self) -> None:
        self.assertNotIn("--allow-dirty", EXPORTER_PATH.read_text("utf-8"))
        with self.assertRaises(exporter.ExportError):
            exporter.export_tree(
                ROOT / "inside-export",
                root=ROOT,
                require_clean=False,
            )
        with tempfile.TemporaryDirectory(prefix="rcm-export-existing-") as temporary:
            with self.assertRaises(exporter.ExportError):
                exporter.export_tree(
                    Path(temporary),
                    root=ROOT,
                    require_clean=False,
                )

    def test_source_map_traversal_and_collision_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rcm-contract-mutation-") as temporary:
            contract_root = Path(temporary)
            policy = contract_root / "policy"
            policy.mkdir()
            for relative in (
                "public-export-allowlist.txt",
                "private-staging-exclusions.txt",
                "public-export-source-map.json",
            ):
                shutil.copyfile(ROOT / "policy" / relative, policy / relative)
            map_path = policy / "public-export-source-map.json"
            data = json.loads(map_path.read_text("utf-8"))
            data["mappings"][0]["source"] = "../AGENTS.public.md"
            map_path.write_text(json.dumps(data) + "\n", encoding="utf-8")
            with self.assertRaises(exporter.ExportError):
                exporter.load_contract(contract_root)

            data["mappings"][0]["source"] = "AGENTS.public.md"
            data["mappings"].append(dict(data["mappings"][0]))
            map_path.write_text(json.dumps(data) + "\n", encoding="utf-8")
            with self.assertRaises(exporter.ExportError):
                exporter.load_contract(contract_root)


if __name__ == "__main__":
    unittest.main()
