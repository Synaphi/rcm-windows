from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_dependency_lock as dependency


class DependencyLockTests(unittest.TestCase):
    def test_repository_locks_and_provenance_are_exact(self) -> None:
        issues, notices_pending = dependency.validate_repository()
        self.assertEqual([], issues)
        self.assertFalse(notices_pending)

        unique_artifacts: set[tuple[str, str, str]] = set()
        entry_count = 0
        for relative in dependency.LOCK_PATHS:
            expected_id = relative.stem
            text = (dependency.ROOT / relative).read_text(encoding="utf-8")
            lock_issues, records = dependency.lock_text_issues(
                text,
                expected_id=expected_id,
            )
            self.assertEqual([], lock_issues)
            entry_count += len(records)
            unique_artifacts.update(
                (name, version, digest)
                for name, (version, digest) in records.items()
            )
            for line in text.splitlines()[5:]:
                self.assertEqual(1, line.count("--hash=sha256:"))
        self.assertEqual(29, entry_count)
        self.assertEqual(21, len(unique_artifacts))
        self.assertEqual(21, len(dependency.EXPECTED_ARTIFACTS))

    def test_lock_parser_rejects_unhashed_duplicate_unsorted_and_drift(
        self,
    ) -> None:
        path = dependency.ROOT / "requirements/runtime-win-x86_64.lock"
        baseline = path.read_text(encoding="utf-8")
        first, second = baseline.splitlines()[5:7]
        parser_mutations = (
            baseline.replace(" --hash=sha256:", " ", 1),
            baseline + first + "\n",
            "\n".join(
                [*baseline.splitlines()[:5], second, first]
                + baseline.splitlines()[7:]
            )
            + "\n",
        )
        for mutated in parser_mutations:
            with self.subTest(size=len(mutated)):
                issues, _ = dependency.lock_text_issues(
                    mutated,
                    expected_id="runtime-win-x86_64",
                )
                self.assertTrue(issues)

        drifted = baseline.replace(
            "requests==2.34.2",
            "requests==2.34.3",
            1,
        )
        parser_issues, drifted_records = dependency.lock_text_issues(
            drifted,
            expected_id="runtime-win-x86_64",
        )
        self.assertEqual([], parser_issues)
        locks = {}
        for relative in dependency.LOCK_PATHS:
            if relative.name == "runtime-win-x86_64.lock":
                locks[relative.stem] = drifted_records
            else:
                _, records = dependency.lock_text_issues(
                    (dependency.ROOT / relative).read_text(encoding="utf-8"),
                    expected_id=relative.stem,
                )
                locks[relative.stem] = records
        provenance = dependency.parse_json_strict(
            (dependency.ROOT / dependency.PROVENANCE_PATH).read_text(
                encoding="utf-8"
            )
        )
        provenance_issues, _ = dependency.provenance_data_issues(
            provenance,
            locks=locks,
        )
        self.assertTrue(provenance_issues)

    def test_provenance_rejects_hash_filename_scope_and_hidden_records(
        self,
    ) -> None:
        locks = {}
        for relative in dependency.LOCK_PATHS:
            _, records = dependency.lock_text_issues(
                (dependency.ROOT / relative).read_text(encoding="utf-8"),
                expected_id=relative.stem,
            )
            locks[relative.stem] = records
        baseline = dependency.parse_json_strict(
            (dependency.ROOT / dependency.PROVENANCE_PATH).read_text(
                encoding="utf-8"
            )
        )
        mutations = []
        wrong_hash = copy.deepcopy(baseline)
        wrong_hash["artifacts"][0]["sha256"] = "0" * 64
        mutations.append(wrong_hash)
        external_filename = copy.deepcopy(baseline)
        external_filename["artifacts"][0]["filename"] = "../artifact.whl"
        mutations.append(external_filename)
        wrong_scope = copy.deepcopy(baseline)
        wrong_scope["artifacts"][0]["scopes"] = ["runtime"]
        mutations.append(wrong_scope)
        hidden = copy.deepcopy(baseline)
        hidden["artifacts"].append(copy.deepcopy(hidden["artifacts"][0]))
        hidden["artifacts"][-1]["artifact_id"] = "hidden:1"
        hidden["artifacts"][-1]["name"] = "hidden"
        hidden["artifacts"][-1]["version"] = "1"
        mutations.append(hidden)
        false_license = copy.deepcopy(baseline)
        false_license["artifacts"][0]["license_expression"] = "UNKNOWN"
        mutations.append(false_license)
        pending_license = copy.deepcopy(baseline)
        pending_license["artifacts"][0]["license_text_reviewed"] = False
        mutations.append(pending_license)
        for mutated in mutations:
            with self.subTest(artifacts=len(mutated["artifacts"])):
                issues, _ = dependency.provenance_data_issues(
                    mutated,
                    locks=locks,
                )
                self.assertTrue(issues)

    def test_pyproject_pins_match_direct_runtime_and_build_boundaries(
        self,
    ) -> None:
        import tomllib

        baseline = tomllib.loads(
            (dependency.ROOT / dependency.PYPROJECT_PATH).read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual([], dependency.pyproject_issues(baseline))
        runtime_drift = copy.deepcopy(baseline)
        runtime_drift["project"]["dependencies"].append("unknown==1")
        self.assertTrue(dependency.pyproject_issues(runtime_drift))
        unpinned = copy.deepcopy(baseline)
        unpinned["build-system"]["requires"][0] = "setuptools>=83"
        self.assertTrue(dependency.pyproject_issues(unpinned))

    def test_duplicate_provenance_json_key_is_rejected(self) -> None:
        text = (
            dependency.ROOT / dependency.PROVENANCE_PATH
        ).read_text(encoding="utf-8")
        mutated = text.replace(
            '"schema_version": 2,',
            '"schema_version": 1,\n  "schema_version": 2,',
            1,
        )
        with self.assertRaises(ValueError):
            dependency.parse_json_strict(mutated)

    def test_structure_and_reviewed_notice_gates_pass(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(0, dependency.main([]))
        self.assertIn("PASS:", output.getvalue())
        self.assertIn("NOT RUN:", output.getvalue())

        required_output = io.StringIO()
        with redirect_stdout(required_output):
            self.assertEqual(
                0,
                dependency.main(["--require-reviewed-notices"]),
            )
        self.assertNotIn(
            "reviewed third-party notices required",
            required_output.getvalue(),
        )

    def test_wheelhouse_verifier_is_exact_and_rejects_links(self) -> None:
        first_bytes = b"synthetic-wheel-one"
        second_bytes = b"synthetic-wheel-two"
        expected = {
            "first-1-py3-none-any.whl": hashlib.sha256(
                first_bytes
            ).hexdigest(),
            "second-1-py3-none-any.whl": hashlib.sha256(
                second_bytes
            ).hexdigest(),
        }
        with tempfile.TemporaryDirectory(
            prefix="rcm-wheelhouse-test-"
        ) as temporary:
            wheelhouse = Path(temporary)
            first = wheelhouse / "first-1-py3-none-any.whl"
            second = wheelhouse / "second-1-py3-none-any.whl"
            first.write_bytes(first_bytes)
            second.write_bytes(second_bytes)
            self.assertEqual(
                [],
                dependency.wheelhouse_issues(
                    wheelhouse,
                    expected_files=expected,
                ),
            )

            second.write_bytes(b"changed")
            self.assertTrue(
                dependency.wheelhouse_issues(
                    wheelhouse,
                    expected_files=expected,
                )
            )
            second.write_bytes(second_bytes)
            extra = wheelhouse / "extra-1-py3-none-any.whl"
            extra.write_bytes(b"extra")
            self.assertTrue(
                dependency.wheelhouse_issues(
                    wheelhouse,
                    expected_files=expected,
                )
            )
            extra.unlink()
            with mock.patch.object(
                dependency,
                "_is_link_or_reparse",
                side_effect=lambda path: path == first,
            ):
                self.assertTrue(
                    dependency.wheelhouse_issues(
                        wheelhouse,
                        expected_files=expected,
                    )
                )


if __name__ == "__main__":
    unittest.main()
