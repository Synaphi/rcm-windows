#!/usr/bin/env python3
"""Validate hash-locked requirements and offline artifact provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import tomllib
from pathlib import Path, PurePosixPath, PureWindowsPath


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATHS = (
    Path("requirements/runtime-win-x86_64.lock"),
    Path("requirements/dev.lock"),
    Path("requirements/build-win-x86_64.lock"),
)
PROVENANCE_PATH = Path("policy/dependency-provenance.json")
PYPROJECT_PATH = Path("pyproject.toml")

EXPECTED_LOCKS = {
    "runtime-win-x86_64": {
        "scope": "runtime",
        "target": "CPython-3.12-win32-x86_64",
        "packages": {
            "certifi",
            "cffi",
            "charset-normalizer",
            "clr-loader",
            "idna",
            "pillow",
            "psutil",
            "pycparser",
            "pystray",
            "pythonnet",
            "requests",
            "six",
            "urllib3",
        },
    },
    "dev": {
        "scope": "development",
        "target": "CPython-3.12-any-any",
        "packages": {
            "altgraph",
            "packaging",
            "pefile",
            "pyinstaller",
            "pyinstaller-hooks-contrib",
            "pywin32-ctypes",
            "setuptools",
            "wheel",
        },
    },
    "build-win-x86_64": {
        "scope": "build",
        "target": "CPython-3.12-win32-x86_64",
        "packages": {
            "altgraph",
            "packaging",
            "pefile",
            "pyinstaller",
            "pyinstaller-hooks-contrib",
            "pywin32-ctypes",
            "setuptools",
            "wheel",
        },
    },
}
EXPECTED_DIRECT_RUNTIME = {
    ("pillow", "10.4.0"),
    ("psutil", "5.9.8"),
    ("pystray", "0.19.5"),
    ("pythonnet", "3.1.0"),
    ("requests", "2.34.2"),
}
EXPECTED_BUILD_REQUIREMENTS = {
    ("setuptools", "83.0.0"),
    ("wheel", "0.45.1"),
}
EXPECTED_ARTIFACTS = {
    "altgraph": (
        "0.17.5",
        "altgraph-0.17.5-py2.py3-none-any.whl",
        "f3a22400bce1b0c701683820ac4f3b159cd301acab067c51c653e06961600597",
        "MIT",
    ),
    "certifi": (
        "2026.6.17",
        "certifi-2026.6.17-py3-none-any.whl",
        "2227dcbaafe0d2f59279d1762ddddc37783ed4354594f194ffc31d20f41fc3db",
        "MPL-2.0",
    ),
    "cffi": (
        "2.1.0",
        "cffi-2.1.0-cp312-cp312-win_amd64.whl",
        "c97f080ea627e2863524c5af3836e2270b5f5dfff1f104392b959f8df0c5d384",
        "MIT-0",
    ),
    "charset-normalizer": (
        "3.4.7",
        "charset_normalizer-3.4.7-cp312-cp312-win_amd64.whl",
        "5ed6ab538499c8644b8a3e18debabcd7ce684f3fa91cf867521a7a0279cab2d6",
        "MIT",
    ),
    "clr-loader": (
        "0.3.1",
        "clr_loader-0.3.1-py3-none-any.whl",
        "cbad189de20d202a7d621956b0fc38049e13c9bf7ca2923441eff725cd121aa1",
        "MIT",
    ),
    "idna": (
        "3.18",
        "idna-3.18-py3-none-any.whl",
        "7f952cbe720b688055e3f87de14f5c3e5fdaa8bc3928985c4077ca689de849a2",
        "BSD-3-Clause",
    ),
    "packaging": (
        "26.2",
        "packaging-26.2-py3-none-any.whl",
        "5fc45236b9446107ff2415ce77c807cee2862cb6fac22b8a73826d0693b0980e",
        "Apache-2.0 OR BSD-2-Clause",
    ),
    "pefile": (
        "2023.2.7",
        "pefile-2023.2.7-py3-none-any.whl",
        "da185cd2af68c08a6cd4481f7325ed600a88f6a813bad9dea07ab3ef73d8d8d6",
        "MIT",
    ),
    "pillow": (
        "10.4.0",
        "pillow-10.4.0-cp312-cp312-win_amd64.whl",
        "1d846aea995ad352d4bdcc847535bd56e0fd88d36829d2c90be880ef1ee4668a",
        "HPND",
    ),
    "psutil": (
        "5.9.8",
        "psutil-5.9.8-cp37-abi3-win_amd64.whl",
        "8db4c1b57507eef143a15a6884ca10f7c73876cdf5d51e713151c1236a0e68cf",
        "BSD-3-Clause",
    ),
    "pycparser": (
        "3.0",
        "pycparser-3.0-py3-none-any.whl",
        "b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992",
        "BSD-3-Clause",
    ),
    "pyinstaller": (
        "6.11.1",
        "pyinstaller-6.11.1-py3-none-win_amd64.whl",
        "7ac83c0dc0e04357dab98c487e74ad2adb30e7eb186b58157a8faf46f1fa796f",
        "GPL-2.0-or-later WITH Bootloader-exception",
    ),
    "pyinstaller-hooks-contrib": (
        "2026.6",
        "pyinstaller_hooks_contrib-2026.6-py3-none-any.whl",
        "fd13b8ac126b35361175edacd41a0d97080b75dd5f4b594ecefefff969509dd3",
        "Apache-2.0 OR GPL-2.0-only",
    ),
    "pystray": (
        "0.19.5",
        "pystray-0.19.5-py2.py3-none-any.whl",
        "a0c2229d02cf87207297c22d86ffc57c86c227517b038c0d3c59df79295ac617",
        "LGPL-3.0-only",
    ),
    "pythonnet": (
        "3.1.0",
        "pythonnet-3.1.0-cp310.cp311.cp312.cp313.cp314-none-win32.win_amd64.whl",
        "7bdd4de03df3547a48122a3989265c8b31d5be0d19dadffa009eec7df8085e0b",
        "MIT",
    ),
    "pywin32-ctypes": (
        "0.2.3",
        "pywin32_ctypes-0.2.3-py3-none-any.whl",
        "8a1513379d709975552d202d942d9837758905c8d01eb82b8bcc30918929e7b8",
        "BSD-3-Clause",
    ),
    "requests": (
        "2.34.2",
        "requests-2.34.2-py3-none-any.whl",
        "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0",
        "Apache-2.0",
    ),
    "setuptools": (
        "83.0.0",
        "setuptools-83.0.0-py3-none-any.whl",
        "29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3",
        "MIT",
    ),
    "six": (
        "1.17.0",
        "six-1.17.0-py2.py3-none-any.whl",
        "4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274",
        "MIT",
    ),
    "urllib3": (
        "2.7.0",
        "urllib3-2.7.0-py3-none-any.whl",
        "9fb4c81ebbb1ce9531cce37674bbc6f1360472bc18ca9a553ede278ef7276897",
        "MIT",
    ),
    "wheel": (
        "0.45.1",
        "wheel-0.45.1-py3-none-any.whl",
        "708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248",
        "MIT",
    ),
}
PROVENANCE_RECORD_KEYS = {
    "artifact_id",
    "name",
    "version",
    "filename",
    "sha256",
    "scopes",
    "bundled",
    "license_expression",
    "license_text_reviewed",
    "state",
}
SAFE_NAME = re.compile(r"^[a-z0-9]+(?:[-.][a-z0-9]+)*$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9]+(?:[A-Za-z0-9._+-]*[A-Za-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_LINE = re.compile(
    r"^([a-z0-9]+(?:[-.][a-z0-9]+)*)=="
    r"([A-Za-z0-9]+(?:[A-Za-z0-9._+-]*[A-Za-z0-9])?) "
    r"--hash=sha256:([0-9a-f]{64})$"
)


def parse_json_strict(text: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=reject_duplicates)


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def safe_wheel_filename(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith(".whl"):
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        value == posix.name
        and value == windows.name
        and posix.parent == PurePosixPath(".")
        and windows.parent == PureWindowsPath(".")
        and windows.drive == ""
        and not any(character in value for character in "*?[]/\\")
    )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheelhouse_issues(
    wheelhouse: Path,
    *,
    expected_files: dict[str, str] | None = None,
) -> list[str]:
    expected = expected_files or {
        artifact[1]: artifact[2]
        for artifact in EXPECTED_ARTIFACTS.values()
    }
    if (
        not wheelhouse.is_dir()
        or _is_link_or_reparse(wheelhouse)
    ):
        return ["wheelhouse must be one real local directory"]
    try:
        entries = list(wheelhouse.iterdir())
    except OSError:
        return ["wheelhouse inventory could not be read"]
    issues: list[str] = []
    actual_names: set[str] = set()
    for entry in entries:
        if _is_link_or_reparse(entry):
            issues.append("wheelhouse must not contain a link or reparse point")
            continue
        if not entry.is_file():
            issues.append("wheelhouse must contain wheel files only")
            continue
        actual_names.add(entry.name)
    if actual_names != set(expected):
        issues.append("wheelhouse filenames do not exactly match reviewed provenance")
    for filename, reviewed_digest in expected.items():
        path = wheelhouse / filename
        if filename not in actual_names:
            continue
        try:
            actual_digest = _file_sha256(path)
        except OSError:
            issues.append("wheelhouse artifact could not be hashed")
            continue
        if actual_digest != reviewed_digest:
            issues.append("wheelhouse artifact SHA-256 does not match reviewed provenance")
    return sorted(set(issues))


def lock_text_issues(
    text: str,
    *,
    expected_id: str,
) -> tuple[list[str], dict[str, tuple[str, str]]]:
    issues: list[str] = []
    if text.startswith("\ufeff"):
        issues.append("dependency lock must not contain a UTF-8 BOM")
    if "\r" in text:
        issues.append("dependency lock must use LF newlines")
    expected = EXPECTED_LOCKS[expected_id]
    expected_header = [
        "# rcm-lock-schema: 1",
        f"# lock-id: {expected_id}",
        f"# scope: {expected['scope']}",
        f"# target: {expected['target']}",
        "",
    ]
    lines = text.splitlines()
    if lines[:5] != expected_header:
        issues.append("dependency lock header is not exact")
    records: dict[str, tuple[str, str]] = {}
    requirement_lines = lines[5:]
    if any(not line for line in requirement_lines):
        issues.append("dependency lock body must not contain blank lines")
    for line in requirement_lines:
        match = REQUIREMENT_LINE.fullmatch(line)
        if match is None:
            issues.append("dependency lock contains a non-canonical requirement")
            continue
        name, version, digest = match.groups()
        if name != canonical_name(name):
            issues.append("dependency lock package name is not canonical")
        if name in records:
            issues.append("dependency lock contains a duplicate package")
        records[name] = (version, digest)
    if list(records) != sorted(records):
        issues.append("dependency lock requirements must be sorted")
    if set(records) != expected["packages"]:
        issues.append("dependency lock package closure is not exact")
    return issues, records


def provenance_data_issues(
    data: object,
    *,
    locks: dict[str, dict[str, tuple[str, str]]],
) -> tuple[list[str], bool]:
    issues: list[str] = []
    expected_keys = {
        "schema_version",
        "acquisition_policy",
        "artifacts",
        "blockers",
    }
    if not isinstance(data, dict) or set(data) != expected_keys:
        return ["dependency provenance schema is not exact"], False
    if data.get("schema_version") != 2:
        issues.append("dependency provenance schema version must be 2")
    if data.get("acquisition_policy") != "approved_offline_wheelhouse_only":
        issues.append("dependency acquisition policy is not exact")
    blockers = data.get("blockers")
    if (
        not isinstance(blockers, list)
        or len(blockers) != len(set(blockers))
        or blockers
    ):
        issues.append("dependency provenance blocker set is not exact")
        blockers = []
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        return issues + ["dependency provenance artifacts must be a list"], bool(
            blockers
        )

    expected_scopes: dict[str, set[str]] = {}
    expected_records: dict[str, tuple[str, str]] = {}
    for lock_id, records in locks.items():
        scope = str(EXPECTED_LOCKS[lock_id]["scope"])
        for name, value in records.items():
            expected_scopes.setdefault(name, set()).add(scope)
            previous = expected_records.setdefault(name, value)
            if previous != value:
                issues.append("the same dependency has conflicting lock identities")

    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != PROVENANCE_RECORD_KEYS:
            issues.append("dependency provenance artifact schema is not exact")
            continue
        name = artifact.get("name")
        version = artifact.get("version")
        digest = artifact.get("sha256")
        artifact_id = artifact.get("artifact_id")
        if (
            not isinstance(name, str)
            or SAFE_NAME.fullmatch(name) is None
            or name != canonical_name(name)
        ):
            issues.append("dependency provenance name is not canonical")
            continue
        if name in seen_names:
            issues.append("dependency provenance contains a duplicate package")
        seen_names.add(name)
        if not isinstance(version, str) or SAFE_VERSION.fullmatch(version) is None:
            issues.append("dependency provenance version is not canonical")
        if artifact_id != f"{name}:{version}" or artifact_id in seen_ids:
            issues.append("dependency provenance artifact identity is not exact")
        if isinstance(artifact_id, str):
            seen_ids.add(artifact_id)
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            issues.append("dependency provenance SHA-256 is not exact")
        if not safe_wheel_filename(artifact.get("filename")):
            issues.append("dependency provenance wheel filename is not public-safe")
        scopes = artifact.get("scopes")
        if (
            not isinstance(scopes, list)
            or scopes != sorted(scopes)
            or len(scopes) != len(set(scopes))
            or set(scopes) != expected_scopes.get(name, set())
        ):
            issues.append("dependency provenance scopes do not match the locks")
        if expected_records.get(name) != (version, digest):
            issues.append("dependency provenance does not match a lock identity")
        expected_artifact = EXPECTED_ARTIFACTS.get(name)
        if expected_artifact != (
            version,
            artifact.get("filename"),
            digest,
            artifact.get("license_expression"),
        ):
            issues.append("dependency provenance differs from reviewed artifact evidence")
        runtime_bundled = "runtime" in expected_scopes.get(name, set())
        if artifact.get("bundled") is not runtime_bundled:
            issues.append("dependency bundled marker does not match runtime scope")
        if (
            not isinstance(artifact.get("license_expression"), str)
            or artifact.get("license_text_reviewed") is not True
            or artifact.get("state") != "reviewed"
        ):
            issues.append("dependency license review must be complete")
    if seen_names != set(expected_records) or seen_names != set(EXPECTED_ARTIFACTS):
        issues.append("dependency provenance artifact set is not exact")
    return issues, False


def _parse_exact_pins(values: object) -> tuple[set[tuple[str, str]], list[str]]:
    issues: list[str] = []
    parsed: set[tuple[str, str]] = set()
    if not isinstance(values, list):
        return parsed, ["dependency pins must be a list"]
    for value in values:
        match = re.fullmatch(
            r"([A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*)=="
            r"([A-Za-z0-9]+(?:[A-Za-z0-9._+-]*[A-Za-z0-9])?)",
            value if isinstance(value, str) else "",
        )
        if match is None:
            issues.append("dependency declaration must be an exact pin")
            continue
        parsed.add((canonical_name(match.group(1)), match.group(2)))
    return parsed, issues


def pyproject_issues(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["pyproject root must be a table"]
    issues: list[str] = []
    project = data.get("project")
    build = data.get("build-system")
    setuptools = data.get("tool", {}).get("setuptools", {})
    if not isinstance(project, dict) or not isinstance(build, dict):
        return ["pyproject project and build-system tables are required"]
    if project.get("name") != "ray-cluster-manager":
        issues.append("pyproject project name is not exact")
    if project.get("version") != "2.8.3a1":
        issues.append("pyproject foundation version is not exact")
    if project.get("requires-python") != ">=3.12":
        issues.append("pyproject Python floor is not exact")
    if project.get("scripts") != {
        "ray-cluster-manager": "rcm.__main__:main"
    }:
        issues.append("pyproject console entry point is not exact")
    runtime, runtime_issues = _parse_exact_pins(project.get("dependencies"))
    build_requirements, build_issues = _parse_exact_pins(build.get("requires"))
    issues.extend(runtime_issues)
    issues.extend(build_issues)
    if runtime != EXPECTED_DIRECT_RUNTIME:
        issues.append("pyproject direct runtime dependency set is not exact")
    if build_requirements != EXPECTED_BUILD_REQUIREMENTS:
        issues.append("pyproject build dependency set is not exact")
    if build.get("build-backend") != "setuptools.build_meta":
        issues.append("pyproject build backend is not exact")
    if not isinstance(setuptools, dict) or setuptools.get("package-dir") != {
        "": "src"
    }:
        issues.append("pyproject must use the reviewed src layout")
    return issues


def _read_json(path: Path) -> tuple[object | None, list[str]]:
    try:
        return parse_json_strict(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None, ["reviewed dependency provenance could not be parsed"]


def validate_repository(root: Path = ROOT) -> tuple[list[str], bool]:
    issues: list[str] = []
    locks: dict[str, dict[str, tuple[str, str]]] = {}
    for relative in LOCK_PATHS:
        expected_id = relative.stem
        try:
            text = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            issues.append("reviewed dependency lock could not be decoded")
            continue
        lock_issues, records = lock_text_issues(text, expected_id=expected_id)
        issues.extend(lock_issues)
        locks[expected_id] = records
    provenance, read_issues = _read_json(root / PROVENANCE_PATH)
    issues.extend(read_issues)
    notices_pending = False
    if provenance is not None:
        provenance_issues, notices_pending = provenance_data_issues(
            provenance,
            locks=locks,
        )
        issues.extend(provenance_issues)
    try:
        pyproject = tomllib.loads(
            (root / PYPROJECT_PATH).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        issues.append("pyproject could not be parsed")
    else:
        issues.extend(pyproject_issues(pyproject))
    return sorted(set(issues)), notices_pending


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate hash-locked dependencies and provenance."
    )
    parser.add_argument(
        "--require-reviewed-notices",
        action="store_true",
        help="fail unless vendor licenses and redistribution notices are reviewed",
    )
    parser.add_argument(
        "--wheelhouse",
        type=Path,
        help="verify one offline wheelhouse against the 21 reviewed artifacts",
    )
    arguments = parser.parse_args(argv)
    issues, notices_pending = validate_repository()
    if arguments.wheelhouse is not None:
        issues.extend(wheelhouse_issues(arguments.wheelhouse))
        issues = sorted(set(issues))
    if issues:
        for issue in issues:
            print(f"FAIL: {issue}")
        print(f"dependency lock policy failed: {len(issues)} issue(s)")
        return 1
    print("PASS: dependency locks and offline artifact provenance")
    if notices_pending:
        print(
            "NOT RUN: vendor license and notice review "
            "(approved evidence set required)"
        )
        if arguments.require_reviewed_notices:
            print("FAIL: reviewed third-party notices required")
            return 1
    if arguments.wheelhouse is None:
        print("NOT RUN: wheelhouse byte verification (--wheelhouse PATH required)")
    else:
        print("PASS: offline wheelhouse filenames and SHA-256 identities")
    return 0


if __name__ == "__main__":
    sys.exit(main())
