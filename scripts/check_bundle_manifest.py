#!/usr/bin/env python3
"""Validate the exact bundle-data and import boundary without building."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath, PureWindowsPath


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = Path("packaging/bundle-data.json")
IMPORT_POLICY_PATH = Path("packaging/import-policy.json")
PYPROJECT_PATH = Path("pyproject.toml")
EXPECTED_FORBIDDEN_DYNAMIC_CALLS = ["__import__"]
EXPECTED_ALLOWED_DYNAMIC_CALLS = [
    {
        "path": "src/rcm/bootstrap.py",
        "call": "importlib.import_module",
        "count": 1,
    },
    {
        "path": "src/rcm/foundation_check.py",
        "call": "importlib.import_module",
        "count": 1,
    },
]
EXPECTED_IMPORT_ROOTS = [
    "PIL",
    "cffi",
    "clr",
    "clr_loader",
    "psutil",
    "pystray",
    "pythonnet",
    "requests",
    "rcm",
]
SAFE_BLOCKER = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def parse_json_strict(text: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=reject_duplicates)


def safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if any(character in value for character in "*?[]\\"):
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        not posix.is_absolute()
        and not windows.is_absolute()
        and windows.drive == ""
        and value == posix.as_posix()
        and "." not in posix.parts
        and ".." not in posix.parts
        and all(part not in {"", ".git", "__pycache__"} for part in posix.parts)
    )


def _exact_safe_paths(value: object, *, label: str) -> tuple[list[str], list[str]]:
    if not isinstance(value, list):
        return [], [f"{label} must be a list"]
    issues: list[str] = []
    paths: list[str] = []
    for item in value:
        if not safe_relative_path(item):
            issues.append(f"{label} contains a non-public path")
            continue
        paths.append(item)
    if len(paths) != len(set(paths)):
        issues.append(f"{label} contains a duplicate path")
    return paths, issues


def bundle_data_issues(
    data: object,
    *,
    root: Path,
) -> tuple[list[str], list[str]]:
    expected_keys = {
        "schema_version",
        "package",
        "source_root",
        "release",
        "allowed_data_files",
        "required_notice_files",
        "candidate",
    }
    if not isinstance(data, dict) or set(data) != expected_keys:
        return ["bundle-data schema is not exact"], []
    issues: list[str] = []
    blockers: list[str] = []
    if data.get("schema_version") != 4:
        issues.append("bundle-data schema version must be 4")
    if data.get("package") != "rcm":
        issues.append("bundle package identity is not exact")
    if data.get("source_root") != "src/rcm":
        issues.append("bundle source root is not exact")
    if data.get("release") != {
        "channel": "preview",
        "package_version": "2.8.2a1",
        "display_version": "2.08.02a",
        "release_id": "rcm-2-2026-08-02-a",
        "tag": "v2.08.02a",
        "sequence": 2026080201,
        "asset": "RCM-2.08.02a-windows-x64.exe",
        "windows_version": ".".join(
            str(part) for part in (2, 8, 2, 1)
        ),
        "windows_tuple": [2, 8, 2, 1],
        "architecture": "x86_64",
        "prerelease": True,
        "authenticode": False,
    }:
        issues.append("preview release identity is not exact")
    allowed_data, path_issues = _exact_safe_paths(
        data.get("allowed_data_files"),
        label="bundle data allowlist",
    )
    notices, notice_issues = _exact_safe_paths(
        data.get("required_notice_files"),
        label="bundle notice allowlist",
    )
    issues.extend(path_issues)
    issues.extend(notice_issues)
    if allowed_data != ["src/rcm/resources/help.json"]:
        issues.append("bundle data allowlist is not exact")
    if notices != ["THIRD_PARTY_NOTICES.md"]:
        issues.append("bundle notice allowlist is not exact")

    source_root = root / "src" / "rcm"
    if not source_root.is_dir():
        issues.append("reviewed bundle source root is missing")
    else:
        actual_data: list[str] = []
        for path in source_root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            source_relative = path.relative_to(source_root)
            if (
                "__pycache__" in source_relative.parts
                or path.suffix.lower() == ".pyc"
            ):
                continue
            if path.is_symlink():
                issues.append("bundle source contains a symbolic link")
                continue
            if path.is_file() and path.suffix.lower() != ".py":
                actual_data.append(relative)
        if sorted(actual_data) != sorted(allowed_data):
            issues.append("bundle data files must exactly equal the reviewed allowlist")
    for notice in notices:
        path = root / notice
        if not path.is_file() or path.is_symlink():
            issues.append("required bundle notice is missing or not a regular file")

    candidate = data.get("candidate")
    candidate_keys = {
        "state",
        "file",
        "size",
        "sha256",
        "public_source_snapshot_sha256",
        "package_manifest_sha256",
        "local_admin_elevation_enabled",
        "verification",
        "blockers",
    }
    if not isinstance(candidate, dict) or set(candidate) != candidate_keys:
        issues.append("bundle candidate schema is not exact")
        return issues, blockers
    candidate_file = candidate.get("file")
    raw_blockers = candidate.get("blockers")
    if (
        not isinstance(raw_blockers, list)
        or any(
            not isinstance(item, str) or SAFE_BLOCKER.fullmatch(item) is None
            for item in raw_blockers
        )
        or len(set(raw_blockers)) != len(raw_blockers)
    ):
        issues.append("bundle candidate blockers are not canonical")
        raw_blockers = []
    state = candidate.get("state")
    if candidate.get("local_admin_elevation_enabled") is not False:
        issues.append("preview local admin elevation capability must remain disabled")
    verification = candidate.get("verification")
    verification_keys = {
        "visible_quit_cycles",
        "hidden_show_quit_cycles",
        "minimized_show_quit_cycles",
        "passed_cycles",
        "evidence_sha256",
    }
    if not isinstance(verification, dict) or set(verification) != verification_keys:
        issues.append("bundle candidate verification schema is not exact")
        verification = {}
    if (
        verification.get("visible_quit_cycles") != 50
        or verification.get("hidden_show_quit_cycles") != 25
        or verification.get("minimized_show_quit_cycles") != 25
    ):
        issues.append("bundle candidate verification must require exact 100 cycles")
    identity_values = (
        candidate_file,
        candidate.get("size"),
        candidate.get("sha256"),
        candidate.get("public_source_snapshot_sha256"),
        candidate.get("package_manifest_sha256"),
    )
    if state == "not_built":
        if (
            any(item is not None for item in identity_values)
            or verification.get("passed_cycles") is not None
            or verification.get("evidence_sha256") is not None
            or not raw_blockers
        ):
            issues.append("unbuilt bundle candidate must contain no invented identity")
        blockers.extend(raw_blockers)
    elif state in {"built_unverified", "frozen"}:
        digest = candidate.get("sha256")
        size = candidate.get("size")
        source_snapshot_digest = candidate.get("public_source_snapshot_sha256")
        package_manifest_digest = candidate.get("package_manifest_sha256")
        evidence_digest = verification.get("evidence_sha256")
        if (
            candidate_file != "RayClusterManager-PR07.exe"
            or not safe_relative_path(candidate_file)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
            or not isinstance(source_snapshot_digest, str)
            or SHA256.fullmatch(source_snapshot_digest) is None
            or not isinstance(package_manifest_digest, str)
            or SHA256.fullmatch(package_manifest_digest) is None
        ):
            issues.append(
                "built bundle candidate requires exact artifact, source snapshot, "
                "and manifest identities"
            )
        if state == "built_unverified":
            if (
                verification.get("passed_cycles") is not None
                or evidence_digest is not None
                or not raw_blockers
            ):
                issues.append(
                    "unverified bundle candidate must retain blockers and no "
                    "invented lifecycle evidence"
                )
            blockers.extend(raw_blockers)
        elif (
            verification.get("passed_cycles") != 100
            or not isinstance(evidence_digest, str)
            or SHA256.fullmatch(evidence_digest) is None
            or raw_blockers
        ):
            issues.append(
                "frozen bundle candidate requires 100-cycle evidence and no blockers"
            )
    else:
        issues.append(
            "bundle candidate state must be not_built, built_unverified, or frozen"
        )
    return issues, blockers


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return None


def _literal_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left)
        right = _literal_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def python_import_issues(
    text: str,
    *,
    module_depth: int,
    allowed_roots: set[str],
    forbidden_calls: set[str],
) -> tuple[list[str], list[str]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return ["package Python source is not AST-parseable"], []
    issues: list[str] = []
    dynamic_calls: list[str] = []
    import_module_aliases: set[str] = set()
    importlib_aliases: set[str] = set()
    builtins_aliases: set[str] = set()
    forbidden_aliases: set[str] = set(forbidden_calls)
    getattr_aliases = {"getattr"}
    vars_aliases = {"vars"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.partition(".")[0]
                if root == "importlib":
                    importlib_aliases.add(alias.asname or "importlib")
                if root == "builtins":
                    builtins_aliases.add(alias.asname or "builtins")
                    issues.append(
                        "package imports the builtins reflection surface"
                    )
                if root not in sys.stdlib_module_names and root not in allowed_roots:
                    issues.append("package imports a non-approved root")
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.level > module_depth:
                    issues.append("relative import leaves the reviewed package")
                continue
            root = (node.module or "").partition(".")[0]
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_module_aliases.add(alias.asname or alias.name)
            if node.module == "builtins":
                issues.append("package imports the builtins reflection surface")
                for alias in node.names:
                    if alias.name in forbidden_calls:
                        forbidden_aliases.add(alias.asname or alias.name)
            if root not in sys.stdlib_module_names and root not in allowed_roots:
                issues.append("package imports a non-approved root")
        elif isinstance(node, ast.Name) and node.id == "__builtins__":
            issues.append("package uses the builtins reflection surface")

    dynamic_aliases = set(import_module_aliases)

    def reflective_kind(node: ast.expr) -> str | None:
        if (
            isinstance(node, ast.Call)
            and _call_name(node.func) in getattr_aliases
            and len(node.args) >= 2
        ):
            target = _call_name(node.args[0])
            attribute = _literal_string(node.args[1])
            if target in importlib_aliases and attribute == "import_module":
                return "allowed"
            if target in builtins_aliases and (
                attribute is None or attribute in forbidden_calls
            ):
                return "forbidden"
        if (
            isinstance(node, ast.Subscript)
            and _literal_string(node.slice) in forbidden_calls
        ):
            if (
                isinstance(node.value, ast.Attribute)
                and node.value.attr == "__dict__"
                and _call_name(node.value.value) in builtins_aliases
            ):
                return "forbidden"
            if (
                isinstance(node.value, ast.Call)
                and _call_name(node.value.func) in vars_aliases
                and len(node.value.args) == 1
                and _call_name(node.value.args[0]) in builtins_aliases
            ):
                return "forbidden"
        return None

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                positional = [*node.args.posonlyargs, *node.args.args]
                for argument, default in zip(
                    positional[-len(node.args.defaults) :],
                    node.args.defaults,
                ):
                    if (
                        _call_name(default) in dynamic_aliases
                        and argument.arg not in dynamic_aliases
                    ):
                        dynamic_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in forbidden_aliases
                        and argument.arg not in forbidden_aliases
                    ):
                        forbidden_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in getattr_aliases
                        and argument.arg not in getattr_aliases
                    ):
                        getattr_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in vars_aliases
                        and argument.arg not in vars_aliases
                    ):
                        vars_aliases.add(argument.arg)
                        changed = True
                for argument, default in zip(
                    node.args.kwonlyargs,
                    node.args.kw_defaults,
                ):
                    if default is None:
                        continue
                    if (
                        _call_name(default) in dynamic_aliases
                        and argument.arg not in dynamic_aliases
                    ):
                        dynamic_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in forbidden_aliases
                        and argument.arg not in forbidden_aliases
                    ):
                        forbidden_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in getattr_aliases
                        and argument.arg not in getattr_aliases
                    ):
                        getattr_aliases.add(argument.arg)
                        changed = True
                    if (
                        _call_name(default) in vars_aliases
                        and argument.arg not in vars_aliases
                    ):
                        vars_aliases.add(argument.arg)
                        changed = True
                continue
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            value_name = _call_name(value)
            is_allowed_dynamic = (
                value_name in dynamic_aliases
                or reflective_kind(value) == "allowed"
                or value_name is not None
                and any(
                    value_name == f"{alias}.import_module"
                    for alias in importlib_aliases
                )
            )
            is_forbidden_dynamic = (
                value_name in forbidden_aliases
                or reflective_kind(value) == "forbidden"
                or value_name is not None
                and any(
                    value_name == f"{alias}.{call}"
                    for alias in builtins_aliases
                    for call in forbidden_calls
                )
            )
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if is_allowed_dynamic and target.id not in dynamic_aliases:
                    dynamic_aliases.add(target.id)
                    changed = True
                if is_forbidden_dynamic and target.id not in forbidden_aliases:
                    forbidden_aliases.add(target.id)
                    changed = True
                if value_name in getattr_aliases and target.id not in getattr_aliases:
                    getattr_aliases.add(target.id)
                    changed = True
                if value_name in vars_aliases and target.id not in vars_aliases:
                    vars_aliases.add(target.id)
                    changed = True

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if (
            name in forbidden_aliases
            or reflective_kind(node.func) == "forbidden"
            or name is not None
            and name.rpartition(".")[2] in forbidden_aliases
            or name is not None
            and any(
                name == f"{alias}.{call}"
                for alias in builtins_aliases
                for call in forbidden_calls
            )
        ):
            issues.append("package uses a forbidden dynamic import")
        if (
            name in dynamic_aliases
            or reflective_kind(node.func) == "allowed"
            or name is not None
            and name.rpartition(".")[2] in dynamic_aliases
            or name is not None
            and any(
                name == f"{alias}.import_module"
                for alias in importlib_aliases
            )
        ):
            dynamic_calls.append("importlib.import_module")
    return sorted(set(issues)), dynamic_calls


def import_policy_issues(data: object, *, root: Path) -> list[str]:
    expected_keys = {
        "schema_version",
        "package",
        "source_root",
        "stdlib_only",
        "allowed_import_roots",
        "forbidden_dynamic_import_calls",
        "allowed_dynamic_import_calls",
    }
    if not isinstance(data, dict) or set(data) != expected_keys:
        return ["import-policy schema is not exact"]
    issues: list[str] = []
    if data.get("schema_version") != 1:
        issues.append("import-policy schema version must be 1")
    if data.get("package") != "rcm" or data.get("source_root") != "src/rcm":
        issues.append("import-policy package boundary is not exact")
    if data.get("stdlib_only") is not False:
        issues.append("import-policy dependency mode is not exact")
    allowed = data.get("allowed_import_roots")
    forbidden_dynamic = data.get("forbidden_dynamic_import_calls")
    allowed_dynamic = data.get("allowed_dynamic_import_calls")
    if allowed != EXPECTED_IMPORT_ROOTS:
        issues.append("import root allowlist is not exact")
        allowed = []
    if forbidden_dynamic != EXPECTED_FORBIDDEN_DYNAMIC_CALLS:
        issues.append("dynamic import deny list is not exact")
        forbidden_dynamic = []
    if allowed_dynamic != EXPECTED_ALLOWED_DYNAMIC_CALLS:
        issues.append("dynamic import exception list is not exact")
        allowed_dynamic = []
    observed_dynamic: dict[tuple[str, str], int] = {}
    source_root = root / "src" / "rcm"
    if not source_root.is_dir():
        return issues + ["reviewed import source root is missing"]
    for path in source_root.rglob("*.py"):
        if path.is_symlink():
            issues.append("package Python source contains a symbolic link")
            continue
        relative_module = path.relative_to(source_root)
        module_depth = len(relative_module.parts)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            issues.append("package Python source could not be decoded")
            continue
        import_issues, dynamic_calls = python_import_issues(
            text,
            module_depth=module_depth,
            allowed_roots=set(allowed),
            forbidden_calls=set(forbidden_dynamic),
        )
        issues.extend(import_issues)
        repository_path = path.relative_to(root).as_posix()
        for call in dynamic_calls:
            key = (repository_path, call)
            observed_dynamic[key] = observed_dynamic.get(key, 0) + 1
    expected_dynamic = {
        (str(record["path"]), str(record["call"])): int(record["count"])
        for record in allowed_dynamic
        if isinstance(record, dict)
        and set(record) == {"path", "call", "count"}
        and safe_relative_path(record.get("path"))
        and isinstance(record.get("call"), str)
        and isinstance(record.get("count"), int)
        and not isinstance(record.get("count"), bool)
        and record.get("count", 0) > 0
    }
    if observed_dynamic != expected_dynamic:
        issues.append("dynamic imports must exactly match reviewed exceptions")
    return sorted(set(issues))


def pyproject_bundle_issues(data: object) -> list[str]:
    if not isinstance(data, dict):
        return ["pyproject root must be a table"]
    project = data.get("project", {})
    setuptools = data.get("tool", {}).get("setuptools", {})
    packages = setuptools.get("packages", {}).get("find", {})
    issues: list[str] = []
    if project.get("scripts") != {
        "ray-cluster-manager": "rcm.__main__:main"
    }:
        issues.append("bundle console entry point is not exact")
    if setuptools.get("package-dir") != {"": "src"}:
        issues.append("bundle package directory is not exact")
    if packages != {
        "where": ["src"],
        "include": ["rcm", "rcm.*"],
        "namespaces": False,
    }:
        issues.append("bundle package discovery is not exact")
    if setuptools.get("include-package-data") is not False:
        issues.append("implicit package-data discovery must remain disabled")
    return issues


def _read_json(path: Path) -> tuple[object | None, list[str]]:
    try:
        return parse_json_strict(path.read_text(encoding="utf-8")), []
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None, ["reviewed packaging JSON could not be parsed"]


def validate_repository(root: Path = ROOT) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    blockers: list[str] = []
    bundle, bundle_read_issues = _read_json(root / BUNDLE_PATH)
    issues.extend(bundle_read_issues)
    if bundle is not None:
        bundle_issues, blockers = bundle_data_issues(bundle, root=root)
        issues.extend(bundle_issues)
    import_policy, import_read_issues = _read_json(root / IMPORT_POLICY_PATH)
    issues.extend(import_read_issues)
    if import_policy is not None:
        issues.extend(import_policy_issues(import_policy, root=root))
    try:
        pyproject = tomllib.loads(
            (root / PYPROJECT_PATH).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        issues.append("pyproject could not be parsed")
    else:
        issues.extend(pyproject_bundle_issues(pyproject))
    return sorted(set(issues)), sorted(blockers)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate bundle data and package import boundaries."
    )
    parser.add_argument(
        "--require-frozen-candidate",
        action="store_true",
        help="fail unless a reviewed frozen bundle identity is present",
    )
    arguments = parser.parse_args(argv)
    issues, blockers = validate_repository()
    if issues:
        for issue in issues:
            print(f"FAIL: {issue}")
        print(f"bundle policy failed: {len(issues)} issue(s)")
        return 1
    print("PASS: bundle-data and import-policy structure")
    if blockers:
        print(
            "NOT RUN: frozen bundle candidate "
            f"({len(blockers)} blocker(s); build authorization and evidence required)"
        )
        if arguments.require_frozen_candidate:
            print("FAIL: frozen bundle candidate required")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
