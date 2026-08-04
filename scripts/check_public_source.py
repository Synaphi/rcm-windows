#!/usr/bin/env python3
"""Fail-closed validation for an RCM public source checkout or export."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib
import tokenize
from typing import Iterable


ALLOWLIST = Path("policy/public-export-allowlist.txt")
DENYLIST = Path("policy/public-export-deny-patterns.txt")
EXPECTED_PATH_COUNT = 161
EXPECTED_PATH_DIGEST = (
    "e7b4af70361852261c6ab81e527366db46f95473e5d299fa8fe042a2723f058a"
)
EXPECTED_LICENSE_BYTES = 11_358
EXPECTED_LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
EXPECTED_DENY_POLICY_SHA256 = (
    "26fb54bdb0a76f00ec4810d65e3fccd2de46e394d38beb58b592515cd24d8902"
)
EXPECTED_DENY_PATH_COUNT = 35
EXPECTED_DENY_CONTENT_COUNT = 18
DISALLOWED_BINARY_SUFFIXES = {
    ".7z", ".db", ".dll", ".dmp", ".exe", ".gz", ".msi", ".p12",
    ".pdb", ".pem", ".pfx", ".pyc", ".sqlite", ".tar", ".tmp",
    ".whl", ".zip",
}
ALLOWED_CONTROLS = {9, 10}
SAFE_LITERAL_MARKERS = (
    "127.0.0.1",
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "localhost",
    "synthetic",
    "example",
)
SAFE_ABSOLUTE_PATH_LITERALS = {
    "c:\\windows",
    "c:\\windows\\temp",
    "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
    "\\\\.\\pipe\\",
}
SAFE_ABSOLUTE_PATH_PREFIXES = (
    "\\\\.\\pipe\\",
)
PRIVATE_ADDRESS_PATTERNS = (
    r"(?<![0-9])10(?:\.[0-9]{1,3}){3}(?![0-9])",
    r"(?<![0-9])192\.168(?:\.[0-9]{1,3}){2}(?![0-9])",
    r"(?<![0-9])172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}(?![0-9])",
    r"(?<![0-9])100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])(?:\.[0-9]{1,3}){2}(?![0-9])",
    r"(?<![0-9])169\.254(?:\.[0-9]{1,3}){2}(?![0-9])",
    r"(?i)(?<![0-9a-f:])f[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])",
    r"(?i)(?<![0-9a-f:])fe[89ab][0-9a-f](?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:])",
)
SENSITIVE_ASSIGNMENT_SUFFIXES = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "credential",
    "private_key",
    "access_key",
    "access_key_id",
    "signing_key",
    "auth_token",
    "authorization",
    "auth",
    "session_cookie",
    "head_ip",
    "node_ip",
    "controller_ip",
    "host",
    "hostname",
    "user",
    "username",
)
SAFE_ASSIGNMENT_MARKERS = (
    "synthetic",
    "example",
    "placeholder",
    "disabled",
)
SAFE_ASSIGNMENT_LITERALS = {
    "!#$%+-.:=?@_~",
}
GIT_OBJECT_ID = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")


def _policy_entries(path: Path, prefix: str | None = None) -> list[str]:
    text = path.read_text(encoding="utf-8")
    entries: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if prefix is None:
            entries.append(line)
        elif line.startswith(prefix):
            entries.append(line[len(prefix):])
    return entries


def _safe_relative(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and value == path.as_posix()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _path_digest(paths: Iterable[str]) -> str:
    payload = "".join(f"{path}\n" for path in paths).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_allowlist(root: Path) -> tuple[list[str], list[str]]:
    path = root / ALLOWLIST
    if not path.is_file():
        return [], [f"missing allowlist: {ALLOWLIST.as_posix()}"]
    try:
        entries = _policy_entries(path)
    except (OSError, UnicodeError) as exc:
        return [], [f"unable to read allowlist: {exc}"]
    issues: list[str] = []
    if len(entries) != EXPECTED_PATH_COUNT:
        issues.append(
            f"public path count is {len(entries)}; expected {EXPECTED_PATH_COUNT}"
        )
    if len(entries) != len(set(entries)):
        issues.append("public allowlist contains duplicate paths")
    invalid = [entry for entry in entries if not _safe_relative(entry)]
    if invalid:
        issues.append("public allowlist contains an unsafe relative path")
    digest = _path_digest(entries)
    if digest != EXPECTED_PATH_DIGEST:
        issues.append(f"public path digest is not approved: {digest}")
    return entries, issues


def _git_inventory(root: Path) -> tuple[dict[str, Path], list[str]]:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        return {}, [f"git inventory failed: {detail}"]
    files: dict[str, Path] = {}
    issues: list[str] = []
    for record in result.stdout.split(b"\x00"):
        if not record:
            continue
        try:
            metadata, path_bytes = record.split(b"\t", 1)
            mode = metadata.split(b" ", 1)[0].decode("ascii")
            relative = path_bytes.decode("utf-8", errors="strict")
        except (ValueError, UnicodeError):
            issues.append("git inventory contains an unparseable entry")
            continue
        if mode != "100644":
            issues.append(f"tracked path is not a regular 100644 file: {relative}")
        files[relative] = root / PurePosixPath(relative)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if untracked.returncode:
        detail = untracked.stderr.decode("utf-8", errors="replace").strip()
        issues.append(f"untracked-file inventory failed: {detail}")
        return files, issues
    for path_bytes in untracked.stdout.split(b"\x00"):
        if not path_bytes:
            continue
        try:
            relative = path_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            issues.append("untracked-file inventory contains non-UTF-8 data")
            continue
        issues.append(
            f"untracked or ignored public source path is not allowed: {relative}"
        )
        files[relative] = root / PurePosixPath(relative)
    return files, issues


def _filesystem_inventory(root: Path) -> tuple[dict[str, Path], list[str]]:
    files: dict[str, Path] = {}
    issues: list[str] = []
    for directory, names, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        names[:] = [name for name in names if name != ".git"]
        for name in tuple(names):
            candidate = current / name
            if candidate.is_symlink():
                relative = candidate.relative_to(root).as_posix()
                issues.append(f"symlink directory is not allowed: {relative}")
                names.remove(name)
        for name in filenames:
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            if candidate.is_symlink():
                issues.append(f"symlink is not allowed: {relative}")
                continue
            if not candidate.is_file():
                issues.append(f"special file is not allowed: {relative}")
                continue
            files[relative] = candidate
    return files, issues


def inventory(root: Path) -> tuple[dict[str, Path], list[str]]:
    if (root / ".git").exists():
        return _git_inventory(root)
    return _filesystem_inventory(root)


def validate_inventory(
    root: Path,
    expected: Iterable[str],
) -> tuple[dict[str, Path], list[str]]:
    files, issues = inventory(root)
    expected_set = set(expected)
    actual_set = set(files)
    for relative in sorted(expected_set - actual_set):
        issues.append(f"missing public source path: {relative}")
    for relative in sorted(actual_set - expected_set):
        issues.append(f"unexpected public source path: {relative}")
    for relative, path in files.items():
        if path.suffix.casefold() in DISALLOWED_BINARY_SUFFIXES:
            issues.append(f"binary or archive path is not allowed: {relative}")
        if path.is_symlink():
            issues.append(f"symlink is not allowed: {relative}")
    return files, issues


def _decode_text(relative: str, path: Path) -> tuple[str | None, list[str]]:
    data = path.read_bytes()
    issues: list[str] = []
    if data.startswith(b"\xef\xbb\xbf"):
        issues.append(f"UTF-8 BOM is not allowed: {relative}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return None, [f"invalid UTF-8: {relative}: {exc}"]
    if "\r" in text:
        issues.append(f"non-LF newline detected: {relative}")
    if text and not text.endswith("\n"):
        issues.append(f"final LF is required: {relative}")
    if any(line.endswith((" ", "\t")) for line in text.splitlines()):
        issues.append(f"trailing whitespace detected: {relative}")
    for offset, character in enumerate(text):
        value = ord(character)
        if value < 32 and value not in ALLOWED_CONTROLS:
            issues.append(
                f"control character U+{value:04X} at offset {offset}: {relative}"
            )
            break
    return text, issues


def _path_denied(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def _markdown_issues(root: Path, relative: str, text: str) -> list[str]:
    issues: list[str] = []
    if text.count("```") % 2:
        issues.append(f"unbalanced fenced code block: {relative}")
    if re.search(
        r"(?i)(?:data:[a-z][a-z0-9.+-]*/[a-z0-9.+-]+|file://)",
        text,
    ):
        issues.append(f"embedded data/file URI is not allowed: {relative}")
    for target in re.findall(r"\]\(([^)\r\n]+)\)", text):
        target = target.strip().strip("<>")
        if re.match(r"^(?:https?|mailto):", target, flags=re.IGNORECASE):
            continue
        clean = target.partition("#")[0]
        if not clean:
            continue
        if "\\" in clean or clean.startswith("/"):
            issues.append(f"unsafe Markdown link in {relative}: {target}")
            continue
        resolved = (root / PurePosixPath(relative).parent / clean).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            issues.append(f"Markdown link leaves the source tree: {relative}")
            continue
        if not resolved.exists():
            issues.append(f"broken Markdown link in {relative}: {target}")
    return issues


def _literal_is_sensitive(value: str) -> bool:
    absolute_path_patterns = (
        r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/][^\s`\"']*",
        r"(?i)\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+"
        r"(?:\\[^\s`\"']*)?",
        r"(?i)(?<![:/])//[A-Za-z0-9._-]+/[A-Za-z0-9$._-]+"
        r"(?:/[^\s`\"']*)?",
        r"(?i)/(?:home|Users)/[A-Za-z0-9._-]+(?:/[^\s`\"']*)?",
        r"(?i)/root(?=$|/|[\s`\"',;:)])(?:/[^\s`\"']*)?",
    )
    if any(re.search(pattern, value) for pattern in PRIVATE_ADDRESS_PATTERNS):
        return True
    return any(
        not any(
            marker in match.group().casefold()
            for marker in SAFE_LITERAL_MARKERS
        )
        and match.group().casefold() not in SAFE_ABSOLUTE_PATH_LITERALS
        and not any(
            match.group().casefold().startswith(prefix)
            for prefix in SAFE_ABSOLUTE_PATH_PREFIXES
        )
        for pattern in absolute_path_patterns
        for match in re.finditer(pattern, value)
    )


def _static_text(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_text(node.left)
        right = _static_text(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                return None
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
    ):
        separator = _static_text(node.func.value)
        values = node.args[0]
        if separator is None or not isinstance(values, (ast.Tuple, ast.List)):
            return None
        parts = [_static_text(item) for item in values.elts]
        if all(part is not None for part in parts):
            return separator.join(part for part in parts if part is not None)
    return None


def _target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, ast.Attribute):
        return (node.attr,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(name for item in node.elts for name in _target_names(item))
    if isinstance(node, ast.Subscript):
        key = _static_text(node.slice)
        return (key,) if key is not None else ()
    return ()


def _sensitive_assignment_name(name: str) -> bool:
    folded = re.sub(r"[_-]+", "_", name.casefold()).strip("_")
    bounded = f"_{folded}_"
    return any(
        f"_{suffix}_" in bounded
        for suffix in SENSITIVE_ASSIGNMENT_SUFFIXES
    )


def _safe_assignment_value(value: str, *, is_test: bool = False) -> bool:
    folded = value.casefold().strip()
    if (
        not folded
        or folded in {"false", "true", "none", "null", "normal"}
        or value.strip() in SAFE_ASSIGNMENT_LITERALS
        or any(marker in folded for marker in SAFE_ASSIGNMENT_MARKERS)
        or any(marker in folded for marker in SAFE_LITERAL_MARKERS)
        or folded in {"0.0.0.0", "::", "::1"}
    ):
        return True
    return is_test and (
        folded.startswith("legacy_node\\")
        or folded in {
            "head",
            "offline",
            "first",
            "second",
            "bearer",
            "sk-live-secret",
            "token-value",
        }
    )


SENSITIVE_TEXT_EQUALS_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"
    r'(?:"([^"\r\n]*)"|\'([^\'\r\n]*)\'|([^\s,}\]#]+))'
)
SENSITIVE_TEXT_COLON_ASSIGNMENT = re.compile(
    r"(?im)^\s*\#?\s*([A-Za-z_][A-Za-z0-9_-]*)\s*:\s+"
    r"(?![A-Za-z_][A-Za-z0-9_.\[\], |]*\s*=)"
    r'(?:"([^"\r\n]*)"|\'([^\'\r\n]*)\'|([^\s,}\]#]+))'
)


def _text_has_sensitive_assignment(value: str, *, is_test: bool = False) -> bool:
    for pattern in (
        SENSITIVE_TEXT_EQUALS_ASSIGNMENT,
        SENSITIVE_TEXT_COLON_ASSIGNMENT,
    ):
        for match in pattern.finditer(value):
            name = match.group(1)
            assigned = next(
                item for item in match.groups()[1:] if item is not None
            )
            if (
                _sensitive_assignment_name(name)
                and assigned.casefold().strip() != name.casefold().strip()
                and not _safe_assignment_value(assigned, is_test=is_test)
            ):
                return True
    return False


def _python_literal_issues(relative: str, text: str) -> list[str]:
    try:
        tree = ast.parse(text, filename=relative)
    except SyntaxError as exc:
        return [f"invalid Python syntax: {relative}: {exc}"]
    is_test = Path(relative).name.startswith("test_")
    scan_complex = relative != "scripts/check_public_source.py"
    for node in ast.walk(tree):
        value = _static_text(node) if scan_complex else (
            node.value
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            else None
        )
        if value is not None and _literal_is_sensitive(value):
            return [f"private address or absolute user path literal: {relative}"]
        if value is not None and _text_has_sensitive_assignment(
            value, is_test=is_test
        ):
            return [f"non-synthetic sensitive assignment text: {relative}"]
        named_values: list[tuple[str, ast.AST | None]] = []
        if isinstance(node, ast.Assign):
            named_values.extend(
                (name, node.value)
                for target in node.targets
                for name in _target_names(target)
            )
        elif isinstance(node, ast.AnnAssign):
            named_values.extend(
                (name, node.value) for name in _target_names(node.target)
            )
        elif isinstance(node, ast.NamedExpr):
            named_values.extend(
                (name, node.value) for name in _target_names(node.target)
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            positional = [*node.args.posonlyargs, *node.args.args]
            if node.args.defaults:
                named_values.extend(
                    (argument.arg, default)
                    for argument, default in zip(
                        positional[-len(node.args.defaults):],
                        node.args.defaults,
                    )
                )
            named_values.extend(
                (argument.arg, default)
                for argument, default in zip(
                    node.args.kwonlyargs,
                    node.args.kw_defaults,
                )
                if default is not None
            )
        elif isinstance(node, ast.keyword) and node.arg is not None:
            named_values.append((node.arg, node.value))
        elif isinstance(node, ast.Dict):
            for key_node, value_node in zip(node.keys, node.values):
                key = _static_text(key_node)
                if key is not None:
                    named_values.append((key, value_node))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 3
        ):
            name = _static_text(node.args[1])
            if name is not None:
                named_values.append((name, node.args[2]))
        for name, value_node in named_values:
            assigned = _static_text(value_node)
            if (
                assigned is not None
                and assigned.casefold().strip() != name.casefold().strip()
                and not _safe_assignment_value(assigned, is_test=is_test)
                and _sensitive_assignment_name(name)
            ):
                return [f"non-synthetic sensitive assignment: {relative}"]
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            if _literal_is_sensitive(token.string):
                return [f"private address or absolute user path comment: {relative}"]
            if _text_has_sensitive_assignment(token.string, is_test=is_test):
                return [f"non-synthetic sensitive assignment comment: {relative}"]
    except (IndentationError, tokenize.TokenError) as exc:
        return [f"unable to tokenize Python source: {relative}: {exc}"]
    return []


def validate_text_privacy(
    root: Path,
    files: dict[str, Path],
) -> list[str]:
    deny_path = root / DENYLIST
    issues: list[str] = []
    try:
        deny_text = deny_path.read_text(encoding="utf-8")
        path_patterns = _policy_entries(deny_path, "path:")
        content_patterns = _policy_entries(deny_path, "content:")
    except (OSError, UnicodeError) as exc:
        return [f"unable to read deny policy: {exc}"]
    deny_entries = [
        line.strip()
        for line in deny_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if hashlib.sha256(deny_text.encode("utf-8")).hexdigest() != EXPECTED_DENY_POLICY_SHA256:
        issues.append("public-export deny policy hash is not approved")
    if (
        len(path_patterns) != EXPECTED_DENY_PATH_COUNT
        or len(content_patterns) != EXPECTED_DENY_CONTENT_COUNT
        or len(deny_entries) != len(set(deny_entries))
        or any(
            not entry.startswith(("path:", "content:"))
            for entry in deny_entries
        )
    ):
        issues.append("public-export deny policy grammar/count is not exact")
    staging_marker = "".join(("Synaphi", "/", "RayClusterManager"))
    token_patterns = (
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile("-----BEGIN " + "PRIVATE KEY"),
    )
    action_pin = re.compile(
        r"\s*uses:\s*[^@\s]+@([0-9a-f]{40})\s*(?:#.*)?$"
    )
    for relative, path in sorted(files.items()):
        if _path_denied(relative, path_patterns):
            issues.append(f"path matches public-export deny policy: {relative}")
        text, decode_issues = _decode_text(relative, path)
        issues.extend(decode_issues)
        if text is None:
            continue
        if staging_marker in text:
            issues.append(f"private staging repository marker detected: {relative}")
        if any(pattern.search(text) for pattern in token_patterns):
            issues.append(f"credential or private-key signature detected: {relative}")
        for line in text.splitlines():
            identities = GIT_OBJECT_ID.findall(line)
            if not identities:
                continue
            pinned = action_pin.fullmatch(line)
            if (
                not relative.startswith(".github/workflows/")
                or pinned is None
                or identities != [pinned.group(1)]
            ):
                issues.append(
                    f"unapproved Git object identity detected: {relative}"
                )
                break
        if relative.endswith(".md"):
            issues.extend(_markdown_issues(root, relative, text))
        if relative.endswith(".py"):
            issues.extend(_python_literal_issues(relative, text))
            continue
        if relative == DENYLIST.as_posix() or relative.startswith("tests/fixtures/"):
            continue
        for pattern in content_patterns:
            try:
                matched = re.search(pattern, text, flags=re.MULTILINE)
            except re.error as exc:
                issues.append(f"invalid content deny expression: {exc}")
                break
            if matched:
                issues.append(f"private marker pattern matched: {relative}")
                break
    return issues


def validate_license_and_notices(root: Path) -> list[str]:
    issues: list[str] = []
    license_path = root / "LICENSE"
    if license_path.is_file():
        data = license_path.read_bytes()
        if len(data) != EXPECTED_LICENSE_BYTES:
            issues.append("LICENSE byte length is not the canonical Apache-2.0 text")
        if hashlib.sha256(data).hexdigest() != EXPECTED_LICENSE_SHA256:
            issues.append("LICENSE SHA-256 is not the canonical Apache-2.0 text")
    else:
        issues.append("LICENSE is missing")
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text("utf-8"))
        if project.get("project", {}).get("license") != "Apache-2.0":
            issues.append("pyproject.toml project license must be Apache-2.0")
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        issues.append(f"unable to validate pyproject.toml licensing: {exc}")
    try:
        notice = (root / "THIRD_PARTY_NOTICES.md").read_text("utf-8").casefold()
        provenance = json.loads(
            (root / "policy/dependency-provenance.json").read_text("utf-8")
        )
        artifacts = provenance.get("artifacts")
        if provenance.get("blockers") != []:
            issues.append("dependency provenance contains a blocker")
        if not isinstance(artifacts, list) or len(artifacts) != 21:
            issues.append("dependency provenance must contain exactly 21 artifacts")
        else:
            normalized_notice = re.sub(r"[-_ ]", "", notice)
            for artifact in artifacts:
                identity = (
                    str(artifact.get("name", "")),
                    str(artifact.get("version", "")),
                    str(artifact.get("license_expression", "")),
                )
                name_present = (
                    bool(identity[0])
                    and re.sub(r"[-_ ]", "", identity[0].casefold())
                    in normalized_notice
                )
                if not (
                    name_present
                    and all(
                        value and value.casefold() in notice
                        for value in identity[1:]
                    )
                ):
                    issues.append(
                        "third-party notice does not cover dependency identity: "
                        f"{identity[0]}"
                    )
        vendor = json.loads(
            (root / "policy/vendor-provenance.json").read_text("utf-8")
        )
        vendor_text = json.dumps(vendor, sort_keys=True).casefold()
        for required in ("librehardwaremonitor", "0.9.6", "mpl-2.0"):
            if required not in vendor_text or required not in notice:
                issues.append(f"vendor notice/provenance is missing {required}")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        issues.append(f"unable to validate third-party notices: {exc}")
    return issues


def validate_product_boundary(root: Path) -> list[str]:
    required_snippets = {
        "temps_server.py": (
            'bind: str = "127.0.0.1"',
            'if bind != "127.0.0.1":',
            'ThreadingHTTPServer((self.bind, self.port)',
        ),
        "src/rcm/config/schema.py": (
            'bind_host: str = "127.0.0.1"',
            '"must be loopback while remote service is enabled"',
        ),
        "src/rcm/legacy_compat.py": ('"legacy_remote_retired"',),
        "src/rcm/privilege.py": ("LOCAL_ADMIN_ELEVATION_ENABLED = False",),
    }
    issues: list[str] = []
    for relative, snippets in required_snippets.items():
        try:
            text = (root / relative).read_text("utf-8")
        except (OSError, UnicodeError) as exc:
            issues.append(f"unable to inspect product boundary in {relative}: {exc}")
            continue
        for snippet in snippets:
            if snippet not in text:
                issues.append(f"product boundary assertion missing in {relative}")
                break
    return issues


def validate_public_tree(root: Path) -> list[str]:
    root = root.resolve()
    allowlist, issues = load_allowlist(root)
    files, inventory_issues = validate_inventory(root, allowlist)
    issues.extend(inventory_issues)
    issues.extend(validate_text_privacy(root, files))
    issues.extend(validate_license_and_notices(root))
    issues.extend(validate_product_boundary(root))
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tree",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="public source tree to validate",
    )
    args = parser.parse_args(argv)
    issues = validate_public_tree(args.tree)
    if issues:
        for issue in issues:
            print(f"ERROR: {issue}", file=sys.stderr)
        print(f"FAIL: public source validation found {len(issues)} issue(s)")
        return 1
    print(
        "PASS: public source validation "
        f"({EXPECTED_PATH_COUNT} paths, {EXPECTED_PATH_DIGEST})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
