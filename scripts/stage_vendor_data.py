#!/usr/bin/env python3
"""Verify and atomically stage the pinned vendor-data allowlist.

This script intentionally has no downloader.  It accepts only a reviewed,
offline extraction and publishes only the files named by the checked-in
manifest to an explicit destination outside the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from typing import NoReturn


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPOSITORY_ROOT / "packaging" / "vendor-data.json"
OUTPUT_MANIFEST_NAME = "vendor-manifest.json"
MAX_MANIFEST_BYTES = 1_048_576
MAX_VENDOR_FILE_BYTES = 134_217_728
EXPECTED_LIBRARY_COUNT = 9
EXPECTED_LICENSE_COUNT = 1


class VendorStageError(Exception):
    """A vendor input or staging safety invariant failed."""


def _fail(message: str) -> NoReturn:
    raise VendorStageError(message)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _read_manifest(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VendorStageError("unable to read vendor manifest") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        _fail("vendor manifest exceeds the size limit")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda item: _fail(f"invalid JSON constant: {item}"),
        )
    except VendorStageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise VendorStageError("vendor manifest is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        _fail("vendor manifest must be an object")
    return value


def _exact_keys(value: object, expected: set[str], path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{path} must be an object")
    if set(value) != expected:
        _fail(f"{path} keys must be exactly {sorted(expected)}")
    return value


def _text(value: object, path: str, *, maximum: int = 2_048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _fail(f"{path} must be a non-empty bounded string")
    if any(ord(character) < 0x20 for character in value):
        _fail(f"{path} contains a control character")
    return value


def _size(value: object, path: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(f"{path} must be an integer between 0 and {maximum}")
    return value


def _checksum(value: object, path: str) -> str:
    result = _text(value, path, maximum=64)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        _fail(f"{path} must be a lowercase SHA-256")
    return result


def _https_url(value: object, path: str) -> str:
    result = _text(value, path)
    if not result.startswith("https://"):
        _fail(f"{path} must be an HTTPS URL")
    return result


def load_vendor_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, object]:
    """Load and strictly validate a vendor allowlist manifest."""

    root = _read_manifest(Path(path))
    _exact_keys(
        root,
        {"schema_version", "component", "source_archive", "license_source", "files"},
        "$",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        _fail("schema_version must be 1")

    component = _exact_keys(root["component"], {"name", "version", "license"}, "component")
    _text(component["name"], "component.name", maximum=128)
    _text(component["version"], "component.version", maximum=64)
    _text(component["license"], "component.license", maximum=64)

    archive = _exact_keys(
        root["source_archive"],
        {"name", "release_url", "download_url", "size", "sha256"},
        "source_archive",
    )
    archive_name = _text(archive["name"], "source_archive.name", maximum=255)
    if Path(archive_name).name != archive_name:
        _fail("source_archive.name must be a base name")
    _https_url(archive["release_url"], "source_archive.release_url")
    _https_url(archive["download_url"], "source_archive.download_url")
    _size(archive["size"], "source_archive.size", maximum=1_073_741_824)
    _checksum(archive["sha256"], "source_archive.sha256")

    license_source = _exact_keys(
        root["license_source"],
        {"url", "sha256"},
        "license_source",
    )
    _https_url(license_source["url"], "license_source.url")
    license_checksum = _checksum(license_source["sha256"], "license_source.sha256")

    files = root["files"]
    if not isinstance(files, list):
        _fail("files must be an array")
    names: set[str] = set()
    destinations: set[str] = set()
    library_count = 0
    license_count = 0
    for index, item in enumerate(files):
        entry = _exact_keys(
            item,
            {"source_name", "destination", "kind", "size", "sha256"},
            f"files[{index}]",
        )
        source_name = _text(entry["source_name"], f"files[{index}].source_name", maximum=255)
        if Path(source_name).name != source_name or source_name in {".", ".."}:
            _fail(f"files[{index}].source_name must be a base name")
        destination = _text(entry["destination"], f"files[{index}].destination", maximum=259)
        destination_path = PurePosixPath(destination)
        if (
            len(destination_path.parts) != 2
            or destination_path.parts[0] != "lhm"
            or destination_path.parts[1] != source_name
        ):
            _fail(f"files[{index}].destination must be lhm/<source_name>")
        folded_name = source_name.casefold()
        folded_destination = destination.casefold()
        if folded_name in names or folded_destination in destinations:
            _fail("file names and destinations must be unique case-insensitively")
        names.add(folded_name)
        destinations.add(folded_destination)
        kind = _text(entry["kind"], f"files[{index}].kind", maximum=16)
        if kind == "library":
            library_count += 1
            if not source_name.casefold().endswith(".dll"):
                _fail("library entries must be DLL files")
        elif kind == "license":
            license_count += 1
            if _checksum(entry["sha256"], f"files[{index}].sha256") != license_checksum:
                _fail("staged license checksum must equal license_source.sha256")
        else:
            _fail("file kind must be library or license")
        _size(entry["size"], f"files[{index}].size", maximum=MAX_VENDOR_FILE_BYTES)
        _checksum(entry["sha256"], f"files[{index}].sha256")
    if library_count != EXPECTED_LIBRARY_COUNT or license_count != EXPECTED_LICENSE_COUNT:
        _fail(
            f"manifest must select exactly {EXPECTED_LIBRARY_COUNT} libraries "
            f"and {EXPECTED_LICENSE_COUNT} license"
        )
    return root


def _is_reparse(path: Path) -> bool:
    try:
        status = path.lstat()
    except OSError as exc:
        raise VendorStageError("unable to inspect a filesystem path") from exc
    attributes = getattr(status, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(status.st_mode) or bool(attributes & reparse_flag)


def _assert_existing_chain_is_plain(path: Path, *, label: str) -> None:
    absolute = Path(os.path.abspath(path))
    pending = [absolute, *absolute.parents]
    for candidate in reversed(pending):
        if candidate.exists() or candidate.is_symlink():
            if _is_reparse(candidate):
                _fail(f"{label} contains a symlink or reparse point")


def _within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _source_inventory(root: Path, expected_names: set[str]) -> None:
    actual_names: set[str] = set()
    try:
        entries = tuple(root.iterdir())
    except OSError as exc:
        raise VendorStageError("unable to enumerate vendor root") from exc
    for entry in entries:
        if _is_reparse(entry):
            _fail("vendor root contains a symlink or reparse point")
        if not entry.is_file():
            _fail("vendor root contains an extra non-file entry")
        actual_names.add(entry.name)
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    if missing or extra:
        _fail(f"vendor root allowlist mismatch; missing={missing!r}, extra={extra!r}")


def _verified_source_bytes(path: Path, *, expected_size: int, expected_checksum: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise VendorStageError("unable to open a selected vendor file") from exc
    try:
        status = os.fstat(descriptor)
        attributes = getattr(status, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if not stat.S_ISREG(status.st_mode) or bool(attributes & reparse_flag):
            _fail("selected vendor input is not a plain regular file")
        if status.st_size != expected_size:
            _fail("selected vendor input size mismatch")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
        if digest.hexdigest() != expected_checksum:
            _fail("selected vendor input SHA-256 mismatch")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write_synced(path: Path, data: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise VendorStageError("unable to write staged vendor data") from exc


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stage_vendor_data(
    *,
    vendor_root: Path,
    destination: Path,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, object]:
    """Validate all inputs and atomically publish the exact allowlist."""

    vendor_root = Path(vendor_root)
    destination = Path(destination)
    if not vendor_root.is_absolute() or not destination.is_absolute():
        _fail("vendor root and destination must be explicit absolute paths")
    _assert_existing_chain_is_plain(vendor_root, label="vendor root")
    if not vendor_root.is_dir():
        _fail("vendor root must be an existing directory")
    resolved_root = vendor_root.resolve(strict=True)
    resolved_repository = REPOSITORY_ROOT.resolve(strict=True)
    if _within(resolved_root, resolved_repository):
        _fail("vendor root must be outside the repository")

    if destination.exists() or destination.is_symlink():
        _fail("destination must not already exist")
    parent = destination.parent
    _assert_existing_chain_is_plain(parent, label="destination parent")
    if not parent.is_dir():
        _fail("destination parent must be an existing directory")
    resolved_destination = parent.resolve(strict=True) / destination.name
    if _within(resolved_destination, resolved_repository):
        _fail("destination must be outside the repository")

    manifest = load_vendor_manifest(Path(manifest_path))
    files = manifest["files"]
    assert isinstance(files, list)
    expected_names = {
        str(entry["source_name"])
        for entry in files
        if isinstance(entry, dict)
    }
    _source_inventory(resolved_root, expected_names)

    verified: dict[str, bytes] = {}
    for entry in files:
        assert isinstance(entry, dict)
        source_name = str(entry["source_name"])
        verified[source_name] = _verified_source_bytes(
            resolved_root / source_name,
            expected_size=int(entry["size"]),
            expected_checksum=str(entry["sha256"]),
        )

    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.stage-",
            dir=resolved_destination.parent,
        )
    )
    published = False
    try:
        lhm_directory = temporary / "lhm"
        lhm_directory.mkdir()
        for entry in files:
            assert isinstance(entry, dict)
            source_name = str(entry["source_name"])
            _write_synced(lhm_directory / source_name, verified[source_name])
        output_manifest = {
            "schema_version": 1,
            "component": manifest["component"],
            "source_archive": manifest["source_archive"],
            "license_source": manifest["license_source"],
            "files": manifest["files"],
        }
        _write_synced(temporary / OUTPUT_MANIFEST_NAME, _canonical_bytes(output_manifest))
        _sync_directory(lhm_directory)
        _sync_directory(temporary)
        if resolved_destination.exists() or resolved_destination.is_symlink():
            _fail("destination appeared during staging")
        os.replace(temporary, resolved_destination)
        published = True
        _sync_directory(resolved_destination.parent)
        return output_manifest
    except VendorStageError:
        raise
    except OSError as exc:
        raise VendorStageError("unable to atomically publish staged vendor data") from exc
    finally:
        if not published and temporary.exists():
            shutil.rmtree(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        output = stage_vendor_data(
            vendor_root=arguments.vendor_root,
            destination=arguments.destination,
            manifest_path=arguments.manifest,
        )
    except VendorStageError as exc:
        print(f"vendor staging failed: {exc}", file=os.sys.stderr)
        return 1
    print(hashlib.sha256(_canonical_bytes(output)).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
