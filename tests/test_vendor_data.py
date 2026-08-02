from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.stage_vendor_data import (
    DEFAULT_MANIFEST,
    OUTPUT_MANIFEST_NAME,
    REPOSITORY_ROOT,
    VendorStageError,
    load_vendor_manifest,
    stage_vendor_data,
)


PROVENANCE_PATH = REPOSITORY_ROOT / "policy" / "vendor-provenance.json"
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "stage_vendor_data.py"
EXPECTED_LIBRARIES = {
    "BlackSharp.Core.dll",
    "DiskInfoToolkit.dll",
    "HidSharp.dll",
    "LibreHardwareMonitorLib.dll",
    "RAMSPDToolkit-NDD.dll",
    "System.Buffers.dll",
    "System.Memory.dll",
    "System.Numerics.Vectors.dll",
    "System.Runtime.CompilerServices.Unsafe.dll",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _synthetic_manifest(root: Path) -> tuple[Path, dict[str, bytes]]:
    payloads = {
        **{
            f"Synthetic.Dependency.{index}.dll": f"synthetic-library-{index}".encode()
            for index in range(9)
        },
        "LICENSE-Synthetic.txt": b"synthetic license text\n",
    }
    files = [
        {
            "source_name": name,
            "destination": f"lhm/{name}",
            "kind": "license" if name.endswith(".txt") else "library",
            "size": len(data),
            "sha256": _sha256(data),
        }
        for name, data in payloads.items()
    ]
    license_hash = _sha256(payloads["LICENSE-Synthetic.txt"])
    manifest = {
        "schema_version": 1,
        "component": {
            "name": "SyntheticMonitor",
            "version": "1.0.0",
            "license": "MPL-2.0",
        },
        "source_archive": {
            "name": "SyntheticMonitor.zip",
            "release_url": "https://example.com/releases/tag/1.0.0",
            "download_url": "https://example.com/releases/SyntheticMonitor.zip",
            "size": 123,
            "sha256": _sha256(b"synthetic archive"),
        },
        "license_source": {
            "url": "https://example.com/SyntheticMonitor/LICENSE",
            "sha256": license_hash,
        },
        "files": files,
    }
    manifest_path = root / "vendor-data.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, payloads


def _write_vendor_root(root: Path, payloads: dict[str, bytes]) -> Path:
    vendor_root = root / "vendor-input"
    vendor_root.mkdir()
    for name, data in payloads.items():
        (vendor_root / name).write_bytes(data)
    return vendor_root


class VendorManifestTests(unittest.TestCase):
    def test_checked_in_manifest_pins_official_release_and_minimal_set(self) -> None:
        manifest = load_vendor_manifest()
        archive = manifest["source_archive"]
        license_source = manifest["license_source"]
        files = manifest["files"]
        assert isinstance(archive, dict)
        assert isinstance(license_source, dict)
        assert isinstance(files, list)

        self.assertEqual("LibreHardwareMonitor.zip", archive["name"])
        self.assertEqual(6_632_626, archive["size"])
        self.assertRegex(archive["sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(license_source["sha256"], r"^[0-9a-f]{64}$")
        libraries = {
            entry["source_name"]
            for entry in files
            if isinstance(entry, dict) and entry["kind"] == "library"
        }
        self.assertEqual(EXPECTED_LIBRARIES, libraries)
        self.assertEqual(10, len(files))
        self.assertEqual(
            license_source["sha256"],
            next(
                entry["sha256"]
                for entry in files
                if isinstance(entry, dict) and entry["kind"] == "license"
            ),
        )
        self.assertTrue(
            all(
                isinstance(entry, dict)
                and entry["destination"] == f"lhm/{entry['source_name']}"
                for entry in files
            )
        )

    def test_provenance_exactly_matches_staging_manifest(self) -> None:
        manifest = load_vendor_manifest()
        provenance = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))

        self.assertEqual(
            manifest["component"],
            {
                key: provenance["component"][key]
                for key in ("name", "version", "license")
            },
        )
        self.assertEqual(manifest["source_archive"], provenance["source_archive"])
        self.assertEqual(manifest["license_source"], provenance["license_source"])
        manifest_identity = {
            (
                entry["source_name"],
                entry["destination"],
                entry["size"],
                entry["sha256"],
            )
            for entry in manifest["files"]
        }
        provenance_identity = {
            (
                entry["source_name"],
                entry["destination"],
                entry["size"],
                entry["sha256"],
            )
            for entry in provenance["selected_files"]
        }
        self.assertEqual(manifest_identity, provenance_identity)
        self.assertEqual(9, provenance["selection"]["library_count"])
        self.assertEqual(1, provenance["selection"]["license_count"])
        self.assertEqual(
            sum(entry["size"] for entry in manifest["files"]),
            provenance["selection"]["total_staged_size"],
        )
        self.assertFalse(provenance["selection"]["repository_binary_storage"])
        self.assertFalse(provenance["selection"]["network_during_staging"])
        self.assertFalse(provenance["selection"]["process_creation_during_staging"])

    def test_repository_contains_metadata_not_vendor_payloads(self) -> None:
        for directory in ("packaging", "policy", "scripts", "src", "tests"):
            dlls = tuple((REPOSITORY_ROOT / directory).rglob("*.dll"))
            self.assertEqual((), dlls, directory)

    def test_stage_script_has_no_network_or_process_dependency(self) -> None:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
        forbidden_imports = {"requests", "socket", "subprocess", "urllib"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(forbidden_imports.isdisjoint(imported))
        self.assertNotIn("system", {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)})


class VendorStagingTests(unittest.TestCase):
    def test_stages_only_allowlist_atomically_with_canonical_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, payloads = _synthetic_manifest(root)
            vendor_root = _write_vendor_root(root, payloads)
            destination = root / "published"

            output = stage_vendor_data(
                vendor_root=vendor_root,
                destination=destination,
                manifest_path=manifest_path,
            )

            expected_paths = {
                f"lhm/{name}" for name in payloads
            } | {OUTPUT_MANIFEST_NAME}
            actual_paths = {
                path.relative_to(destination).as_posix()
                for path in destination.rglob("*")
                if path.is_file()
            }
            self.assertEqual(expected_paths, actual_paths)
            for name, data in payloads.items():
                self.assertEqual(data, (destination / "lhm" / name).read_bytes())
            raw_manifest = (destination / OUTPUT_MANIFEST_NAME).read_bytes()
            self.assertEqual(output, json.loads(raw_manifest))
            self.assertEqual(
                json.dumps(
                    output,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode(),
                raw_manifest,
            )
            self.assertEqual((), tuple(root.glob(".published.stage-*")))

    def test_rejects_missing_extra_and_hash_or_size_mismatch(self) -> None:
        cases = ("missing", "extra", "hash", "size")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest_path, payloads = _synthetic_manifest(root)
                vendor_root = _write_vendor_root(root, payloads)
                if case == "missing":
                    next(vendor_root.iterdir()).unlink()
                elif case == "extra":
                    (vendor_root / "unexpected.bin").write_bytes(b"extra")
                elif case == "hash":
                    target = next(vendor_root.glob("*.dll"))
                    target.write_bytes(b"x" * target.stat().st_size)
                else:
                    target = next(vendor_root.glob("*.dll"))
                    target.write_bytes(target.read_bytes() + b"x")
                destination = root / "published"

                with self.assertRaises(VendorStageError):
                    stage_vendor_data(
                        vendor_root=vendor_root,
                        destination=destination,
                        manifest_path=manifest_path,
                    )

                self.assertFalse(destination.exists())
                self.assertEqual((), tuple(root.glob(".published.stage-*")))

    def test_rejects_existing_or_repository_contained_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, payloads = _synthetic_manifest(root)
            vendor_root = _write_vendor_root(root, payloads)
            existing = root / "existing"
            existing.mkdir()
            marker = existing / "preserved.txt"
            marker.write_bytes(b"preserved")

            with self.assertRaises(VendorStageError):
                stage_vendor_data(
                    vendor_root=vendor_root,
                    destination=existing,
                    manifest_path=manifest_path,
                )
            self.assertEqual(b"preserved", marker.read_bytes())

            contained = REPOSITORY_ROOT / "synthetic-vendor-output"
            self.assertFalse(contained.exists())
            with self.assertRaises(VendorStageError):
                stage_vendor_data(
                    vendor_root=vendor_root,
                    destination=contained,
                    manifest_path=manifest_path,
                )
            self.assertFalse(contained.exists())

    def test_rejects_relative_paths_and_repository_vendor_root(self) -> None:
        with self.assertRaises(VendorStageError):
            stage_vendor_data(
                vendor_root=Path("relative-input"),
                destination=Path("relative-output"),
                manifest_path=DEFAULT_MANIFEST,
            )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(VendorStageError):
                stage_vendor_data(
                    vendor_root=REPOSITORY_ROOT,
                    destination=Path(directory) / "published",
                    manifest_path=DEFAULT_MANIFEST,
                )

    def test_rejects_symlinked_selected_input_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path, payloads = _synthetic_manifest(root)
            vendor_root = _write_vendor_root(root, payloads)
            selected = next(vendor_root.glob("*.dll"))
            original = root / "original"
            selected.replace(original)
            try:
                selected.symlink_to(original)
            except OSError:
                self.skipTest("file symlink creation is unavailable")

            with self.assertRaises(VendorStageError):
                stage_vendor_data(
                    vendor_root=vendor_root,
                    destination=root / "published",
                    manifest_path=manifest_path,
                )
            self.assertFalse((root / "published").exists())

    def test_manifest_validation_rejects_duplicate_unknown_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_bytes(b'{"schema_version":1,"schema_version":1}')
            with self.assertRaises(VendorStageError):
                load_vendor_manifest(duplicate)

            manifest_path, _ = _synthetic_manifest(root)
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            value["unknown"] = True
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(VendorStageError):
                load_vendor_manifest(manifest_path)

            manifest_path, _ = _synthetic_manifest(root)
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            value["files"][0]["destination"] = "lhm/../escape.dll"
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(VendorStageError):
                load_vendor_manifest(manifest_path)


if __name__ == "__main__":
    unittest.main()
