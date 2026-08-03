"""Local, secret-free configuration bootstrap and setup wizard."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import os
from pathlib import Path
import stat

from .bootstrap import (
    BootstrapPlan,
    BootstrapRequest,
    Environment,
    plan_bootstrap,
    select_deployment,
)
from .config.schema import (
    MAX_CONFIG_BYTES,
    Config,
    ConfigValidationError,
    NodesSection,
    canonical_config_bytes,
    canonical_json_bytes,
    config_to_dict,
    decode_json_bytes,
)
from .config.migrations import V1ImportProjection, project_v1_import
from .config.store import (
    ConfigConflictError,
    ConfigStore,
    PathFilesystem,
    StoredConfig,
)
from .identity import DeploymentKind, identity_for
from .paths import KnownFolders


V1_IMPORT_RECEIPT_VERSION = 1
MAX_V1_IMPORT_RECEIPT_BYTES = 4_096


class V1ImportError(RuntimeError):
    """A 1.x import could not be completed without weakening its boundary."""


class V1ImportConflictError(V1ImportError):
    """The selected source or destination changed during an import."""


class V1ImportCleanupError(V1ImportError):
    """Rollback committed, but its application-owned receipt remains."""

    def __init__(self, stored: StoredConfig) -> None:
        self.stored = stored
        super().__init__(
            "rollback completed but receipt cleanup did not complete"
        )

    def __repr__(self) -> str:
        return (
            "V1ImportCleanupError("
            f"generation={self.stored.generation}, "
            f"checksum={self.stored.checksum!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _SourceSnapshot:
    path: Path
    raw: bytes
    size: int
    checksum: str
    identity: tuple[int, int, int, int]

    def __repr__(self) -> str:
        return (
            "_SourceSnapshot(path=<redacted>, raw=<redacted>, "
            f"size={self.size}, checksum={self.checksum!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class V1ImportPreview:
    """Immutable source and destination facts approved by the user."""

    source_path: Path
    source_size: int
    source_checksum: str
    source_identity: tuple[int, int, int, int]
    destination_generation: int
    destination_checksum: str
    projection: V1ImportProjection

    def __repr__(self) -> str:
        return (
            "V1ImportPreview(source_path=<redacted>, "
            f"source_size={self.source_size}, "
            f"source_checksum={self.source_checksum!r}, "
            f"destination_generation={self.destination_generation}, "
            f"mapped_count={len(self.projection.mapped_fields)}, "
            f"skipped_count={len(self.projection.skipped_fields)}, "
            f"rejected_count={len(self.projection.rejected_fields)})"
        )


@dataclass(frozen=True, slots=True)
class V1ImportReceipt:
    """Value-free, generation-bound rollback receipt."""

    source_schema: int
    source_size: int
    source_checksum: str
    mapped_count: int
    skipped_count: int
    rejected_count: int
    imported_generation: int
    imported_checksum: str
    import_transaction_id: str = field(repr=False)
    backup_generation: int
    backup_checksum: str


@dataclass(frozen=True, slots=True, repr=False)
class V1ImportResult:
    """Result of an explicit import attempt."""

    changed: bool
    stored: StoredConfig
    receipt: V1ImportReceipt | None

    def __repr__(self) -> str:
        return (
            "V1ImportResult("
            f"changed={self.changed}, generation={self.stored.generation}, "
            f"checksum={self.stored.checksum!r}, "
            f"has_receipt={self.receipt is not None})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _ConfigurationChoice:
    kind: str
    config: Config | None = None
    source_path: Path | None = None

    def __repr__(self) -> str:
        return f"_ConfigurationChoice(kind={self.kind!r}, values=<redacted>)"


def default_v1_config_path() -> Path | None:
    """Return the conventional 1.x path without probing or scanning it."""

    app_data = os.environ.get("APPDATA", "").strip()
    if not app_data:
        return None
    return Path(app_data) / "RayClusterManager" / "config.json"


def _has_reparse_attribute(details: os.stat_result) -> bool:
    return bool(getattr(details, "st_file_attributes", 0) & 0x400)


def _windows_drive_type(path: Path) -> int:
    if os.name != "nt":
        return 3
    import ctypes
    from ctypes import wintypes

    drive = Path(path).drive
    if not drive:
        return 0
    get_drive_type = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    ).GetDriveTypeW
    get_drive_type.argtypes = (wintypes.LPCWSTR,)
    get_drive_type.restype = wintypes.UINT
    return int(get_drive_type(drive + "\\"))


def _assert_local_regular_source(path: Path) -> os.stat_result:
    path = Path(path)
    text = str(path)
    lowered = text.casefold()
    if (
        not path.is_absolute()
        or lowered.startswith(("\\\\", "//", "\\??\\", "\\device\\"))
        or lowered.startswith(("\\\\?\\", "\\\\.\\"))
        or (os.name == "nt" and ":" in text[len(path.drive):])
    ):
        raise V1ImportError("the selected 1.x source is not a local absolute file")
    if os.name == "nt" and _windows_drive_type(path) in {0, 1, 4}:
        raise V1ImportError("the selected 1.x source is not on a local drive")
    try:
        current = path
        while True:
            details = os.stat(current, follow_symlinks=False)
            if stat.S_ISLNK(details.st_mode) or _has_reparse_attribute(details):
                raise V1ImportError("the selected 1.x source uses an alias")
            if current.parent == current:
                break
            current = current.parent
        details = os.stat(path, follow_symlinks=False)
    except V1ImportError:
        raise
    except OSError:
        raise V1ImportError("the selected 1.x source is unavailable") from None
    if not stat.S_ISREG(details.st_mode):
        raise V1ImportError("the selected 1.x source is not a regular file")
    if details.st_size > MAX_CONFIG_BYTES:
        raise V1ImportError("the selected 1.x source is too large")
    return details


def _source_identity(details: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(details.st_dev),
        int(details.st_ino),
        int(details.st_mtime_ns),
        int(details.st_ctime_ns),
    )


def _read_source_snapshot(path: Path) -> _SourceSnapshot:
    before = _assert_local_regular_source(path)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_CONFIG_BYTES
            or _source_identity(before)[:3] != _source_identity(opened)[:3]
            or before.st_size != opened.st_size
        ):
            raise V1ImportConflictError(
                "the selected 1.x source changed before its handle opened"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65_536, MAX_CONFIG_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_CONFIG_BYTES:
                raise V1ImportError("the selected 1.x source is too large")
        raw = b"".join(chunks)
        handle_after = os.fstat(descriptor)
    except V1ImportError:
        raise
    except OSError:
        raise V1ImportError("the selected 1.x source could not be read") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after = _assert_local_regular_source(path)
    if (
        _source_identity(before)[:3] != _source_identity(handle_after)[:3]
        or _source_identity(handle_after)[:3] != _source_identity(after)[:3]
        or before.st_size != after.st_size
        or handle_after.st_size != after.st_size
        or len(raw) != after.st_size
    ):
        raise V1ImportConflictError("the selected 1.x source changed while read")
    return _SourceSnapshot(
        path=Path(path),
        raw=raw,
        size=len(raw),
        checksum=hashlib.sha256(raw).hexdigest(),
        identity=_source_identity(after),
    )


def _same_source(left: _SourceSnapshot, right: _SourceSnapshot) -> bool:
    return (
        left.identity == right.identity
        and left.size == right.size
        and left.checksum == right.checksum
        and left.raw == right.raw
    )


def _receipt_path(store: ConfigStore) -> Path:
    return store.path.with_name(store.path.name + ".v1-import-receipt")


def _receipt_temp_path(store: ConfigStore) -> Path:
    path = _receipt_path(store)
    return path.with_name(path.name + ".tmp")


def _destination_paths(store: ConfigStore) -> tuple[Path, ...]:
    return (
        store.path,
        store.backup_path,
        store.backup_temp_path,
        store.temp_path,
        store.journal_path,
        store.journal_temp_path,
        store.lock_path,
        _receipt_path(store),
        _receipt_temp_path(store),
    )


def _assert_source_not_destination(source: Path, store: ConfigStore) -> None:
    source_text = os.path.normcase(os.path.abspath(source))
    for destination in _destination_paths(store):
        if source_text == os.path.normcase(os.path.abspath(destination)):
            raise V1ImportError("the selected source aliases 2.x state")
        try:
            if (
                source.exists()
                and destination.exists()
                and os.path.samefile(source, destination)
            ):
                raise V1ImportError("the selected source aliases 2.x state")
        except V1ImportError:
            raise
        except OSError:
            raise V1ImportError("source identity could not be verified") from None


def _assert_snapshot_not_destination(
    snapshot: _SourceSnapshot,
    store: ConfigStore,
) -> None:
    source_file_identity = snapshot.identity[:2]
    for destination in _destination_paths(store):
        try:
            details = os.stat(destination, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            raise V1ImportError("destination identity could not be verified") from None
        if (int(details.st_dev), int(details.st_ino)) == source_file_identity:
            raise V1ImportError("the selected source aliases 2.x state")


def prepare_v1_import(source_path: Path, store: ConfigStore) -> V1ImportPreview:
    """Read and project a selected 1.x file without mutating either side."""

    if not isinstance(store, ConfigStore):
        raise TypeError("store must be ConfigStore")
    source_path = Path(source_path)
    _assert_source_not_destination(source_path, store)
    first = _read_source_snapshot(source_path)
    _assert_snapshot_not_destination(first, store)
    current = store.load()
    if current.generation < 1:
        raise V1ImportError("2.x settings must be initialized before import")
    second = _read_source_snapshot(source_path)
    _assert_snapshot_not_destination(second, store)
    if not _same_source(first, second):
        raise V1ImportConflictError("the selected 1.x source changed during preview")
    projection = project_v1_import(second.raw, current.config)
    return V1ImportPreview(
        source_path=source_path,
        source_size=second.size,
        source_checksum=second.checksum,
        source_identity=second.identity,
        destination_generation=current.generation,
        destination_checksum=current.checksum,
        projection=projection,
    )


def _receipt_body(receipt: V1ImportReceipt) -> dict[str, object]:
    return {
        "version": V1_IMPORT_RECEIPT_VERSION,
        "source_schema": receipt.source_schema,
        "source_size": receipt.source_size,
        "source_checksum": receipt.source_checksum,
        "mapped_count": receipt.mapped_count,
        "skipped_count": receipt.skipped_count,
        "rejected_count": receipt.rejected_count,
        "imported_generation": receipt.imported_generation,
        "imported_checksum": receipt.imported_checksum,
        "import_transaction_id": receipt.import_transaction_id,
        "backup_generation": receipt.backup_generation,
        "backup_checksum": receipt.backup_checksum,
    }


def _receipt_bytes(receipt: V1ImportReceipt) -> bytes:
    body = _receipt_body(receipt)
    envelope = dict(body)
    envelope["receipt_checksum"] = hashlib.sha256(
        canonical_json_bytes(body)
    ).hexdigest()
    return canonical_json_bytes(envelope)


def _decode_receipt(raw: bytes) -> V1ImportReceipt:
    try:
        decoded = decode_json_bytes(raw, max_bytes=MAX_V1_IMPORT_RECEIPT_BYTES)
    except Exception:
        raise V1ImportError("the import rollback receipt is invalid") from None
    expected_keys = {
        "version",
        "source_schema",
        "source_size",
        "source_checksum",
        "mapped_count",
        "skipped_count",
        "rejected_count",
        "imported_generation",
        "imported_checksum",
        "import_transaction_id",
        "backup_generation",
        "backup_checksum",
        "receipt_checksum",
    }
    if not isinstance(decoded, dict) or set(decoded) != expected_keys:
        raise V1ImportError("the import rollback receipt is invalid")
    checksum = decoded.pop("receipt_checksum")
    if (
        not isinstance(checksum, str)
        or checksum != hashlib.sha256(canonical_json_bytes(decoded)).hexdigest()
    ):
        raise V1ImportError("the import rollback receipt is invalid")
    integer_fields = (
        "version",
        "source_schema",
        "source_size",
        "mapped_count",
        "skipped_count",
        "rejected_count",
        "imported_generation",
        "backup_generation",
    )
    if any(type(decoded[name]) is not int for name in integer_fields):
        raise V1ImportError("the import rollback receipt is invalid")
    checksum_fields = (
        "source_checksum",
        "imported_checksum",
        "import_transaction_id",
        "backup_checksum",
    )
    if any(
        not isinstance(decoded[name], str)
        or len(decoded[name]) != 64
        or decoded[name].lower() != decoded[name]
        or any(character not in "0123456789abcdef" for character in decoded[name])
        for name in checksum_fields
    ):
        raise V1ImportError("the import rollback receipt is invalid")
    if (
        decoded["version"] != V1_IMPORT_RECEIPT_VERSION
        or not 0 <= decoded["source_schema"] <= 15
        or not 0 <= decoded["source_size"] <= MAX_CONFIG_BYTES
        or any(decoded[name] < 0 for name in (
            "mapped_count", "skipped_count", "rejected_count"
        ))
        or decoded["imported_generation"] < 1
        or decoded["backup_generation"] != decoded["imported_generation"] - 1
    ):
        raise V1ImportError("the import rollback receipt is invalid")
    return V1ImportReceipt(
        source_schema=decoded["source_schema"],
        source_size=decoded["source_size"],
        source_checksum=decoded["source_checksum"],
        mapped_count=decoded["mapped_count"],
        skipped_count=decoded["skipped_count"],
        rejected_count=decoded["rejected_count"],
        imported_generation=decoded["imported_generation"],
        imported_checksum=decoded["imported_checksum"],
        import_transaction_id=decoded["import_transaction_id"],
        backup_generation=decoded["backup_generation"],
        backup_checksum=decoded["backup_checksum"],
    )


def _write_receipt(store: ConfigStore, receipt: V1ImportReceipt) -> None:
    filesystem = PathFilesystem()
    path = _receipt_path(store)
    temporary = _receipt_temp_path(store)
    raw = _receipt_bytes(receipt)
    filesystem.ensure_parent(path)
    filesystem.unlink(temporary, missing_ok=True)
    try:
        filesystem.write_bytes(temporary, raw)
        filesystem.fsync_file(temporary)
        filesystem.replace(temporary, path)
        filesystem.fsync_directory(path.parent)
    finally:
        filesystem.unlink(temporary, missing_ok=True)
    if _load_receipt(store) != receipt:
        raise V1ImportError("the import rollback receipt could not be verified")


def _load_receipt(store: ConfigStore) -> V1ImportReceipt:
    path = _receipt_path(store)
    descriptor = -1
    try:
        before = os.stat(path, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or _has_reparse_attribute(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > MAX_V1_IMPORT_RECEIPT_BYTES
        ):
            raise V1ImportError("the import rollback receipt is invalid")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size > MAX_V1_IMPORT_RECEIPT_BYTES
            or _source_identity(before)[:3] != _source_identity(opened)[:3]
        ):
            raise V1ImportError("the import rollback receipt is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(4_096, MAX_V1_IMPORT_RECEIPT_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_V1_IMPORT_RECEIPT_BYTES:
                raise V1ImportError("the import rollback receipt is invalid")
        raw = b"".join(chunks)
        if len(raw) != opened.st_size:
            raise V1ImportError("the import rollback receipt is invalid")
        handle_after = os.fstat(descriptor)
        after = os.stat(path, follow_symlinks=False)
        if (
            _source_identity(before)[:3] != _source_identity(handle_after)[:3]
            or _source_identity(handle_after)[:3] != _source_identity(after)[:3]
            or before.st_size != handle_after.st_size
            or handle_after.st_size != after.st_size
        ):
            raise V1ImportError("the import rollback receipt is invalid")
    except V1ImportError:
        raise
    except OSError:
        raise V1ImportError("no valid import rollback receipt is available") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return _decode_receipt(raw)


def _remove_receipt(store: ConfigStore) -> None:
    filesystem = PathFilesystem()
    filesystem.unlink(_receipt_temp_path(store), missing_ok=True)
    filesystem.unlink(_receipt_path(store), missing_ok=True)
    filesystem.fsync_directory(store.path.parent)


def _preview_matches_snapshot(
    preview: V1ImportPreview,
    snapshot: _SourceSnapshot,
) -> bool:
    return (
        preview.source_identity == snapshot.identity
        and preview.source_size == snapshot.size
        and preview.source_checksum == snapshot.checksum
    )


def _rollback_imported_generation(
    store: ConfigStore,
    imported: StoredConfig,
    previous: StoredConfig,
    import_transaction_id: str,
) -> None:
    restored = store.rollback_previous(
        expected_current_generation=imported.generation,
        expected_backup_generation=previous.generation,
        expected_backup_checksum=previous.checksum,
        expected_current_transaction_id=import_transaction_id,
    )
    _finish_receipt_cleanup(store, restored)


def _finish_receipt_cleanup(store: ConfigStore, stored: StoredConfig) -> None:
    try:
        _remove_receipt(store)
    except Exception:
        raise V1ImportCleanupError(stored) from None


def apply_v1_import(preview: V1ImportPreview, store: ConfigStore) -> V1ImportResult:
    """Apply one approved preview and create a bounded rollback receipt."""

    if not isinstance(preview, V1ImportPreview):
        raise TypeError("preview must be V1ImportPreview")
    if not isinstance(store, ConfigStore):
        raise TypeError("store must be ConfigStore")
    _assert_source_not_destination(preview.source_path, store)
    current = store.load()
    if (
        current.generation != preview.destination_generation
        or current.checksum != preview.destination_checksum
    ):
        raise V1ImportConflictError("2.x settings changed after import preview")
    source = _read_source_snapshot(preview.source_path)
    _assert_snapshot_not_destination(source, store)
    if not _preview_matches_snapshot(preview, source):
        raise V1ImportConflictError("the selected 1.x source changed after preview")
    projection = project_v1_import(source.raw, current.config)
    if projection != preview.projection:
        raise V1ImportConflictError("the selected 1.x projection changed after preview")
    final_source = _read_source_snapshot(preview.source_path)
    _assert_snapshot_not_destination(final_source, store)
    if not _same_source(source, final_source):
        raise V1ImportConflictError("the selected 1.x source changed before apply")
    if projection.config == current.config:
        return V1ImportResult(changed=False, stored=current, receipt=None)

    receipt_path = _receipt_path(store)
    if receipt_path.exists():
        try:
            existing_receipt = _load_receipt(store)
        except V1ImportError:
            _remove_receipt(store)
        else:
            if (
                current.generation == existing_receipt.imported_generation
                and current.checksum == existing_receipt.imported_checksum
                and current.transaction_id
                == existing_receipt.import_transaction_id
            ):
                raise V1ImportConflictError(
                    "the current imported generation must be rolled back first"
                )
            _remove_receipt(store)
    if current.generation >= (1 << 63) - 2:
        raise V1ImportError(
            "2.x settings lack a reserved rollback generation"
        )
    import_transaction_id = os.urandom(32).hex()
    receipt = V1ImportReceipt(
        source_schema=projection.source_schema,
        source_size=source.size,
        source_checksum=source.checksum,
        mapped_count=len(projection.mapped_fields),
        skipped_count=len(projection.skipped_fields),
        rejected_count=len(projection.rejected_fields),
        imported_generation=current.generation + 1,
        imported_checksum=hashlib.sha256(
            canonical_config_bytes(projection.config)
        ).hexdigest(),
        import_transaction_id=import_transaction_id,
        backup_generation=current.generation,
        backup_checksum=current.checksum,
    )
    try:
        _write_receipt(store, receipt)
        prepared_source = _read_source_snapshot(preview.source_path)
        _assert_snapshot_not_destination(prepared_source, store)
        if not _same_source(source, prepared_source):
            raise V1ImportConflictError(
                "the selected 1.x source changed before commit"
            )
    except Exception:
        _remove_receipt(store)
        raise V1ImportError(
            "import preparation failed; the previous 2.x settings were retained"
        ) from None

    try:
        imported = store.save(
            projection.config,
            expected_generation=current.generation,
            transaction_id=import_transaction_id,
        )
    except ConfigConflictError:
        try:
            _remove_receipt(store)
        except Exception:
            pass
        raise V1ImportConflictError(
            "2.x settings changed while import attempted to commit"
        ) from None
    except Exception:
        try:
            recovered = store.load()
            if recovered == current:
                _remove_receipt(store)
                raise V1ImportError(
                    "import failed; the previous 2.x settings were retained"
                ) from None
            if (
                recovered.generation == current.generation + 1
                and recovered.config == projection.config
                and recovered.transaction_id == import_transaction_id
            ):
                _rollback_imported_generation(
                    store,
                    recovered,
                    current,
                    import_transaction_id,
                )
                raise V1ImportError(
                    "import failed; the previous 2.x settings were restored"
                ) from None
        except V1ImportError:
            raise
        except Exception:
            raise V1ImportError(
                "import failed and automatic recovery could not complete"
            ) from None
        raise V1ImportError(
            "import failed and its committed state could not be authenticated"
        ) from None
    if (
        imported.generation != receipt.imported_generation
        or imported.checksum != receipt.imported_checksum
        or imported.transaction_id != receipt.import_transaction_id
    ):
        try:
            _rollback_imported_generation(
                store,
                imported,
                current,
                import_transaction_id,
            )
        except V1ImportCleanupError:
            raise
        except Exception:
            raise V1ImportError(
                "import identity mismatch and automatic rollback failed"
            ) from None
        raise V1ImportError(
            "import identity mismatch; the previous 2.x settings were restored"
        )
    try:
        post_save_source = _read_source_snapshot(preview.source_path)
        _assert_snapshot_not_destination(post_save_source, store)
        if not _same_source(source, post_save_source):
            raise V1ImportConflictError("the selected 1.x source changed after apply")
        if store.load() != imported or _load_receipt(store) != receipt:
            raise V1ImportError("the imported settings could not be verified")
    except Exception:
        try:
            _rollback_imported_generation(
                store,
                imported,
                current,
                import_transaction_id,
            )
        except V1ImportCleanupError:
            raise
        except Exception:
            raise V1ImportError(
                "import failed and automatic rollback could not complete"
            ) from None
        raise V1ImportError(
            "import failed; the previous 2.x settings were restored"
        ) from None
    return V1ImportResult(changed=True, stored=imported, receipt=receipt)


def rollback_v1_import(store: ConfigStore) -> StoredConfig:
    """Restore only the backup authenticated by the current import receipt."""

    if not isinstance(store, ConfigStore):
        raise TypeError("store must be ConfigStore")
    receipt = _load_receipt(store)
    current = store.load()
    if (
        current.generation == receipt.backup_generation
        and current.checksum == receipt.backup_checksum
    ):
        _finish_receipt_cleanup(store, current)
        return current
    if (
        current.generation == receipt.imported_generation + 1
        and current.checksum == receipt.backup_checksum
    ):
        _finish_receipt_cleanup(store, current)
        return current
    if (
        current.generation != receipt.imported_generation
        or current.checksum != receipt.imported_checksum
        or current.transaction_id != receipt.import_transaction_id
    ):
        raise V1ImportConflictError("2.x settings changed after the recorded import")
    restored = store.rollback_previous(
        expected_current_generation=receipt.imported_generation,
        expected_backup_generation=receipt.backup_generation,
        expected_backup_checksum=receipt.backup_checksum,
        expected_current_transaction_id=receipt.import_transaction_id,
    )
    _finish_receipt_cleanup(store, restored)
    return restored


def initialize_runtime_config(plan: BootstrapPlan) -> StoredConfig:
    """Create or load the strict local configuration for one startup plan."""

    if not isinstance(plan, BootstrapPlan):
        raise TypeError("plan must be a BootstrapPlan")
    for operation in plan.directories:
        Path(str(operation.path)).mkdir(
            parents=operation.parents,
            exist_ok=operation.exist_ok,
        )
    store = ConfigStore(Path(str(plan.paths.config_file)))
    stored = store.load()
    if stored.generation == 0:
        initial = replace(
            stored.config,
            app=replace(
                stored.config.app,
                environment=plan.identity.deployment.value,
            ),
        )
        config_to_dict(initial)
        try:
            stored = store.save(initial, expected_generation=0)
        except ConfigConflictError:
            stored = store.load()
            if stored.generation == 0:
                raise
    return stored


def host_bootstrap_plan(environment: Environment, *, frozen: bool) -> BootstrapPlan:
    """Resolve the current host into the import-safe bootstrap model."""

    import os
    import sys

    if not isinstance(environment, Environment):
        raise TypeError("environment must be an Environment")
    if type(frozen) is not bool:
        raise TypeError("frozen must be a bool")
    current_binary = Path(sys.executable).resolve()
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        deployment = select_deployment(environment, frozen=frozen)
        if deployment is not DeploymentKind.PORTABLE:
            raise RuntimeError("LOCALAPPDATA is unavailable")
        local_app_data = str(current_binary.parent)
    if frozen:
        application_root = current_binary.parent
        resource_root = Path(
            getattr(sys, "_MEIPASS", application_root)
        ).resolve()
    else:
        application_root = Path(__file__).resolve().parents[2]
        resource_root = Path(__file__).resolve().parent
    return plan_bootstrap(BootstrapRequest(
        environment=environment,
        known_folders=KnownFolders(local_app_data=local_app_data),
        application_root=application_root,
        resource_root=resource_root,
        current_binary=current_binary,
        frozen=frozen,
    ))


def configure_local_node(
    config: Config,
    *,
    node_id: str,
    address: str,
    role: str,
    cpu_count: int,
    monitoring_enabled: bool,
    start_minimized: bool,
) -> Config:
    """Apply the secret-free setup-wizard fields to a typed configuration."""

    from .ui.node_dialog import NodeDraft

    if not isinstance(config, Config):
        raise TypeError("config must be a Config")
    if type(monitoring_enabled) is not bool or type(start_minimized) is not bool:
        raise TypeError("setup flags must be bool values")
    node = NodeDraft(
        node_id=node_id,
        address=address,
        role=role,
        enabled=True,
        cpu_count=cpu_count,
    ).to_node()
    previous_local = config.nodes.local_node_id.casefold()
    items = []
    replaced_local = False
    for existing in config.nodes.items:
        if previous_local and existing.node_id.casefold() == previous_local:
            items.append(node)
            replaced_local = True
        else:
            items.append(existing)
    if not replaced_local:
        items.append(node)
    updated = replace(
        config,
        app=replace(config.app, start_minimized=start_minimized),
        monitoring=replace(config.monitoring, enabled=monitoring_enabled),
        nodes=NodesSection(tuple(items), node.node_id),
    )
    config_to_dict(updated)
    return updated


def _configuration_form_result(
    config: Config,
    *,
    node_id: str,
    address: str,
    role: str,
    cpu_count: str,
    monitoring_enabled: bool,
    start_minimized: bool,
) -> tuple[Config | None, str]:
    """Return a validated form result or one safe user-facing error."""

    try:
        updated = configure_local_node(
            config,
            node_id=node_id.strip(),
            address=address.strip(),
            role=role,
            cpu_count=int(cpu_count, 10),
            monitoring_enabled=monitoring_enabled,
            start_minimized=start_minimized,
        )
    except (ConfigValidationError, TypeError, ValueError) as exc:
        return None, str(exc)
    return updated, ""


def _configuration_dialog(config: Config) -> _ConfigurationChoice | None:
    """Show the bounded, secret-free local setup form."""

    import tkinter as tk

    if not isinstance(config, Config):
        raise TypeError("config must be a Config")
    current = next(
        (
            item
            for item in config.nodes.items
            if item.node_id.casefold() == config.nodes.local_node_id.casefold()
        ),
        None,
    )
    root = tk.Tk()
    root.title("Ray Cluster Manager - Local setup")
    root.resizable(False, False)
    frame = tk.Frame(root, padx=14, pady=14)
    frame.pack(fill="both", expand=True)
    tk.Label(
        frame,
        text=(
            "Configure this PC only. No password, token, or remote command "
            "setting is accepted here."
        ),
        justify="left",
        wraplength=460,
    ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
    node_id = tk.StringVar(value=current.node_id if current else "local-pc")
    address = tk.StringVar(value=current.address if current else "127.0.0.1")
    role = tk.StringVar(value=current.role if current else "worker")
    cpu_count = tk.StringVar(value=str(current.cpu_count if current else 0))
    monitoring = tk.BooleanVar(value=config.monitoring.enabled)
    minimized = tk.BooleanVar(value=config.app.start_minimized)
    rows = (
        ("Local node ID", node_id),
        ("Address or host name", address),
        ("CPU count (0 = automatic)", cpu_count),
    )
    first_entry = None
    for offset, (label, variable) in enumerate(rows, start=1):
        tk.Label(frame, text=label).grid(
            row=offset, column=0, sticky="w", padx=(0, 10), pady=3
        )
        entry = tk.Entry(frame, textvariable=variable, width=34)
        entry.grid(
            row=offset, column=1, sticky="ew", pady=3
        )
        if first_entry is None:
            first_entry = entry
    tk.Label(frame, text="Role").grid(
        row=4, column=0, sticky="w", padx=(0, 10), pady=3
    )
    tk.OptionMenu(frame, role, "worker", "head", "observer").grid(
        row=4, column=1, sticky="ew", pady=3
    )
    tk.Checkbutton(
        frame,
        text="Enable monitoring when the service is available",
        variable=monitoring,
    ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 2))
    tk.Checkbutton(
        frame, text="Start minimized", variable=minimized
    ).grid(row=6, column=0, columnspan=2, sticky="w", pady=2)
    status = tk.StringVar(value="")
    tk.Label(
        frame, textvariable=status, fg="#800000", justify="left",
        wraplength=460,
    ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
    result: list[_ConfigurationChoice] = []

    def save() -> None:
        updated, error = _configuration_form_result(
            config,
            node_id=node_id.get(),
            address=address.get(),
            role=role.get(),
            cpu_count=cpu_count.get(),
            monitoring_enabled=monitoring.get(),
            start_minimized=minimized.get(),
        )
        if updated is None:
            status.set(error)
            if first_entry is not None:
                first_entry.focus_set()
            return
        result.append(_ConfigurationChoice("save", config=updated))
        root.destroy()

    def import_v1() -> None:
        from tkinter import filedialog

        suggested = default_v1_config_path()
        options: dict[str, object] = {
            "title": "Select an RCM 1.x config.json",
            "filetypes": (("JSON configuration", "*.json"), ("All files", "*.*")),
        }
        if suggested is not None:
            options["initialdir"] = str(suggested.parent)
            options["initialfile"] = suggested.name
        selected = filedialog.askopenfilename(parent=root, **options)
        if not selected:
            return
        result.append(
            _ConfigurationChoice("import", source_path=Path(selected))
        )
        root.destroy()

    def rollback_import() -> None:
        result.append(_ConfigurationChoice("rollback"))
        root.destroy()

    buttons = tk.Frame(frame)
    buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(12, 0))
    tk.Button(
        buttons,
        text="Import RCM 1.x...",
        width=16,
        command=import_v1,
    ).pack(side="left", padx=(0, 6))
    tk.Button(
        buttons,
        text="Rollback import",
        width=14,
        command=rollback_import,
    ).pack(side="left", padx=(0, 6))
    tk.Button(buttons, text="Save", width=10, command=save).pack(
        side="left", padx=(0, 6)
    )
    tk.Button(buttons, text="Cancel", width=10, command=root.destroy).pack(
        side="left"
    )
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Return>", lambda _event: save())
    root.bind("<Escape>", lambda _event: root.destroy())
    if first_entry is not None:
        first_entry.focus_set()
    root.mainloop()
    return result[0] if result else None


def _show_configuration_message(kind: str, message: str) -> None:
    from tkinter import messagebox

    if kind == "error":
        messagebox.showerror("Ray Cluster Manager", message)
    else:
        messagebox.showinfo("Ray Cluster Manager", message)


def _confirm_v1_import(preview: V1ImportPreview) -> bool:
    from tkinter import messagebox

    projection = preview.projection
    node_lines = [
        (
            f"  {node.node_id}: {node.address}, {node.role}, "
            f"CPU {'auto' if node.cpu_count == 0 else node.cpu_count}"
        )
        for node in projection.config.nodes.items[:8]
    ]
    if len(projection.config.nodes.items) > len(node_lines):
        node_lines.append(
            f"  ... {len(projection.config.nodes.items) - len(node_lines)} more nodes"
        )

    def field_lines(items: tuple[object, ...], *, rejected: bool) -> list[str]:
        visible: list[str] = []
        for item in items[:8]:
            source_path = str(getattr(item, "source_path"))
            if rejected:
                detail = str(getattr(item, "reason"))
            else:
                detail = str(getattr(item, "target_path"))
            visible.append(f"  {source_path} -> {detail}")
        if len(items) > len(visible):
            visible.append(f"  ... {len(items) - len(visible)} more fields")
        return visible

    mapped_lines = field_lines(projection.mapped_fields, rejected=False)
    skipped_lines = field_lines(projection.skipped_fields, rejected=True)
    rejected_lines = field_lines(projection.rejected_fields, rejected=True)
    preview_details = "\n".join((
        "Supported node preview:",
        *(node_lines or ("  none",)),
        "",
        "Mapped fields:",
        *(mapped_lines or ("  none",)),
        "",
        "Skipped fields:",
        *(skipped_lines or ("  none",)),
        "",
        "Rejected authority/metadata fields:",
        *(rejected_lines or ("  none",)),
    ))
    return bool(messagebox.askyesno(
        "Import RCM 1.x settings",
        (
            "The selected source will remain byte-for-byte unchanged.\n\n"
            f"Source: {preview.source_path}\n"
            f"Schema: {projection.source_schema}\n"
            f"SHA-256: {preview.source_checksum}\n"
            f"Mapped fields: {len(projection.mapped_fields)}\n"
            f"Skipped fields: {len(projection.skipped_fields)}\n"
            f"Rejected legacy authority fields: {len(projection.rejected_fields)}\n\n"
            f"{preview_details}\n\n"
            "Secrets and credential material are never imported. Ray settings "
            "remain disabled until separately reviewed. Continue?"
        ),
    ))


def run_configuration_wizard() -> int:
    """Load, display, validate, and durably save local setup state."""

    import sys

    from .adapters.windows_desktop import WindowsSingleton

    lease = WindowsSingleton().acquire(identity_for(DeploymentKind.INSTALLED))
    if lease is None:
        return 3
    try:
        environment = Environment(
            {
                key: os.environ[key]
                for key in ("RCM_RUNTIME_MODE", "RCM_PORTABLE")
                if key in os.environ
            }
        )
        plan = host_bootstrap_plan(
            environment,
            frozen=bool(getattr(sys, "frozen", False)),
        )
        stored = initialize_runtime_config(plan)
        choice = _configuration_dialog(stored.config)
        if choice is None:
            return 0
        store = ConfigStore(Path(str(plan.paths.config_file)))
        if choice.kind == "save":
            if choice.config is not None and choice.config != stored.config:
                store.save(
                    choice.config,
                    expected_generation=stored.generation,
                )
            return 0
        if choice.kind == "rollback":
            try:
                rollback_v1_import(store)
            except V1ImportCleanupError as exc:
                _show_configuration_message(
                    "info",
                    "The previous settings were restored at generation "
                    f"{exc.stored.generation}, but the stale rollback receipt "
                    "could not be removed. No settings rollback is pending; "
                    "rerun --configure to retry receipt cleanup.",
                )
                return 5
            except Exception:
                _show_configuration_message(
                    "error",
                    "Rollback was refused because no matching import receipt "
                    "is available. Current settings were not changed.",
                )
                return 4
            _show_configuration_message(
                "info",
                "The settings from immediately before the 1.x import were restored.",
            )
            return 0
        if choice.kind != "import" or choice.source_path is None:
            raise RuntimeError("configuration dialog returned an invalid action")
        try:
            preview = prepare_v1_import(choice.source_path, store)
        except Exception:
            _show_configuration_message(
                "error",
                "Import preview was refused safely. The selected 1.x file and "
                "current 2.x settings were not changed.",
            )
            return 4
        if not _confirm_v1_import(preview):
            return 0
        try:
            result = apply_v1_import(preview, store)
        except V1ImportCleanupError as exc:
            _show_configuration_message(
                "info",
                "Import did not complete, but the previous 2.x settings were "
                f"restored at generation {exc.stored.generation}. The stale "
                "rollback receipt could not be removed; rerun --configure "
                "to retry receipt cleanup.",
            )
            return 5
        except Exception:
            _show_configuration_message(
                "error",
                "Import did not complete. The selected 1.x file was not changed; "
                "the previous 2.x settings were retained or restored.",
            )
            return 4
        if result.changed:
            _show_configuration_message(
                "info",
                "The supported 1.x settings were imported. A generation-bound "
                "rollback is available from --configure.\n\n"
                f"Recovery backup: {store.backup_path}\n"
                f"Rollback receipt: {_receipt_path(store)}",
            )
        else:
            _show_configuration_message(
                "info",
                "The selected 1.x settings already match the current 2.x settings.",
            )
        return 0
    finally:
        lease.release()


def run_internal_configuration_check() -> int:
    """Exercise packaged create/reload against a verifier-owned data root."""

    import os
    import sys

    expectation = os.environ.get("RCM_CONFIGURATION_EXPECT")
    if (
        not getattr(sys, "frozen", False)
        or os.environ.get("RCM_INTERNAL_CONFIGURATION_CHECK") != "1"
        or expectation not in {"create", "reload"}
    ):
        return 2
    environment = Environment(
        {
            key: os.environ[key]
            for key in ("RCM_RUNTIME_MODE", "RCM_PORTABLE")
            if key in os.environ
        }
    )
    plan = host_bootstrap_plan(environment, frozen=True)
    config_path = Path(str(plan.paths.config_file))
    existed = config_path.exists()
    if existed == (expectation == "create"):
        return 3
    from .foundation_check import _deny_network_and_children

    with _deny_network_and_children() as counters:
        stored = initialize_runtime_config(plan)
        first_bytes = config_path.read_bytes()
        reloaded = initialize_runtime_config(plan)
        second_bytes = config_path.read_bytes()
    if (
        any(counters.values())
        or stored.generation != 1
        or reloaded != stored
        or first_bytes != second_bytes
        or config_path.is_symlink()
        or not config_path.is_file()
        or stored.config.app.environment != plan.identity.deployment.value
    ):
        return 4
    return 0


__all__ = (
    "MAX_V1_IMPORT_RECEIPT_BYTES",
    "V1_IMPORT_RECEIPT_VERSION",
    "V1ImportConflictError",
    "V1ImportCleanupError",
    "V1ImportError",
    "V1ImportPreview",
    "V1ImportReceipt",
    "V1ImportResult",
    "apply_v1_import",
    "configure_local_node",
    "default_v1_config_path",
    "host_bootstrap_plan",
    "initialize_runtime_config",
    "prepare_v1_import",
    "rollback_v1_import",
    "run_internal_configuration_check",
    "run_configuration_wizard",
)
