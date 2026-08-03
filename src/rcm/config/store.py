"""Crash-recoverable transactional storage for typed RCM configuration.

Construction is side-effect free.  Files and locks are touched only by
``load`` and ``save``.  The filesystem and lock are injectable so every
transaction boundary can be tested without using a real user profile.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import hashlib
import os
from pathlib import Path
import time
from typing import Callable, ContextManager, Iterator, Mapping, Protocol

from .schema import (
    MAX_CONFIG_BYTES,
    Config,
    ConfigError,
    ConfigValidationError,
    canonical_config_bytes,
    canonical_json_bytes,
    config_from_dict,
    config_to_dict,
    decode_json_bytes,
    default_config,
)


STORE_VERSION = 1
MAX_RECORD_BYTES = MAX_CONFIG_BYTES + 65_536
MAX_JOURNAL_BYTES = 65_536
TRANSACTION_PHASES = (
    "backup_durable",
    "new_staged",
    "journal_prepared",
    "target_replaced",
    "journal_replaced",
    "journal_committed",
    "cleanup_complete",
)
_JOURNAL_PHASES = {"prepared", "replaced", "committed"}
_MAX_GENERATION = (1 << 63) - 1


class ConfigStoreError(ConfigError):
    """Base class for persistence failures."""


class ConfigIOError(ConfigStoreError):
    """An unclassified filesystem operation failed."""


class ConfigDiskFullError(ConfigIOError):
    """The filesystem cannot durably accept more configuration bytes."""


class ConfigReadOnlyError(ConfigIOError):
    """The configuration location is not writable."""


class ConfigLockError(ConfigStoreError):
    """The transaction lock could not be acquired."""


class ConfigConflictError(ConfigStoreError):
    """The expected generation or transaction base no longer matches."""


class ConfigCorruptError(ConfigStoreError):
    """Stored data cannot be authenticated and decoded safely."""


class ConfigGenerationError(ConfigCorruptError):
    """Stored generation metadata is invalid or exhausted."""


class Filesystem(Protocol):
    """Minimal durable-filesystem contract consumed by :class:`ConfigStore`."""

    def ensure_parent(self, path: Path) -> None: ...

    def exists(self, path: Path) -> bool: ...

    def read_bytes(self, path: Path) -> bytes: ...

    def write_bytes(self, path: Path, data: bytes) -> None: ...

    def fsync_file(self, path: Path) -> None: ...

    def replace(self, source: Path, destination: Path) -> None: ...

    def fsync_directory(self, path: Path) -> None: ...

    def unlink(self, path: Path, *, missing_ok: bool = False) -> None: ...


class Lock(Protocol):
    """Cross-writer exclusion contract."""

    def acquire(self) -> ContextManager[None]: ...


class PathFilesystem:
    """Durable backend for an explicitly supplied local :class:`Path`."""

    def ensure_parent(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

    def exists(self, path: Path) -> bool:
        return path.exists()

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def write_bytes(self, path: Path, data: bytes) -> None:
        if type(data) is not bytes:
            raise TypeError("data must be bytes")
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()

    def fsync_file(self, path: Path) -> None:
        # A writable descriptor is required by ``os.fsync`` on Windows.
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())

    def replace(self, source: Path, destination: Path) -> None:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            move_file = ctypes.windll.kernel32.MoveFileExW
            move_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                wintypes.DWORD,
            )
            move_file.restype = wintypes.BOOL
            if not move_file(
                str(source),
                str(destination),
                0x00000001 | 0x00000008,
            ):
                raise ctypes.WinError()
            return
        os.replace(source, destination)

    def fsync_directory(self, path: Path) -> None:
        if os.name == "nt":
            # Windows directory handles cannot be flushed reliably as normal
            # file handles.  ``replace`` above uses MOVEFILE_WRITE_THROUGH,
            # which supplies the metadata durability barrier at the mutation.
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def unlink(self, path: Path, *, missing_ok: bool = False) -> None:
        path.unlink(missing_ok=missing_ok)


class FileLock:
    """Small standard-library advisory file lock.

    The lock path is derived from the explicit configuration path.  Acquisition
    creates that file when necessary, but merely constructing the lock does not.
    """

    def __init__(
        self,
        path: Path,
        *,
        timeout_seconds: float = 5.0,
        retry_seconds: float = 0.05,
    ) -> None:
        if timeout_seconds < 0 or retry_seconds <= 0:
            raise ValueError("lock timing values are invalid")
        self._path = Path(path)
        self._timeout = timeout_seconds
        self._retry = retry_seconds

    @contextmanager
    def acquire(self) -> Iterator[None]:
        stream = self._path.open("a+b")
        locked = False
        deadline = time.monotonic() + self._timeout
        try:
            if os.name == "nt":
                import msvcrt

                if stream.seek(0, os.SEEK_END) == 0:
                    stream.write(b"\0")
                    stream.flush()
                    os.fsync(stream.fileno())
                while True:
                    try:
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                        locked = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("configuration lock timed out")
                        time.sleep(min(self._retry, max(0.0, deadline - time.monotonic())))
            else:
                import fcntl

                while True:
                    try:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        locked = True
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("configuration lock timed out")
                        time.sleep(min(self._retry, max(0.0, deadline - time.monotonic())))
            yield
        finally:
            if locked:
                if os.name == "nt":
                    import msvcrt

                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()


@dataclass(frozen=True, slots=True)
class StoredConfig:
    config: Config
    generation: int
    checksum: str
    transaction_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class _Record:
    stored: StoredConfig
    raw: bytes
    raw_checksum: str


@dataclass(frozen=True, slots=True)
class _Journal:
    phase: str
    old_generation: int
    old_record_checksum: str | None
    new_generation: int
    new_record_checksum: str

    def with_phase(self, phase: str) -> _Journal:
        return _Journal(
            phase=phase,
            old_generation=self.old_generation,
            old_record_checksum=self.old_record_checksum,
            new_generation=self.new_generation,
            new_record_checksum=self.new_record_checksum,
        )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_checksum(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _record_bytes(
    config: Config,
    generation: int,
    transaction_id: str | None = None,
) -> bytes:
    if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
        raise ConfigGenerationError("generation is outside the supported range")
    if transaction_id is not None and not _is_checksum(transaction_id):
        raise ValueError("transaction_id must be a lowercase SHA-256")
    payload = canonical_config_bytes(config)
    record: dict[str, object] = {
        "store_version": STORE_VERSION,
        "generation": generation,
        "checksum": _sha256(payload),
        "config": config_to_dict(config),
    }
    if transaction_id is not None:
        record["transaction_id"] = transaction_id
    return canonical_json_bytes(record)


def _decode_record(raw: bytes, *, source: str) -> _Record:
    try:
        value = decode_json_bytes(raw, max_bytes=MAX_RECORD_BYTES)
        if not isinstance(value, Mapping):
            raise ConfigValidationError("", "record must be an object")
        required = {"store_version", "generation", "checksum", "config"}
        valid_key_sets = {
            frozenset(required),
            frozenset(required | {"transaction_id"}),
        }
        if set(value) not in valid_key_sets:
            raise ConfigValidationError("", "record keys do not match the storage format")
        version = value["store_version"]
        generation = value["generation"]
        checksum = value["checksum"]
        transaction_id = value.get("transaction_id")
        if type(version) is not int or version != STORE_VERSION:
            raise ConfigValidationError("store_version", "unsupported storage version")
        if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
            raise ConfigGenerationError("stored generation is invalid")
        if not _is_checksum(checksum):
            raise ConfigValidationError("checksum", "must be a lowercase SHA-256")
        if transaction_id is not None and not _is_checksum(transaction_id):
            raise ConfigValidationError(
                "transaction_id",
                "must be a lowercase SHA-256",
            )
        config = config_from_dict(value["config"])
        actual = _sha256(canonical_config_bytes(config))
        if actual != checksum:
            raise ConfigValidationError("checksum", "configuration checksum mismatch")
    except ConfigGenerationError:
        raise
    except ConfigError as exc:
        raise ConfigCorruptError(f"{source} is corrupt: {exc}") from exc
    return _Record(
        stored=StoredConfig(
            config=config,
            generation=generation,
            checksum=checksum,
            transaction_id=transaction_id,
        ),
        raw=raw,
        raw_checksum=_sha256(raw),
    )


def _journal_bytes(journal: _Journal) -> bytes:
    return canonical_json_bytes(
        {
            "journal_version": 1,
            "phase": journal.phase,
            "old_generation": journal.old_generation,
            "old_record_checksum": journal.old_record_checksum,
            "new_generation": journal.new_generation,
            "new_record_checksum": journal.new_record_checksum,
        }
    )


def _decode_journal(raw: bytes) -> _Journal:
    try:
        value = decode_json_bytes(raw, max_bytes=MAX_JOURNAL_BYTES)
        if not isinstance(value, Mapping):
            raise ConfigValidationError("", "journal must be an object")
        expected = {
            "journal_version",
            "phase",
            "old_generation",
            "old_record_checksum",
            "new_generation",
            "new_record_checksum",
        }
        if set(value) != expected:
            raise ConfigValidationError("", "journal keys do not match the storage format")
        if type(value["journal_version"]) is not int or value["journal_version"] != 1:
            raise ConfigValidationError("journal_version", "unsupported journal version")
        phase = value["phase"]
        old_generation = value["old_generation"]
        old_checksum = value["old_record_checksum"]
        new_generation = value["new_generation"]
        new_checksum = value["new_record_checksum"]
        if not isinstance(phase, str) or phase not in _JOURNAL_PHASES:
            raise ConfigValidationError("phase", "unknown journal phase")
        if type(old_generation) is not int or not 0 <= old_generation <= _MAX_GENERATION:
            raise ConfigValidationError("old_generation", "invalid generation")
        if old_checksum is not None and not _is_checksum(old_checksum):
            raise ConfigValidationError("old_record_checksum", "invalid checksum")
        if (old_generation == 0) != (old_checksum is None):
            raise ConfigValidationError(
                "old_record_checksum",
                "must be null exactly when old_generation is zero",
            )
        if type(new_generation) is not int or not 1 <= new_generation <= _MAX_GENERATION:
            raise ConfigValidationError("new_generation", "invalid generation")
        if new_generation != old_generation + 1:
            raise ConfigValidationError("new_generation", "must follow old_generation")
        if not _is_checksum(new_checksum):
            raise ConfigValidationError("new_record_checksum", "invalid checksum")
    except ConfigError as exc:
        raise ConfigCorruptError(f"transaction journal is corrupt: {exc}") from exc
    return _Journal(
        phase=phase,
        old_generation=old_generation,
        old_record_checksum=old_checksum,
        new_generation=new_generation,
        new_record_checksum=new_checksum,
    )


def _map_os_error(exc: OSError) -> ConfigIOError:
    if exc.errno in {errno.ENOSPC, getattr(errno, "EDQUOT", -1)}:
        return ConfigDiskFullError("configuration storage is full")
    if exc.errno in {errno.EACCES, errno.EPERM, getattr(errno, "EROFS", -1)}:
        return ConfigReadOnlyError("configuration storage is read-only or inaccessible")
    return ConfigIOError(f"configuration filesystem operation failed: {exc}")


class ConfigStore:
    """Transactional typed configuration store."""

    def __init__(
        self,
        path: Path,
        *,
        filesystem: Filesystem | None = None,
        lock: Lock | None = None,
        phase_hook: Callable[[str], None] | None = None,
    ) -> None:
        path = Path(path)
        if not path.name:
            raise ValueError("configuration path must name a file")
        self.path = path
        self.backup_path = path.with_name(path.name + ".bak")
        self.backup_temp_path = path.with_name(path.name + ".bak.tmp")
        self.temp_path = path.with_name(path.name + ".tmp")
        self.journal_path = path.with_name(path.name + ".journal")
        self.journal_temp_path = path.with_name(path.name + ".journal.tmp")
        self.lock_path = path.with_name(path.name + ".lock")
        if filesystem is not None and lock is None:
            raise ValueError("an injected filesystem requires an injected lock")
        self._fs = filesystem if filesystem is not None else PathFilesystem()
        self._lock = lock if lock is not None else FileLock(self.lock_path)
        self._phase_hook = phase_hook

    def _checkpoint(self, phase: str) -> None:
        if self._phase_hook is not None:
            self._phase_hook(phase)

    def _exists(self, path: Path) -> bool:
        return self._fs.exists(path)

    def _read(self, path: Path) -> bytes:
        return self._fs.read_bytes(path)

    def _unlink(self, path: Path) -> None:
        self._fs.unlink(path, missing_ok=True)

    def _write_synced(self, path: Path, raw: bytes) -> None:
        self._fs.write_bytes(path, raw)
        self._fs.fsync_file(path)

    def _replace_synced(self, source: Path, destination: Path) -> None:
        self._fs.replace(source, destination)
        self._fs.fsync_directory(destination.parent)

    def _write_journal(self, journal: _Journal) -> None:
        self._write_synced(self.journal_temp_path, _journal_bytes(journal))
        self._replace_synced(self.journal_temp_path, self.journal_path)

    def _read_record_if_present(self, path: Path, *, source: str) -> _Record | None:
        if not self._exists(path):
            return None
        return _decode_record(self._read(path), source=source)

    def _clean_transaction_residue(self) -> None:
        self._unlink(self.temp_path)
        self._unlink(self.backup_temp_path)
        self._unlink(self.journal_temp_path)
        self._unlink(self.journal_path)
        self._fs.fsync_directory(self.path.parent)

    def _recover_without_journal(self) -> None:
        changed = False
        for path in (self.temp_path, self.backup_temp_path, self.journal_temp_path):
            if self._exists(path):
                self._unlink(path)
                changed = True
        if changed:
            self._fs.fsync_directory(self.path.parent)

    def _recover(self) -> None:
        if not self._exists(self.journal_path):
            self._recover_without_journal()
            return

        journal = _decode_journal(self._read(self.journal_path))
        target = self._read_record_if_present(self.path, source="configuration")
        staged = self._read_record_if_present(self.temp_path, source="staged configuration")
        backup = self._read_record_if_present(self.backup_path, source="configuration backup")

        target_is_new = (
            target is not None
            and target.raw_checksum == journal.new_record_checksum
            and target.stored.generation == journal.new_generation
        )
        target_is_old = (
            target is not None
            and target.raw_checksum == journal.old_record_checksum
            and target.stored.generation == journal.old_generation
        )
        staged_is_new = (
            staged is not None
            and staged.raw_checksum == journal.new_record_checksum
            and staged.stored.generation == journal.new_generation
        )
        backup_is_old = (
            backup is not None
            and backup.raw_checksum == journal.old_record_checksum
            and backup.stored.generation == journal.old_generation
        )

        if target_is_new:
            self._clean_transaction_residue()
            return

        if target_is_old or (target is None and journal.old_record_checksum is None):
            if staged_is_new:
                self._replace_synced(self.temp_path, self.path)
            self._clean_transaction_residue()
            return

        if target is None:
            if staged_is_new:
                self._replace_synced(self.temp_path, self.path)
                self._clean_transaction_residue()
                return
            if backup_is_old:
                self._write_synced(self.backup_temp_path, backup.raw)
                self._replace_synced(self.backup_temp_path, self.path)
                self._clean_transaction_residue()
                return
            raise ConfigCorruptError("interrupted transaction has no authentic old or new record")

        # A different valid target indicates an uncoordinated writer.  Preserve
        # that writer's valid record and remove only this transaction's residue.
        self._clean_transaction_residue()
        raise ConfigConflictError("configuration changed outside the transaction lock")

    def _under_lock(self, operation: Callable[[], StoredConfig]) -> StoredConfig:
        try:
            context = self._lock.acquire()
            with context:
                return operation()
        except ConfigError:
            raise
        except TimeoutError as exc:
            raise ConfigLockError("configuration lock timed out") from exc
        except OSError as exc:
            raise _map_os_error(exc) from exc

    def load(self, *, require_existing: bool = False) -> StoredConfig:
        """Recover an interrupted transaction and load an authenticated record."""

        def operation() -> StoredConfig:
            self._recover()
            record = self._read_record_if_present(self.path, source="configuration")
            if record is None:
                if require_existing:
                    raise ConfigCorruptError("configuration does not exist")
                config = default_config()
                return StoredConfig(config=config, generation=0, checksum=_sha256(canonical_config_bytes(config)))
            return record.stored

        try:
            self._fs.ensure_parent(self.path)
        except OSError as exc:
            raise _map_os_error(exc) from exc
        return self._under_lock(operation)

    @staticmethod
    def _expected_generation(value: object, *, label: str) -> int:
        if type(value) is not int or not 1 <= value <= _MAX_GENERATION:
            raise ValueError(f"{label} is outside the supported range")
        return value

    def _commit_locked(
        self,
        config: Config,
        old: _Record | None,
        transaction_id: str | None,
    ) -> StoredConfig:
        old_generation = old.stored.generation if old is not None else 0
        if old_generation >= _MAX_GENERATION:
            raise ConfigGenerationError("configuration generation is exhausted")

        new_generation = old_generation + 1
        new_raw = _record_bytes(config, new_generation, transaction_id)
        new_checksum = _sha256(new_raw)
        old_checksum = old.raw_checksum if old is not None else None

        if old is not None:
            self._write_synced(self.backup_temp_path, old.raw)
            self._replace_synced(self.backup_temp_path, self.backup_path)
        elif self._exists(self.backup_path):
            self._unlink(self.backup_path)
            self._fs.fsync_directory(self.path.parent)
        self._checkpoint("backup_durable")

        self._write_synced(self.temp_path, new_raw)
        self._checkpoint("new_staged")

        journal = _Journal(
            phase="prepared",
            old_generation=old_generation,
            old_record_checksum=old_checksum,
            new_generation=new_generation,
            new_record_checksum=new_checksum,
        )
        self._write_journal(journal)
        self._checkpoint("journal_prepared")

        # Detect writers that ignore the shared lock before the commit point.
        current_raw = self._read(self.path) if self._exists(self.path) else None
        if current_raw != (old.raw if old is not None else None):
            self._clean_transaction_residue()
            raise ConfigConflictError("configuration changed during transaction")

        self._replace_synced(self.temp_path, self.path)
        self._checkpoint("target_replaced")

        self._write_journal(journal.with_phase("replaced"))
        self._checkpoint("journal_replaced")
        self._write_journal(journal.with_phase("committed"))
        self._checkpoint("journal_committed")

        self._clean_transaction_residue()
        self._checkpoint("cleanup_complete")
        return StoredConfig(
            config=config,
            generation=new_generation,
            checksum=_sha256(canonical_config_bytes(config)),
            transaction_id=transaction_id,
        )

    def _commit_rollback_locked(
        self,
        config: Config,
        current: _Record,
        backup: _Record,
    ) -> StoredConfig:
        """Commit a rollback without overwriting its recovery source first."""

        if current.stored.generation >= _MAX_GENERATION:
            raise ConfigGenerationError("configuration generation is exhausted")
        new_generation = current.stored.generation + 1
        new_raw = _record_bytes(config, new_generation)
        journal = _Journal(
            phase="prepared",
            old_generation=current.stored.generation,
            old_record_checksum=current.raw_checksum,
            new_generation=new_generation,
            new_record_checksum=_sha256(new_raw),
        )

        # The authenticated pre-import backup remains untouched until the new
        # current record is durable.  An interruption therefore cannot destroy
        # the only recovery source while the imported record is still current.
        self._checkpoint("backup_durable")
        self._write_synced(self.temp_path, new_raw)
        self._checkpoint("new_staged")
        self._write_journal(journal)
        self._checkpoint("journal_prepared")

        current_raw = self._read(self.path) if self._exists(self.path) else None
        backup_raw = (
            self._read(self.backup_path)
            if self._exists(self.backup_path)
            else None
        )
        if current_raw != current.raw or backup_raw != backup.raw:
            self._clean_transaction_residue()
            raise ConfigConflictError(
                "configuration or rollback backup changed during transaction"
            )

        self._replace_synced(self.temp_path, self.path)
        self._checkpoint("target_replaced")
        self._write_journal(journal.with_phase("replaced"))
        self._checkpoint("journal_replaced")
        self._write_journal(journal.with_phase("committed"))
        self._checkpoint("journal_committed")
        self._clean_transaction_residue()
        self._checkpoint("cleanup_complete")
        return StoredConfig(
            config=config,
            generation=new_generation,
            checksum=_sha256(canonical_config_bytes(config)),
        )

    def save(
        self,
        config: Config,
        *,
        expected_generation: int | None = None,
        transaction_id: str | None = None,
    ) -> StoredConfig:
        """Durably replace the configuration with optimistic conflict checking."""

        # Validate before acquiring a filesystem lock.
        canonical_config_bytes(config)
        if expected_generation is not None and (
            type(expected_generation) is not int
            or not 0 <= expected_generation <= _MAX_GENERATION
        ):
            raise ValueError("expected_generation is outside the supported range")
        if transaction_id is not None and not _is_checksum(transaction_id):
            raise ValueError("transaction_id must be a lowercase SHA-256")

        def operation() -> StoredConfig:
            self._recover()
            old = self._read_record_if_present(self.path, source="configuration")
            old_generation = old.stored.generation if old is not None else 0
            if expected_generation is not None and expected_generation != old_generation:
                raise ConfigConflictError(
                    f"expected generation {expected_generation}, found {old_generation}"
                )
            return self._commit_locked(config, old, transaction_id)

        try:
            self._fs.ensure_parent(self.path)
        except OSError as exc:
            raise _map_os_error(exc) from exc
        return self._under_lock(operation)

    def rollback_previous(
        self,
        *,
        expected_current_generation: int,
        expected_backup_generation: int,
        expected_backup_checksum: str,
        expected_current_transaction_id: str | None = None,
    ) -> StoredConfig:
        """Restore the authenticated immediate backup as a new generation.

        The caller must bind the request to both the current generation and a
        previously observed backup receipt.  No path or raw record is accepted,
        the rollback never moves the backup record directly into place, and the
        recovery source is not overwritten before the restored current record
        is durable.
        """

        current_generation = self._expected_generation(
            expected_current_generation,
            label="expected_current_generation",
        )
        backup_generation = self._expected_generation(
            expected_backup_generation,
            label="expected_backup_generation",
        )
        if not _is_checksum(expected_backup_checksum):
            raise ValueError("expected_backup_checksum must be a lowercase SHA-256")
        if (
            expected_current_transaction_id is not None
            and not _is_checksum(expected_current_transaction_id)
        ):
            raise ValueError(
                "expected_current_transaction_id must be a lowercase SHA-256"
            )

        def operation() -> StoredConfig:
            self._recover()
            current = self._read_record_if_present(
                self.path,
                source="configuration",
            )
            found_generation = (
                current.stored.generation if current is not None else 0
            )
            if found_generation != current_generation:
                raise ConfigConflictError(
                    f"expected generation {current_generation}, "
                    f"found {found_generation}"
                )
            if current.stored.transaction_id != expected_current_transaction_id:
                raise ConfigConflictError(
                    "configuration transaction does not match the expected receipt"
                )
            backup = self._read_record_if_present(
                self.backup_path,
                source="configuration backup",
            )
            if backup is None:
                raise ConfigCorruptError("configuration backup does not exist")
            if backup.stored.generation != current_generation - 1:
                raise ConfigConflictError(
                    "configuration backup is not the immediately previous generation"
                )
            if (
                backup.stored.generation != backup_generation
                or backup.stored.checksum != expected_backup_checksum
            ):
                raise ConfigConflictError(
                    "configuration backup does not match the expected receipt"
                )
            return self._commit_rollback_locked(
                backup.stored.config,
                current,
                backup,
            )

        try:
            self._fs.ensure_parent(self.path)
        except OSError as exc:
            raise _map_os_error(exc) from exc
        return self._under_lock(operation)


__all__ = [
    "MAX_JOURNAL_BYTES",
    "MAX_RECORD_BYTES",
    "STORE_VERSION",
    "TRANSACTION_PHASES",
    "ConfigConflictError",
    "ConfigCorruptError",
    "ConfigDiskFullError",
    "ConfigGenerationError",
    "ConfigIOError",
    "ConfigLockError",
    "ConfigReadOnlyError",
    "ConfigStore",
    "ConfigStoreError",
    "FileLock",
    "Filesystem",
    "Lock",
    "PathFilesystem",
    "StoredConfig",
]
