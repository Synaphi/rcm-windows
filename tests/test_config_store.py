from __future__ import annotations

from contextlib import contextmanager
import errno
import json
from pathlib import Path
import tempfile
import unittest

from rcm.config.schema import AppSection, Config, default_config
from rcm.config.store import (
    TRANSACTION_PHASES,
    ConfigConflictError,
    ConfigCorruptError,
    ConfigDiskFullError,
    ConfigIOError,
    ConfigLockError,
    ConfigReadOnlyError,
    ConfigStore,
)


class _MemoryFilesystem:
    MUTATIONS = {"write_bytes", "fsync_file", "replace", "fsync_directory", "unlink"}

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.events: list[tuple[str, str]] = []
        self.mutation_count = 0
        self.fail_mutation: int | None = None
        self.fail_operation: tuple[str, int] | None = None

    @staticmethod
    def _key(path: Path) -> str:
        return str(path)

    def _event(self, operation: str, detail: str) -> None:
        self.events.append((operation, detail))
        if operation in self.MUTATIONS:
            self.mutation_count += 1
            if self.fail_mutation == self.mutation_count:
                self.fail_mutation = None
                raise OSError(errno.EIO, "synthetic mutation failure")
        if self.fail_operation is not None and self.fail_operation[0] == operation:
            _, error_number = self.fail_operation
            self.fail_operation = None
            raise OSError(error_number, "synthetic operation failure")

    def ensure_parent(self, path: Path) -> None:
        self._event("ensure_parent", self._key(path.parent))

    def exists(self, path: Path) -> bool:
        self._event("exists", self._key(path))
        return self._key(path) in self.files

    def read_bytes(self, path: Path) -> bytes:
        key = self._key(path)
        self._event("read_bytes", key)
        try:
            return self.files[key]
        except KeyError as exc:
            raise FileNotFoundError(key) from exc

    def write_bytes(self, path: Path, data: bytes) -> None:
        key = self._key(path)
        self._event("write_bytes", key)
        if key in self.files:
            raise FileExistsError(key)
        self.files[key] = bytes(data)

    def fsync_file(self, path: Path) -> None:
        key = self._key(path)
        self._event("fsync_file", key)
        if key not in self.files:
            raise FileNotFoundError(key)

    def replace(self, source: Path, destination: Path) -> None:
        source_key = self._key(source)
        destination_key = self._key(destination)
        self._event("replace", f"{source_key}->{destination_key}")
        if source_key not in self.files:
            raise FileNotFoundError(source_key)
        self.files[destination_key] = self.files.pop(source_key)

    def fsync_directory(self, path: Path) -> None:
        self._event("fsync_directory", self._key(path))

    def unlink(self, path: Path, *, missing_ok: bool = False) -> None:
        key = self._key(path)
        self._event("unlink", key)
        if key not in self.files:
            if missing_ok:
                return
            raise FileNotFoundError(key)
        del self.files[key]

    def transaction_residue(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                path
                for path in self.files
                if path.endswith(".tmp") or path.endswith(".journal")
            )
        )


class _Lock:
    def __init__(self) -> None:
        self.depth = 0
        self.entries = 0

    @contextmanager
    def acquire(self):
        if self.depth:
            raise TimeoutError("synthetic concurrent lock")
        self.depth += 1
        self.entries += 1
        try:
            yield
        finally:
            self.depth -= 1


class _Unlocked:
    @contextmanager
    def acquire(self):
        yield


class _TimeoutLock:
    @contextmanager
    def acquire(self):
        raise TimeoutError("synthetic timeout")
        yield  # pragma: no cover


class _Crash(BaseException):
    pass


def _named(name: str) -> Config:
    return Config(app=AppSection(name=name))


class ConfigStoreTests(unittest.TestCase):
    def make_store(
        self,
        filesystem: _MemoryFilesystem | None = None,
        *,
        phase_hook=None,
        lock=None,
    ) -> tuple[ConfigStore, _MemoryFilesystem]:
        filesystem = filesystem or _MemoryFilesystem()
        store = ConfigStore(
            Path("synthetic-state/config.json"),
            filesystem=filesystem,
            lock=lock or _Lock(),
            phase_hook=phase_hook,
        )
        return store, filesystem

    def test_construction_has_no_filesystem_or_lock_side_effect(self) -> None:
        filesystem = _MemoryFilesystem()
        lock = _Lock()

        ConfigStore(
            Path("synthetic-state/config.json"),
            filesystem=filesystem,
            lock=lock,
        )

        self.assertEqual([], filesystem.events)
        self.assertEqual(0, lock.entries)
        self.assertEqual({}, filesystem.files)

    def test_missing_load_returns_unpersisted_generation_zero_defaults(self) -> None:
        store, filesystem = self.make_store()
        loaded = store.load()

        self.assertEqual(default_config(), loaded.config)
        self.assertEqual(0, loaded.generation)
        self.assertEqual(64, len(loaded.checksum))
        self.assertFalse(filesystem.files)
        with self.assertRaises(ConfigCorruptError):
            store.load(require_existing=True)

    def test_save_load_generation_checksum_backup_and_canonical_record(self) -> None:
        store, filesystem = self.make_store()

        first = store.save(_named("First"), expected_generation=0)
        second = store.save(_named("Second"), expected_generation=1)
        loaded = store.load()

        self.assertEqual(1, first.generation)
        self.assertEqual(2, second.generation)
        self.assertEqual(second, loaded)
        record = json.loads(filesystem.files[str(store.path)])
        backup = json.loads(filesystem.files[str(store.backup_path)])
        self.assertEqual(2, record["generation"])
        self.assertEqual(1, backup["generation"])
        self.assertEqual(second.checksum, record["checksum"])
        self.assertEqual(
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(),
            filesystem.files[str(store.path)],
        )
        self.assertEqual((), filesystem.transaction_residue())

    def test_transaction_identity_authenticates_rollback_ownership(self) -> None:
        store, filesystem = self.make_store()
        previous = store.save(_named("Previous"), expected_generation=0)
        transaction_id = "a" * 64
        imported = store.save(
            _named("Imported"),
            expected_generation=1,
            transaction_id=transaction_id,
        )

        self.assertEqual(transaction_id, imported.transaction_id)
        self.assertEqual(transaction_id, store.load().transaction_id)
        current_record = json.loads(filesystem.files[str(store.path)])
        self.assertEqual(transaction_id, current_record["transaction_id"])
        before = dict(filesystem.files)
        with self.assertRaises(ConfigConflictError):
            store.rollback_previous(
                expected_current_generation=imported.generation,
                expected_backup_generation=previous.generation,
                expected_backup_checksum=previous.checksum,
                expected_current_transaction_id="b" * 64,
            )
        self.assertEqual(before, filesystem.files)

        restored = store.rollback_previous(
            expected_current_generation=imported.generation,
            expected_backup_generation=previous.generation,
            expected_backup_checksum=previous.checksum,
            expected_current_transaction_id=transaction_id,
        )
        self.assertIsNone(restored.transaction_id)
        self.assertEqual((3, "Previous"), (
            restored.generation,
            restored.config.app.name,
        ))

    def test_generation_conflict_does_not_write(self) -> None:
        store, filesystem = self.make_store()
        store.save(_named("Old"), expected_generation=0)
        before = dict(filesystem.files)

        with self.assertRaises(ConfigConflictError):
            store.save(_named("New"), expected_generation=0)

        self.assertEqual(before, filesystem.files)
        self.assertEqual("Old", store.load().config.app.name)

    def test_authenticated_previous_rollback_commits_a_new_generation(self) -> None:
        store, filesystem = self.make_store()
        previous = store.save(_named("Previous"), expected_generation=0)
        current = store.save(_named("Imported"), expected_generation=1)

        rolled_back = store.rollback_previous(
            expected_current_generation=current.generation,
            expected_backup_generation=previous.generation,
            expected_backup_checksum=previous.checksum,
        )

        self.assertEqual((3, "Previous"), (
            rolled_back.generation,
            rolled_back.config.app.name,
        ))
        self.assertEqual(previous.checksum, rolled_back.checksum)
        self.assertEqual(rolled_back, store.load(require_existing=True))
        target = json.loads(filesystem.files[str(store.path)])
        backup = json.loads(filesystem.files[str(store.backup_path)])
        self.assertEqual((3, "Previous"), (
            target["generation"],
            target["config"]["app"]["name"],
        ))
        self.assertEqual((1, "Previous"), (
            backup["generation"],
            backup["config"]["app"]["name"],
        ))
        self.assertEqual(
            {str(store.path), str(store.backup_path)},
            set(filesystem.files),
        )
        self.assertEqual((), filesystem.transaction_residue())

    def test_rollback_receipt_validation_happens_before_filesystem_access(self) -> None:
        invalid = (
            {
                "expected_current_generation": 0,
                "expected_backup_generation": 1,
                "expected_backup_checksum": "0" * 64,
            },
            {
                "expected_current_generation": 2,
                "expected_backup_generation": False,
                "expected_backup_checksum": "0" * 64,
            },
            {
                "expected_current_generation": 2,
                "expected_backup_generation": 1,
                "expected_backup_checksum": "A" * 64,
            },
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                store, filesystem = self.make_store()
                with self.assertRaises(ValueError):
                    store.rollback_previous(**arguments)
                self.assertEqual([], filesystem.events)
                self.assertEqual({}, filesystem.files)

    def test_rollback_absent_corrupt_and_mismatched_backup_do_not_write(self) -> None:
        cases = (
            ("generation_conflict", ConfigConflictError),
            ("absent", ConfigCorruptError),
            ("corrupt", ConfigCorruptError),
            ("generation_receipt", ConfigConflictError),
            ("checksum_receipt", ConfigConflictError),
            ("not_previous", ConfigConflictError),
        )
        for case, error_type in cases:
            with self.subTest(case=case):
                store, filesystem = self.make_store()
                previous = store.save(_named("Previous"), expected_generation=0)
                current = store.save(_named("Imported"), expected_generation=1)
                arguments = {
                    "expected_current_generation": current.generation,
                    "expected_backup_generation": previous.generation,
                    "expected_backup_checksum": previous.checksum,
                }
                if case == "generation_conflict":
                    arguments["expected_current_generation"] = 1
                elif case == "absent":
                    del filesystem.files[str(store.backup_path)]
                elif case == "corrupt":
                    filesystem.files[str(store.backup_path)] = b"not json"
                elif case == "generation_receipt":
                    arguments["expected_backup_generation"] = 2
                elif case == "checksum_receipt":
                    arguments["expected_backup_checksum"] = "0" * 64
                elif case == "not_previous":
                    filesystem.files[str(store.backup_path)] = (
                        filesystem.files[str(store.path)]
                    )
                    arguments["expected_backup_generation"] = 2
                    arguments["expected_backup_checksum"] = current.checksum
                before = dict(filesystem.files)
                filesystem.mutation_count = 0

                with self.assertRaises(error_type):
                    store.rollback_previous(**arguments)

                self.assertEqual(0, filesystem.mutation_count)
                self.assertEqual(before, filesystem.files)
                self.assertEqual((), filesystem.transaction_residue())

    def test_each_transaction_phase_recovers_to_exactly_old_or_new(self) -> None:
        self.assertEqual(
            (
                "backup_durable",
                "new_staged",
                "journal_prepared",
                "target_replaced",
                "journal_replaced",
                "journal_committed",
                "cleanup_complete",
            ),
            TRANSACTION_PHASES,
        )
        for phase in TRANSACTION_PHASES:
            with self.subTest(phase=phase):
                filesystem = _MemoryFilesystem()
                initial, _ = self.make_store(filesystem)
                initial.save(_named("Old"), expected_generation=0)

                def crash(current: str, *, selected: str = phase) -> None:
                    if current == selected:
                        raise _Crash(selected)

                crashing, _ = self.make_store(filesystem, phase_hook=crash)
                with self.assertRaises(_Crash):
                    crashing.save(_named("New"), expected_generation=1)

                recovered, _ = self.make_store(filesystem)
                loaded = recovered.load()
                self.assertIn(loaded.config.app.name, {"Old", "New"})
                self.assertIn(loaded.generation, {1, 2})
                self.assertEqual(
                    loaded.generation == 2,
                    loaded.config.app.name == "New",
                )
                self.assertEqual((), filesystem.transaction_residue())

    def test_every_filesystem_mutation_failure_preserves_old_or_new_and_cleans(self) -> None:
        baseline_fs = _MemoryFilesystem()
        baseline, _ = self.make_store(baseline_fs)
        baseline.save(_named("Old"), expected_generation=0)
        baseline_fs.mutation_count = 0
        baseline.save(_named("New"), expected_generation=1)
        mutation_total = baseline_fs.mutation_count
        self.assertGreater(mutation_total, 10)

        for fail_at in range(1, mutation_total + 1):
            with self.subTest(fail_at=fail_at):
                filesystem = _MemoryFilesystem()
                store, _ = self.make_store(filesystem)
                store.save(_named("Old"), expected_generation=0)
                filesystem.mutation_count = 0
                filesystem.fail_mutation = fail_at
                try:
                    store.save(_named("New"), expected_generation=1)
                except ConfigIOError:
                    pass
                filesystem.fail_mutation = None

                recovered, _ = self.make_store(filesystem)
                loaded = recovered.load()
                self.assertIn(
                    (loaded.generation, loaded.config.app.name),
                    {(1, "Old"), (2, "New")},
                )
                self.assertEqual((), filesystem.transaction_residue())

    def test_every_rollback_mutation_failure_preserves_old_or_new_and_cleans(
        self,
    ) -> None:
        baseline_fs = _MemoryFilesystem()
        baseline, _ = self.make_store(baseline_fs)
        previous = baseline.save(_named("Previous"), expected_generation=0)
        current = baseline.save(_named("Imported"), expected_generation=1)
        baseline_fs.mutation_count = 0
        baseline.rollback_previous(
            expected_current_generation=current.generation,
            expected_backup_generation=previous.generation,
            expected_backup_checksum=previous.checksum,
        )
        mutation_total = baseline_fs.mutation_count
        self.assertGreater(mutation_total, 10)

        for fail_at in range(1, mutation_total + 1):
            with self.subTest(fail_at=fail_at):
                filesystem = _MemoryFilesystem()
                store, _ = self.make_store(filesystem)
                previous = store.save(
                    _named("Previous"),
                    expected_generation=0,
                )
                current = store.save(
                    _named("Imported"),
                    expected_generation=1,
                )
                filesystem.mutation_count = 0
                filesystem.fail_mutation = fail_at
                try:
                    store.rollback_previous(
                        expected_current_generation=current.generation,
                        expected_backup_generation=previous.generation,
                        expected_backup_checksum=previous.checksum,
                    )
                except ConfigIOError:
                    pass
                filesystem.fail_mutation = None

                recovered, _ = self.make_store(filesystem)
                loaded = recovered.load(require_existing=True)
                self.assertIn(
                    (loaded.generation, loaded.config.app.name),
                    {(2, "Imported"), (3, "Previous")},
                )
                backup_store = ConfigStore(
                    recovered.backup_path,
                    filesystem=filesystem,
                    lock=_Lock(),
                )
                backup = backup_store.load(require_existing=True)
                self.assertEqual(
                    (1, "Previous"),
                    (backup.generation, backup.config.app.name),
                )
                self.assertEqual((), filesystem.transaction_residue())

    def test_disk_full_and_readonly_are_typed(self) -> None:
        cases = (
            (errno.ENOSPC, ConfigDiskFullError),
            (errno.EROFS, ConfigReadOnlyError),
            (errno.EACCES, ConfigReadOnlyError),
        )
        for error_number, expected in cases:
            with self.subTest(error_number=error_number):
                store, filesystem = self.make_store()
                filesystem.fail_operation = ("write_bytes", error_number)
                with self.assertRaises(expected):
                    store.save(_named("New"), expected_generation=0)

    def test_lock_timeout_is_typed_and_does_not_write(self) -> None:
        filesystem = _MemoryFilesystem()
        store, _ = self.make_store(filesystem, lock=_TimeoutLock())

        with self.assertRaises(ConfigLockError):
            store.save(_named("New"), expected_generation=0)

        self.assertEqual({}, filesystem.files)

    def test_corrupt_target_duplicate_json_and_checksum_fail_closed(self) -> None:
        corruptions = (
            b"not json",
            b'{"generation":1,"generation":2}',
            b'{"store_version":1,"generation":1,"checksum":"'
            + (b"0" * 64)
            + b'","config":{}}',
        )
        for raw in corruptions:
            with self.subTest(raw=raw[:20]):
                store, filesystem = self.make_store()
                filesystem.files[str(store.path)] = raw
                with self.assertRaises(ConfigCorruptError):
                    store.load()

    def test_corrupt_journal_fails_closed_without_guessing(self) -> None:
        store, filesystem = self.make_store()
        store.save(_named("Old"), expected_generation=0)
        filesystem.files[str(store.journal_path)] = b'{"phase":"prepared","phase":"committed"}'
        before = dict(filesystem.files)

        with self.assertRaises(ConfigCorruptError):
            store.load()

        self.assertEqual(before, filesystem.files)

    def test_uncoordinated_writer_is_detected_before_replace(self) -> None:
        filesystem = _MemoryFilesystem()
        initial, _ = self.make_store(filesystem, lock=_Unlocked())
        initial.save(_named("Old"), expected_generation=0)

        def external_write(phase: str) -> None:
            if phase != "journal_prepared":
                return
            external = ConfigStore(
                Path("synthetic-state/config.json"),
                filesystem=filesystem,
                lock=_Unlocked(),
            )
            current = external.load()
            external.save(_named("External"), expected_generation=current.generation)

        writer = ConfigStore(
            Path("synthetic-state/config.json"),
            filesystem=filesystem,
            lock=_Unlocked(),
            phase_hook=external_write,
        )
        with self.assertRaises(ConfigConflictError):
            writer.save(_named("Our write"), expected_generation=1)

        loaded = initial.load()
        # The external writer first deterministically recovers the prepared
        # generation 2 transaction, then commits its own generation 3.
        self.assertEqual((3, "External"), (loaded.generation, loaded.config.app.name))
        self.assertEqual((), filesystem.transaction_residue())

    def test_real_path_backend_is_atomic_and_leaves_no_transaction_residue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "config.json"
            store = ConfigStore(path)

            first = store.save(_named("First"), expected_generation=0)
            second = store.save(_named("Second"), expected_generation=first.generation)
            loaded = store.load()

            self.assertEqual(second, loaded)
            self.assertTrue(path.exists())
            self.assertTrue(store.backup_path.exists())
            self.assertFalse(store.temp_path.exists())
            self.assertFalse(store.journal_path.exists())
            self.assertFalse(store.journal_temp_path.exists())
            self.assertFalse(store.backup_temp_path.exists())

    def test_real_path_rollback_leaves_current_backup_and_persistent_lock_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "config.json"
            store = ConfigStore(path)
            previous = store.save(_named("Previous"), expected_generation=0)
            current = store.save(_named("Imported"), expected_generation=1)

            rolled_back = store.rollback_previous(
                expected_current_generation=current.generation,
                expected_backup_generation=previous.generation,
                expected_backup_checksum=previous.checksum,
            )
            reloaded = store.load(require_existing=True)

            self.assertEqual(rolled_back, reloaded)
            self.assertEqual((3, "Previous"), (
                reloaded.generation,
                reloaded.config.app.name,
            ))
            backup = json.loads(store.backup_path.read_bytes())
            self.assertEqual((1, "Previous"), (
                backup["generation"],
                backup["config"]["app"]["name"],
            ))
            self.assertEqual(
                {"config.json", "config.json.bak", "config.json.lock"},
                {item.name for item in path.parent.iterdir()},
            )
            self.assertTrue(store.lock_path.is_file())
            self.assertFalse(store.temp_path.exists())
            self.assertFalse(store.journal_path.exists())
            self.assertFalse(store.journal_temp_path.exists())
            self.assertFalse(store.backup_temp_path.exists())


if __name__ == "__main__":
    unittest.main()
