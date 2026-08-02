from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, date, datetime
import unittest

from rcm.release import (
    MAX_SIGNED_SEQUENCE,
    ReleaseIdentityService,
    ReleaseKind,
    compare_signed_sequence,
    release_date_for,
)


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = ReleaseIdentityService()

    def test_formal_identity_has_exact_display_canonical_and_windows_values(
        self,
    ) -> None:
        identity = self.service.create(date(2026, 7, 29), "a")
        self.assertEqual("2.07.29a", identity.display_version)
        self.assertEqual("rcm-2-2026-07-29-a", identity.release_id)
        self.assertEqual("v2.2026.07.29a", identity.tag)
        self.assertEqual(2026072901, identity.sequence)
        self.assertEqual((2, 2026, 729, 1), identity.windows_tuple)
        self.assertEqual("2.2026.729.1", identity.windows_version)
        self.assertTrue(identity.formal)
        self.assertEqual(
            [2, 2026, 729, 1],
            identity.to_dict()["windows_tuple"],
        )
        with self.assertRaises(FrozenInstanceError):
            identity.tag = "changed"  # type: ignore[misc]

    def test_display_can_repeat_next_year_but_identity_never_does(self) -> None:
        first = self.service.create(date(2026, 7, 29), "a")
        second = self.service.create(date(2027, 7, 29), "a")
        self.assertEqual(first.display_version, second.display_version)
        self.assertNotEqual(first.release_id, second.release_id)
        self.assertNotEqual(first.tag, second.tag)
        self.assertNotEqual(first.sequence, second.sequence)
        self.assertEqual(-1, first.compare(second))
        self.assertEqual(1, second.compare(first))

    def test_next_formal_increments_same_day_and_resets_after_rollover(self) -> None:
        first = self.service.create(date(2026, 12, 31), "a")
        same_day = self.service.next_formal(first, date(2026, 12, 31))
        next_year = self.service.next_formal(same_day, date(2027, 1, 1))
        self.assertEqual("b", same_day.revision)
        self.assertEqual("2.12.31b", same_day.display_version)
        self.assertEqual("a", next_year.revision)
        self.assertEqual("2.01.01a", next_year.display_version)
        self.assertLess(first.sequence, same_day.sequence)  # type: ignore[operator]
        self.assertLess(same_day.sequence, next_year.sequence)  # type: ignore[operator]

    def test_early_year_identity_uses_platform_independent_iso_date(self) -> None:
        for year in (1, 999):
            with self.subTest(year=year):
                identity = self.service.create(date(year, 1, 2), "a")
                self.assertIn(f"{year:04d}-01-02", identity.release_id)

    def test_all_a_to_z_revisions_are_unique_and_z_exhausts_the_day(self) -> None:
        identities = [
            self.service.create(date(2026, 7, 29), chr(ord("a") + index))
            for index in range(26)
        ]
        self.assertEqual(26, len({item.release_id for item in identities}))
        self.assertEqual(26, len({item.tag for item in identities}))
        self.assertEqual(26, len({item.sequence for item in identities}))
        self.assertEqual(1, identities[0].windows_tuple[3])
        self.assertEqual(26, identities[-1].windows_tuple[3])
        with self.assertRaises(ValueError):
            self.service.next_formal(identities[-1], date(2026, 7, 29))

    def test_kst_boundary_uses_aware_timestamp_not_host_timezone(self) -> None:
        before = datetime(2026, 7, 28, 14, 59, 59, tzinfo=UTC)
        after = datetime(2026, 7, 28, 15, 0, 0, tzinfo=UTC)
        self.assertEqual(date(2026, 7, 28), release_date_for(before))
        self.assertEqual(date(2026, 7, 29), release_date_for(after))
        self.assertEqual(
            "2.07.28a",
            self.service.create(before, "a").display_version,
        )
        self.assertEqual(
            "2.07.29a",
            self.service.create(after, "a").display_version,
        )
        with self.assertRaises(ValueError):
            release_date_for(datetime(2026, 7, 29, 0, 0))

    def test_from_display_validates_prefix_calendar_year_and_revision(self) -> None:
        identity = self.service.from_display("2.02.29c", year=2028)
        self.assertEqual(date(2028, 2, 29), identity.release_date)
        invalid = (
            lambda: self.service.from_display("1.07.29a", year=2026),
            lambda: self.service.from_display("2.07.29A", year=2026),
            lambda: self.service.from_display("2.02.29a", year=2027),
            lambda: self.service.from_display("2.13.01a", year=2027),
            lambda: self.service.from_display("2.07.29a", year=True),
        )
        for case in invalid:
            with self.subTest(case=case):
                with self.assertRaises((TypeError, ValueError)):
                    case()

    def test_windows_version_components_remain_in_supported_range(self) -> None:
        identity = self.service.create(date(9999, 12, 31), "z")
        self.assertTrue(all(0 <= item <= 65_535 for item in identity.windows_tuple))
        self.assertLessEqual(identity.sequence, MAX_SIGNED_SEQUENCE)  # type: ignore[operator]

    def test_commit_snapshot_cannot_claim_formal_tag_or_sequence(self) -> None:
        commit = "a" * 40
        snapshot = self.service.create(
            date(2026, 7, 29),
            "a",
            kind=ReleaseKind.COMMIT_SNAPSHOT,
            commit_id=commit,
        )
        formal = self.service.create(date(2026, 7, 29), "a")
        self.assertFalse(snapshot.formal)
        self.assertIsNone(snapshot.tag)
        self.assertIsNone(snapshot.sequence)
        self.assertEqual((2, 2026, 729, 0), snapshot.windows_tuple)
        self.assertIn(f"snapshot-2026-07-29-a-{commit}", snapshot.release_id)
        self.assertNotEqual(formal.release_id, snapshot.release_id)
        self.assertNotIn(commit, str(snapshot.to_dict()))
        self.assertNotIn("release_id", snapshot.to_dict())
        with self.assertRaises(ValueError):
            snapshot.compare(formal)
        with self.assertRaises(ValueError):
            self.service.create(
                date(2026, 7, 29),
                "a",
                kind=ReleaseKind.COMMIT_SNAPSHOT,
            )
        with self.assertRaises(ValueError):
            self.service.create(
                date(2026, 7, 29),
                "a",
                commit_id=commit,
            )

    def test_commit_snapshot_normalizes_full_commit_identity(self) -> None:
        snapshot = self.service.create(
            date(2026, 7, 29),
            "b",
            kind=ReleaseKind.COMMIT_SNAPSHOT,
            commit_id="A" * 64,
        )
        self.assertEqual("a" * 64, snapshot.commit_id)
        self.assertTrue(snapshot.release_id.endswith("a" * 64))
        for commit in ("abc1234", "g" * 40, "a" * 39, "a" * 41):
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError):
                    self.service.create(
                        date(2026, 7, 29),
                        "a",
                        kind=ReleaseKind.COMMIT_SNAPSHOT,
                        commit_id=commit,
                    )

    def test_comparison_uses_sequence_and_rejects_invalid_signed_values(
        self,
    ) -> None:
        self.assertEqual(-1, compare_signed_sequence(1, 2))
        self.assertEqual(0, compare_signed_sequence(2, 2))
        self.assertEqual(1, compare_signed_sequence(3, 2))
        for value in (0, -1, True, MAX_SIGNED_SEQUENCE + 1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    compare_signed_sequence(value, 1)  # type: ignore[arg-type]

    def test_direct_identity_tampering_is_rejected(self) -> None:
        identity = self.service.create(date(2026, 7, 29), "a")
        mutations = (
            {"release_id": "not-canonical"},
            {"tag": "v2.2026.07.29b"},
            {"sequence": 2026072902},
            {"windows_tuple": (2, 2026, 729, 2)},
            {"windows_version": "2.2026.729.2"},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    replace(identity, **changes)

    def test_next_formal_rejects_backwards_date_and_snapshot_base(self) -> None:
        formal = self.service.create(date(2026, 7, 29), "a")
        snapshot = self.service.create(
            date(2026, 7, 29),
            "a",
            kind=ReleaseKind.COMMIT_SNAPSHOT,
            commit_id="a" * 40,
        )
        with self.assertRaises(ValueError):
            self.service.next_formal(formal, date(2026, 7, 28))
        with self.assertRaises(ValueError):
            self.service.next_formal(snapshot, date(2026, 7, 30))


if __name__ == "__main__":
    unittest.main()
