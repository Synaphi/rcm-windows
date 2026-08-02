from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import unittest

from rcm.config.migrations import (
    MAX_LEGACY_SCHEMA,
    LocalOverlay,
    MigrationDecodeError,
    MigrationPlan,
    MigrationValidationError,
    NewerLegacySchemaError,
    SecretMaterialError,
    canonical_migration_bytes,
    local_overlay_to_dict,
    plan_v1_migration,
)
from rcm.config.schema import (
    MAX_CONFIG_BYTES,
    canonical_config_bytes,
    canonical_json_bytes,
    config_from_dict,
    config_to_dict,
)


FIXTURE = Path(__file__).parent / "fixtures" / "v1_schema_corpus.json"
IPV4_DOCUMENTATION = ipaddress.ip_network("192.0.2.0/24")
IPV6_DOCUMENTATION = ipaddress.ip_network("2001:db8::/32")


def load_corpus() -> list[dict[str, object]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return document["cases"]


def source_value(source: dict[str, object], path: str) -> object:
    if path.startswith("process_cleanup."):
        cleanup = source["process_cleanup"]
        assert isinstance(cleanup, dict)
        return cleanup[path.split(".", 1)[1]]
    if path == "nodes[].rdp_user":
        nodes = source["nodes"]
        assert isinstance(nodes, list)
        return [
            {"index": index, "value": node["rdp_user"]}
            for index, node in enumerate(nodes)
            if isinstance(node, dict) and "rdp_user" in node
        ]
    return source[path]


class V1MigrationTests(unittest.TestCase):
    def test_migration_api_is_exported_from_config_package(self) -> None:
        from rcm import config as public_config

        self.assertIs(plan_v1_migration, public_config.plan_v1_migration)
        self.assertIs(MigrationPlan, public_config.MigrationPlan)
        self.assertIs(
            canonical_migration_bytes,
            public_config.canonical_migration_bytes,
        )

    def test_corpus_has_exactly_one_case_for_every_schema_0_through_15(
        self,
    ) -> None:
        cases = load_corpus()
        self.assertEqual(16, len(cases))
        self.assertEqual(list(range(16)), [case["schema"] for case in cases])

    def test_corpus_uses_only_documentation_ip_ranges(self) -> None:
        def visit(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {
                        "address",
                        "head_ip",
                        "ip",
                    } or key.endswith("_ips"):
                        if isinstance(child, list):
                            for item in child:
                                assert_documentation_ip(item)
                        else:
                            assert_documentation_ip(child)
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        def assert_documentation_ip(value: object) -> None:
            address = ipaddress.ip_address(str(value))
            if address.version == 4:
                self.assertIn(address, IPV4_DOCUMENTATION)
            else:
                self.assertIn(address, IPV6_DOCUMENTATION)

        for case in load_corpus():
            visit(case["source"])

    def test_every_corpus_case_copy_converts_without_source_mutation(
        self,
    ) -> None:
        for case in load_corpus():
            source = case["source"]
            before = deepcopy(source)
            raw = canonical_json_bytes(source)
            raw_before = bytes(raw)
            with self.subTest(schema=case["schema"]):
                mapping_plan = plan_v1_migration(source)
                bytes_plan = plan_v1_migration(raw)
                self.assertEqual(case["schema"], mapping_plan.source_schema)
                self.assertEqual(mapping_plan, bytes_plan)
                self.assertTrue(mapping_plan.lossless)
                self.assertEqual(before, source)
                self.assertEqual(raw_before, raw)
                self.assertEqual(
                    mapping_plan.config,
                    config_from_dict(config_to_dict(mapping_plan.config)),
                )
                passthrough = {
                    item.path: item.value()
                    for item in mapping_plan.local_overlay.legacy_passthrough
                }
                self.assertEqual(
                    {
                        field.source_path: source_value(
                            source,
                            field.source_path,
                        )
                        for field in mapping_plan.unmapped_fields
                    },
                    passthrough,
                )
                encoded = json.loads(
                    canonical_migration_bytes(mapping_plan).decode("utf-8")
                )
                serialized_passthrough = {
                    item["path"]: item["value"]
                    for item in encoded["local_overlay"][
                        "legacy_passthrough"
                    ]
                }
                self.assertEqual(passthrough, serialized_passthrough)

    def test_repeat_import_and_canonical_output_are_idempotent(self) -> None:
        for case in load_corpus():
            raw = canonical_json_bytes(case["source"])
            first = plan_v1_migration(raw)
            second = plan_v1_migration(raw)
            with self.subTest(schema=case["schema"]):
                self.assertEqual(first, second)
                self.assertEqual(
                    canonical_migration_bytes(first),
                    canonical_migration_bytes(second),
                )
                self.assertEqual(
                    canonical_config_bytes(first.config),
                    canonical_config_bytes(second.config),
                )

    def test_public_candidate_excludes_local_topology_and_references(
        self,
    ) -> None:
        source = {
            "schema_version": 15,
            "head_ip": "192.0.2.40",
            "nodes": [
                {
                    "name": "synthetic-worker",
                    "ip": "192.0.2.41",
                    "role": "worker",
                    "mode": "ray",
                    "num_cpus": 4,
                    "credential_reference": "credential://synthetic-worker",
                }
            ],
            "credential_controller_ips": ["192.0.2.42"],
            "trusted_controller_ids": ["synthetic-controller"],
            "official_exe_path": "updates/rcm.exe",
            "theme": "classic",
        }
        plan = plan_v1_migration(source)
        public = config_to_dict(plan.config)
        self.assertEqual([], public["nodes"]["items"])
        self.assertEqual("", public["ray"]["head_address"])
        self.assertEqual("", public["rdp"]["credential_reference"])

        overlay = local_overlay_to_dict(plan.local_overlay)
        self.assertGreater(len(overlay["topology"]), 0)
        self.assertGreater(len(overlay["per_user_ui"]), 0)
        self.assertGreater(len(overlay["trust"]), 0)
        self.assertGreater(len(overlay["controller_lists"]), 0)
        self.assertGreater(len(overlay["update_paths"]), 0)
        self.assertGreater(len(overlay["credential_references"]), 0)

    def test_public_field_conversion_uses_typed_schema(self) -> None:
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "metrics_enabled": False,
                "poll_interval": 1.5,
                "dashboard_stale_grace_sec": 8.0,
                "process_cleanup": {"grace_sec": 4.0},
            }
        )
        self.assertFalse(plan.config.monitoring.enabled)
        self.assertEqual(1_500, plan.config.monitoring.interval_ms)
        self.assertEqual(8_000, plan.config.monitoring.stale_after_ms)
        self.assertEqual(4, plan.config.cleanup.graceful_timeout_seconds)

    def test_every_unsupported_legacy_value_is_explicitly_unmapped(
        self,
    ) -> None:
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "temp_warn_c": 80,
                "metrics_timeout_sec": 3.0,
                "process_cleanup": {
                    "sample_sec": 8.0,
                    "ignored_fingerprints": [],
                },
            }
        )
        paths = {field.source_path for field in plan.unmapped_fields}
        self.assertEqual(
            {
                "metrics_timeout_sec",
                "process_cleanup.ignored_fingerprints",
                "process_cleanup.sample_sec",
                "temp_warn_c",
            },
            paths,
        )

    def test_node_user_name_is_private_passthrough_and_explicitly_unmapped(
        self,
    ) -> None:
        marker = "SYNTHETIC_LOCAL_PRINCIPAL_VALUE"
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "nodes": [
                    {
                        "ip": "192.0.2.50",
                        "role": "worker",
                        "mode": "ray",
                        "num_cpus": 2,
                        "rdp_user": marker,
                    }
                ],
            }
        )
        encoded = canonical_migration_bytes(plan).decode("utf-8")
        self.assertIn(marker, encoded)
        self.assertNotIn(marker, repr(plan))
        self.assertNotIn(marker, repr(plan.local_overlay))
        self.assertIn(
            "nodes[].rdp_user",
            {field.source_path for field in plan.unmapped_fields},
        )

    def test_raw_secret_values_are_rejected_without_echo_or_persistence(
        self,
    ) -> None:
        raw_markers = (
            ("password", "SYNTHETIC_RAW_PASSWORD_VALUE"),
            ("rdp_password", "SYNTHETIC_RAW_RDP_PASSWORD_VALUE"),
            ("token", "SYNTHETIC_RAW_TOKEN_VALUE"),
            ("auth_token", "SYNTHETIC_RAW_AUTH_TOKEN_VALUE"),
            ("authToken", "SYNTHETIC_RAW_CAMEL_TOKEN_VALUE"),
            ("private_key", "SYNTHETIC_RAW_PRIVATE_KEY_VALUE"),
            ("privateKey", "SYNTHETIC_RAW_CAMEL_PRIVATE_KEY_VALUE"),
            ("credential_value", "SYNTHETIC_RAW_CREDENTIAL_VALUE"),
            ("credentialValue", "SYNTHETIC_RAW_CAMEL_CREDENTIAL_VALUE"),
        )
        for key, marker in raw_markers:
            source = {
                "schema_version": 15,
                "nodes": [{"ip": "192.0.2.60", key: marker}],
            }
            with self.subTest(key=key):
                with self.assertRaises(SecretMaterialError) as captured:
                    plan_v1_migration(source)
                self.assertNotIn(marker, str(captured.exception))
                self.assertNotIn(marker, repr(captured.exception))

    def test_secret_bearing_credential_references_are_rejected_without_echo(
        self,
    ) -> None:
        marker = "SYNTHETIC_RAW_REFERENCE_VALUE"
        references = (
            f"credential://user:{marker}@vault",
            f"credential://vault?token={marker}",
            f"credential://vault#{marker}",
            f"credential://vault%2F{marker}",
            f"credential://vault\\{marker}",
            f"credential://vault\n{marker}",
        )
        for reference in references:
            with self.subTest(reference=reference):
                with self.assertRaises(MigrationValidationError) as captured:
                    plan_v1_migration(
                        {
                            "schema_version": 15,
                            "credential_references": [reference],
                        }
                    )
                self.assertNotIn(marker, str(captured.exception))
                self.assertNotIn(marker, repr(captured.exception))

    def test_private_key_marker_is_rejected_even_under_safe_looking_key(
        self,
    ) -> None:
        marker = "-" * 5 + "BEGIN " + "PRIVATE" + " KEY" + "-" * 5
        with self.assertRaises(SecretMaterialError) as captured:
            plan_v1_migration(
                {
                    "schema_version": 15,
                    "head_whoami": marker,
                }
            )
        self.assertNotIn(marker, str(captured.exception))

    def test_valid_unicode_is_preserved_canonically(self) -> None:
        value = "합성-고정폭"
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "diagnostic_font": value,
            }
        )
        self.assertIn(
            value,
            canonical_migration_bytes(plan).decode("utf-8"),
        )

    def test_legacy_field_types_and_ranges_are_strict(self) -> None:
        rejected = (
            {"schema_version": 15, "head_port": "6379"},
            {"schema_version": 15, "metrics_enabled": 1},
            {"schema_version": 15, "head_ip": "synthetic-invalid-address"},
            {"schema_version": 15, "watchdog_stale_cycles": 0},
            {
                "schema_version": 15,
                "this": {"num_cpus": "four"},
            },
        )
        for source in rejected:
            with self.subTest(source=source):
                with self.assertRaises(MigrationValidationError):
                    plan_v1_migration(source)

    def test_local_overlay_paths_reject_unc_namespace_and_traversal(
        self,
    ) -> None:
        rejected = (
            r"..\outside\rcm.exe",
            r"\\synthetic-host\share\rcm.exe",
            r"\\?\C:\Synthetic\rcm.exe",
            "\\" * 2 + r".\pipe\synthetic",
            r"C:drive-relative\rcm.exe",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaises(MigrationValidationError) as captured:
                    plan_v1_migration(
                        {
                            "schema_version": 15,
                            "official_exe_path": value,
                        }
                    )
                self.assertNotIn(value, str(captured.exception))

    def test_plan_and_overlay_repr_redact_local_values(self) -> None:
        marker = "SYNTHETIC_PRIVATE_LOCAL_PATH"
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "official_exe_path": marker,
            }
        )
        self.assertNotIn(marker, repr(plan))
        self.assertNotIn(marker, repr(plan.local_overlay))
        entry = plan.local_overlay.update_paths[0]
        self.assertNotIn(marker, repr(entry))

    def test_diff_contains_only_sanitized_paths_and_actions(self) -> None:
        marker = "SYNTHETIC_VALUE_NOT_FOR_DIFF"
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "official_exe_path": marker,
                "head_ip": "192.0.2.70",
            }
        )
        for entry in plan.diff:
            self.assertNotIn(marker, repr(entry))
            self.assertRegex(entry.source_path, r"^[a-z0-9_.\[\]]+$")
            self.assertRegex(entry.target_path, r"^[a-z0-9_.\[\]]+$")
            self.assertRegex(entry.action, r"^[a-z-]+$")

    def test_newer_schema_is_rejected_read_only(self) -> None:
        source = {"schema_version": MAX_LEGACY_SCHEMA + 1}
        before = deepcopy(source)
        with self.assertRaises(NewerLegacySchemaError) as captured:
            plan_v1_migration(source)
        self.assertTrue(captured.exception.read_only)
        self.assertEqual(before, source)

    def test_strict_parser_rejects_duplicate_malformed_and_unicode(
        self,
    ) -> None:
        rejected = (
            b'{"schema_version":15,"schema_version":14}',
            b'{"schema_version":15',
            b'{"schema_version":15}\xff',
            b'{"schema_version":NaN}',
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                with self.assertRaises(MigrationDecodeError):
                    plan_v1_migration(raw)

    def test_strict_parser_rejects_oversized_input(self) -> None:
        raw = (
            b'{"schema_version":15,"head_whoami":"'
            + b"x" * MAX_CONFIG_BYTES
            + b'"}'
        )
        with self.assertRaises(MigrationDecodeError):
            plan_v1_migration(raw)

    def test_unknown_fields_fail_closed_without_echoing_values(self) -> None:
        marker = "SYNTHETIC_UNKNOWN_VALUE"
        with self.assertRaises(MigrationValidationError) as captured:
            plan_v1_migration(
                {
                    "schema_version": 15,
                    "unsupported_field": marker,
                }
            )
        self.assertNotIn(marker, str(captured.exception))

    def test_local_overlay_type_is_immutable_value_container(self) -> None:
        plan = plan_v1_migration({"schema_version": 15})
        self.assertIsInstance(plan.local_overlay, LocalOverlay)
        with self.assertRaises(AttributeError):
            plan.local_overlay.topology = ()  # type: ignore[misc]

    def test_lossless_requires_exact_unmapped_passthrough_coverage(
        self,
    ) -> None:
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "temp_warn_c": 80,
            }
        )
        self.assertTrue(plan.lossless)
        incomplete = MigrationPlan(
            source_schema=plan.source_schema,
            config=plan.config,
            local_overlay=LocalOverlay(),
            diff=plan.diff,
            unmapped_fields=plan.unmapped_fields,
        )
        self.assertFalse(incomplete.lossless)


if __name__ == "__main__":
    unittest.main()
