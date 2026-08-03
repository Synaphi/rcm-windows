from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import ipaddress
import json
from pathlib import Path
import unittest

from rcm.config.migrations import (
    MAX_LEGACY_SCHEMA,
    LocalOverlay,
    MigrationDecodeError,
    MigrationDiff,
    MigrationPlan,
    MigrationValidationError,
    NewerLegacySchemaError,
    SecretMaterialError,
    V1ImportProjection,
    V1ImportProjectionError,
    canonical_migration_bytes,
    local_overlay_to_dict,
    plan_v1_migration,
    project_v1_import,
)
from rcm.config.schema import (
    MAX_CONFIG_BYTES,
    Node,
    NodesSection,
    canonical_config_bytes,
    canonical_json_bytes,
    config_from_dict,
    config_to_dict,
    default_config,
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
        self.assertIs(project_v1_import, public_config.project_v1_import)
        self.assertIs(
            V1ImportProjection,
            public_config.V1ImportProjection,
        )
        self.assertIs(
            V1ImportProjectionError,
            public_config.V1ImportProjectionError,
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
                self.assertNotIn("local_overlay", encoded)
                self.assertEqual(
                    sorted(passthrough),
                    encoded["local_overlay_paths"]["legacy_passthrough"],
                )
                serialized = canonical_migration_bytes(mapping_plan)
                self.assertNotIn(b'"value":', serialized)

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
        self.assertNotIn(marker, encoded)
        self.assertIn("nodes[].rdp_user", encoded)
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

    def test_valid_unicode_is_preserved_locally_and_redacted_from_summary(self) -> None:
        value = "합성-고정폭"
        plan = plan_v1_migration(
            {
                "schema_version": 15,
                "diagnostic_font": value,
            }
        )
        self.assertEqual(
            value,
            local_overlay_to_dict(plan.local_overlay)["per_user_ui"][0]["value"],
        )
        summary = canonical_migration_bytes(plan).decode("utf-8")
        self.assertNotIn(value, summary)
        self.assertIn("diagnostic_font", summary)

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

    def test_projection_accepts_all_legacy_schemas_and_preserves_current(
        self,
    ) -> None:
        initial = default_config()
        current = replace(
            initial,
            app=replace(initial.app, name="Synthetic Current"),
            ui=replace(initial.ui, theme="dark", scale_percent=125),
            rdp=replace(initial.rdp, port=3391),
            ray=replace(initial.ray, startup_timeout_seconds=91),
        )
        for schema in range(16):
            source = {"schema_version": schema}
            before = deepcopy(source)
            with self.subTest(schema=schema):
                projection = project_v1_import(source, current)
                self.assertEqual(schema, projection.source_schema)
                self.assertEqual(current, projection.config)
                self.assertEqual(before, source)
                self.assertIsInstance(projection, V1ImportProjection)

    def test_projection_maps_safe_local_fields_and_drops_authority_metadata(
        self,
    ) -> None:
        marker = "SYNTHETIC_PRIVATE_METADATA"
        initial = default_config()
        current = replace(
            initial,
            app=replace(initial.app, name="Synthetic Preserved"),
            ui=replace(initial.ui, theme="light", scale_percent=150),
            ray=replace(
                initial.ray,
                enabled=True,
                head_address="192.0.2.99",
                startup_timeout_seconds=77,
            ),
        )
        source = {
            "schema_version": 15,
            "head_ip": "192.0.2.10",
            "head_port": 6389,
            "dashboard_port": 8275,
            "this": {
                "ip": "192.0.2.11",
                "mode": "ray",
                "role": "worker",
                "num_cpus": "auto",
            },
            "nodes": [
                {
                    "name": "synthetic-head",
                    "ip": "192.0.2.10",
                    "mode": "ray",
                    "role": "head",
                    "num_cpus": 8,
                    "enabled": True,
                },
                {
                    "name": "synthetic-worker",
                    "ip": "192.0.2.11",
                    "mode": "ray",
                    "role": "worker",
                    "num_cpus": "auto",
                    "enabled": True,
                    "rdp_user": marker,
                    "credential_reference": (
                        "credential://synthetic-private-metadata"
                    ),
                },
            ],
            "metrics_enabled": False,
            "poll_interval": 1.5,
            "dashboard_stale_grace_sec": 8.0,
            "process_cleanup": {"grace_sec": 4.0},
            "credential_controller_ips": ["192.0.2.30"],
            "trusted_controller_ids": [marker],
            "credential_references": [
                "credential://synthetic-private-metadata"
            ],
            "official_exe_path": f"updates/{marker}.exe",
            "cluster_manifest_path": f"state/{marker}.json",
            "cluster_epoch": 9,
        }
        before = deepcopy(source)

        projection = project_v1_import(source, current)

        self.assertEqual(before, source)
        self.assertEqual("Synthetic Preserved", projection.config.app.name)
        self.assertEqual(current.ui, projection.config.ui)
        self.assertFalse(projection.config.monitoring.enabled)
        self.assertEqual(1_500, projection.config.monitoring.interval_ms)
        self.assertEqual(8_000, projection.config.monitoring.stale_after_ms)
        self.assertEqual(
            4,
            projection.config.cleanup.graceful_timeout_seconds,
        )
        self.assertEqual(
            current.cleanup.force_timeout_seconds,
            projection.config.cleanup.force_timeout_seconds,
        )
        self.assertEqual(
            ("synthetic-head", "synthetic-worker"),
            tuple(node.node_id for node in projection.config.nodes.items),
        )
        self.assertEqual(
            "synthetic-worker",
            projection.config.nodes.local_node_id,
        )
        self.assertFalse(projection.config.ray.enabled)
        self.assertIn(
            MigrationDiff(
                "projection.safety",
                "config.ray.enabled",
                "disabled-for-review",
            ),
            projection.mapped_fields,
        )
        self.assertEqual("192.0.2.10", projection.config.ray.head_address)
        self.assertEqual(6389, projection.config.ray.client_port)
        self.assertEqual(8275, projection.config.ray.dashboard_port)
        self.assertEqual(0, projection.config.ray.cpu_count)
        self.assertEqual(77, projection.config.ray.startup_timeout_seconds)
        target = canonical_config_bytes(projection.config).decode("utf-8")
        self.assertNotIn(marker, target)
        self.assertNotIn("credential://", target)
        self.assertNotIn(marker, repr(projection))
        self.assertTrue(projection.mapped_fields)
        self.assertTrue(projection.rejected_fields)
        self.assertEqual(projection.skipped_fields, projection.unmapped_fields)
        rejected_paths = {
            item.source_path for item in projection.rejected_fields
        }
        self.assertIn("nodes[].rdp_user", rejected_paths)
        self.assertIn("credential_references", rejected_paths)
        self.assertIn("credential_controller_ips", rejected_paths)
        self.assertIn("cluster_manifest_path", rejected_paths)
        for item in (
            *projection.mapped_fields,
            *projection.skipped_fields,
            *projection.rejected_fields,
        ):
            self.assertNotIn(marker, repr(item))
            reason = getattr(item, "reason", "")
            if reason:
                self.assertLess(len(reason), 40)

    def test_projection_preserves_or_explicitly_raises_cleanup_force_timeout(
        self,
    ) -> None:
        baseline = default_config()
        preserved_current = replace(
            baseline,
            cleanup=replace(
                baseline.cleanup,
                graceful_timeout_seconds=10,
                force_timeout_seconds=90,
            ),
        )
        preserved = project_v1_import(
            {
                "schema_version": 15,
                "process_cleanup": {"grace_sec": 4.0},
            },
            preserved_current,
        )
        self.assertEqual(4, preserved.config.cleanup.graceful_timeout_seconds)
        self.assertEqual(90, preserved.config.cleanup.force_timeout_seconds)
        self.assertNotIn(
            "config.cleanup.force_timeout_seconds",
            {item.target_path for item in preserved.mapped_fields},
        )

        raised_current = replace(
            baseline,
            cleanup=replace(
                baseline.cleanup,
                graceful_timeout_seconds=1,
                force_timeout_seconds=2,
            ),
        )
        raised = project_v1_import(
            {
                "schema_version": 15,
                "process_cleanup": {"grace_sec": 4.0},
            },
            raised_current,
        )
        self.assertEqual(4, raised.config.cleanup.graceful_timeout_seconds)
        self.assertEqual(4, raised.config.cleanup.force_timeout_seconds)
        force_mapping = next(
            item
            for item in raised.mapped_fields
            if item.target_path == "config.cleanup.force_timeout_seconds"
        )
        self.assertEqual("raised-for-timeout-invariant", force_mapping.action)

    def test_projection_preserves_local_id_spelling_or_reports_clear(self) -> None:
        baseline = default_config()
        current = replace(
            baseline,
            nodes=NodesSection(
                (
                    Node(
                        node_id="local-v2",
                        address="192.0.2.99",
                        role="worker",
                        enabled=True,
                        cpu_count=2,
                    ),
                ),
                "local-v2",
            ),
        )
        source_node = {
            "ip": "192.0.2.20",
            "mode": "ray",
            "role": "worker",
            "num_cpus": 2,
            "enabled": True,
        }
        cleared = project_v1_import(
            {
                "schema_version": 15,
                "nodes": [{"name": "legacy-worker", **source_node}],
            },
            current,
        )
        self.assertEqual("", cleared.config.nodes.local_node_id)
        local_mapping = next(
            item
            for item in cleared.mapped_fields
            if item.target_path == "config.nodes.local_node_id"
        )
        self.assertEqual("cleared-not-in-import", local_mapping.action)

        recased = project_v1_import(
            {
                "schema_version": 15,
                "nodes": [{"name": "LOCAL-V2", **source_node}],
            },
            current,
        )
        self.assertEqual("local-v2", recased.config.nodes.local_node_id)
        self.assertNotIn(
            "config.nodes.local_node_id",
            {item.target_path for item in recased.mapped_fields},
        )

    def test_projection_always_disables_existing_ray_without_ray_input(
        self,
    ) -> None:
        baseline = default_config()
        current = replace(
            baseline,
            ray=replace(
                baseline.ray,
                enabled=True,
                head_address="192.0.2.1",
            ),
        )
        projection = project_v1_import(
            {"schema_version": 15, "metrics_enabled": False},
            current,
        )

        self.assertFalse(projection.config.ray.enabled)
        safety = next(
            item
            for item in projection.mapped_fields
            if item.target_path == "config.ray.enabled"
        )
        self.assertEqual("projection.safety", safety.source_path)
        self.assertEqual("disabled-for-review", safety.action)

    def test_projection_rejects_ambiguous_or_unrepresentable_nodes_value_free(
        self,
    ) -> None:
        cases = (
            (
                "unicode",
                [{
                    "name": "?⑹꽦 ?몃뱶",
                    "ip": "192.0.2.40",
                    "mode": "ray",
                    "role": "worker",
                    "num_cpus": 4,
                }],
            ),
            (
                "controller",
                [{
                    "name": "synthetic-controller",
                    "ip": "192.0.2.41",
                    "mode": "rdp-client",
                    "role": "worker",
                    "num_cpus": 4,
                }],
            ),
            (
                "driver-zero",
                [{
                    "name": "synthetic-driver",
                    "ip": "192.0.2.42",
                    "mode": "ray",
                    "role": "worker",
                    "num_cpus": 0,
                }],
            ),
            (
                "casefold-duplicate",
                [
                    {
                        "name": "Synthetic-A",
                        "ip": "192.0.2.43",
                        "mode": "ray",
                        "role": "worker",
                        "num_cpus": 2,
                    },
                    {
                        "name": "synthetic-a",
                        "ip": "192.0.2.44",
                        "mode": "ray",
                        "role": "worker",
                        "num_cpus": 2,
                    },
                ],
            ),
            (
                "duplicate-address",
                [
                    {
                        "name": "synthetic-a",
                        "ip": "192.0.2.45",
                        "mode": "ray",
                        "role": "worker",
                        "num_cpus": 2,
                    },
                    {
                        "name": "synthetic-b",
                        "ip": "192.0.2.45",
                        "mode": "ray",
                        "role": "worker",
                        "num_cpus": 2,
                    },
                ],
            ),
            (
                "multiple-heads",
                [
                    {
                        "name": "synthetic-head-a",
                        "ip": "192.0.2.46",
                        "mode": "ray",
                        "role": "head",
                        "num_cpus": 2,
                    },
                    {
                        "name": "synthetic-head-b",
                        "ip": "192.0.2.47",
                        "mode": "ray",
                        "role": "head",
                        "num_cpus": 2,
                    },
                ],
            ),
        )
        for label, nodes in cases:
            source = {"schema_version": 15, "nodes": nodes}
            marker_values = tuple(str(node["name"]) for node in nodes)
            with self.subTest(label=label):
                with self.assertRaises(V1ImportProjectionError) as captured:
                    project_v1_import(source, default_config())
                for marker in marker_values:
                    self.assertNotIn(marker, str(captured.exception))
                    self.assertNotIn(marker, repr(captured.exception))
                self.assertLess(len(captured.exception.reason), 40)

    def test_projection_schema_13_zero_is_auto_but_schema_14_is_ambiguous(
        self,
    ) -> None:
        node = {
            "name": "synthetic-zero",
            "ip": "192.0.2.60",
            "mode": "ray",
            "role": "worker",
            "num_cpus": 0,
        }
        projected = project_v1_import(
            {"schema_version": 13, "nodes": [node]},
            default_config(),
        )
        self.assertEqual(0, projected.config.nodes.items[0].cpu_count)
        with self.assertRaises(V1ImportProjectionError):
            project_v1_import(
                {"schema_version": 14, "nodes": [node]},
                default_config(),
            )

    def test_projection_1_8_32_nodes_is_idempotent_and_non_mutating(
        self,
    ) -> None:
        for count in (1, 8, 32):
            nodes = [
                {
                    "name": f"synthetic-node-{index:02d}",
                    "ip": f"192.0.2.{index + 1}",
                    "mode": "ray",
                    "role": "head" if index == 0 else "worker",
                    "num_cpus": "auto" if index % 2 else index + 1,
                    "enabled": True,
                }
                for index in range(count)
            ]
            source = {
                "schema_version": 15,
                "head_ip": "192.0.2.1",
                "this": {
                    "ip": "192.0.2.1",
                    "mode": "auto",
                    "role": "auto",
                    "num_cpus": "auto",
                },
                "nodes": nodes,
            }
            before = deepcopy(source)
            with self.subTest(count=count):
                first = project_v1_import(source, default_config())
                second = project_v1_import(source, default_config())
                repeated = project_v1_import(source, first.config)
                self.assertEqual(before, source)
                self.assertEqual(first, second)
                self.assertEqual(first.config, repeated.config)
                self.assertEqual(first.mapped_fields, repeated.mapped_fields)
                self.assertEqual(first.skipped_fields, repeated.skipped_fields)
                self.assertEqual(
                    first.rejected_fields,
                    repeated.rejected_fields,
                )
                self.assertEqual(count, len(first.config.nodes.items))


if __name__ == "__main__":
    unittest.main()
