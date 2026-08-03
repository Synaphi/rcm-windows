from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import unittest

from rcm.config.schema import (
    MAX_CONFIG_BYTES,
    CleanupSection,
    Config,
    ConfigDecodeError,
    ConfigTooLargeError,
    ConfigValidationError,
    DuplicateKeyError,
    Node,
    NodesSection,
    RemoteSection,
    UpdateSection,
    canonical_config_bytes,
    config_checksum,
    config_from_dict,
    config_to_dict,
    default_config,
    parse_config_bytes,
)


class ConfigSchemaTests(unittest.TestCase):
    def test_defaults_are_frozen_namespaced_and_public(self) -> None:
        config = default_config()

        self.assertEqual(
            {
                "app",
                "cleanup",
                "monitoring",
                "nodes",
                "ray",
                "rdp",
                "remote",
                "schema_version",
                "ui",
                "update",
            },
            set(config_to_dict(config)),
        )
        self.assertEqual((), config.nodes.items)
        self.assertEqual("", config.ray.executable_path)
        self.assertEqual("", config.ray.head_address)
        self.assertNotIn("executable_path", repr(config.ray))
        self.assertEqual("", config.rdp.credential_reference)
        self.assertEqual("", config.update.manifest_url)
        self.assertFalse(config.remote.enabled)
        self.assertEqual("127.0.0.1", config.remote.bind_host)
        with self.assertRaises(FrozenInstanceError):
            config.ui.scale_percent = 125  # type: ignore[misc]

    def test_minimal_object_fills_defaults_and_round_trips(self) -> None:
        config = parse_config_bytes(b"{}")
        self.assertEqual(default_config(), config)
        self.assertEqual(config, parse_config_bytes(canonical_config_bytes(config)))

    def test_unicode_is_canonical_utf8_and_key_order_is_stable(self) -> None:
        first = config_from_dict({"app": {"name": "Synthetic \uacc4\uc0b0"}, "schema_version": 1})
        second = config_from_dict({"schema_version": 1, "app": {"name": "Synthetic \uacc4\uc0b0"}})

        self.assertEqual(canonical_config_bytes(first), canonical_config_bytes(second))
        self.assertIn("\uacc4\uc0b0".encode(), canonical_config_bytes(first))
        self.assertNotIn(b"\\u", canonical_config_bytes(first))
        self.assertEqual(64, len(config_checksum(first)))

    def test_strict_json_rejects_duplicate_at_any_depth(self) -> None:
        for raw in (
            b'{"app":{},"app":{}}',
            b'{"app":{"name":"one","name":"two"}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(DuplicateKeyError):
                parse_config_bytes(raw)

    def test_strict_json_rejects_invalid_utf8_trailing_data_and_constants(self) -> None:
        cases = (
            b'{"app":{}}\xff',
            b"{}{}",
            b'{"ui":{"scale_percent":NaN}}',
            b"\xef\xbb\xbf{}",
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(ConfigDecodeError):
                parse_config_bytes(raw)

    def test_size_limit_is_measured_before_decode(self) -> None:
        raw = b" " * (MAX_CONFIG_BYTES + 1)
        with self.assertRaises(ConfigTooLargeError) as raised:
            parse_config_bytes(raw)
        self.assertEqual(MAX_CONFIG_BYTES + 1, raised.exception.actual)

    def test_unknown_keys_are_rejected_at_every_namespace(self) -> None:
        cases = (
            ({"mystery": True}, "mystery"),
            ({"app": {"mystery": True}}, "app.mystery"),
            (
                {
                    "nodes": {
                        "items": [
                            {
                                "node_id": "synthetic",
                                "address": "192.0.2.1",
                                "mystery": True,
                            }
                        ]
                    }
                },
                "nodes.items[0].mystery",
            ),
        )
        for value, path in cases:
            with self.subTest(path=path), self.assertRaises(ConfigValidationError) as raised:
                config_from_dict(value)
            self.assertEqual(path, raised.exception.path)

    def test_bool_is_not_accepted_as_integer_and_strings_are_not_coerced(self) -> None:
        cases = (
            {"ui": {"scale_percent": True}},
            {"ui": {"scale_percent": "100"}},
            {"monitoring": {"enabled": 1}},
            {"app": None},
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ConfigValidationError):
                config_from_dict(value)

    def test_ranges_are_fail_closed(self) -> None:
        cases = (
            {"ui": {"scale_percent": 49}},
            {"rdp": {"port": 0}},
            {"remote": {"max_request_bytes": 1023}},
            {"update": {"check_interval_hours": 721}},
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ConfigValidationError):
                config_from_dict(value)

    def test_cross_field_rules_are_enforced(self) -> None:
        cases = (
            {"monitoring": {"interval_ms": 1_000, "stale_after_ms": 1_999}},
            {
                "cleanup": {
                    "graceful_timeout_seconds": 20,
                    "force_timeout_seconds": 19,
                }
            },
            {"ray": {"client_port": 8_265, "dashboard_port": 8_265}},
            {
                "ray": {
                    "enabled": True,
                    "executable_path": r"C:\Synthetic\ray.exe",
                    "head_address": "",
                }
            },
            {"remote": {"enabled": True, "bind_host": "0.0.0.0"}},
            {"update": {"enabled": True, "manifest_url": "http://192.0.2.1/a"}},
            {
                "nodes": {
                    "items": [
                        {"node_id": "alpha", "address": "192.0.2.1"},
                        {"node_id": "ALPHA", "address": "192.0.2.2"},
                    ]
                }
            },
            {
                "nodes": {
                    "items": [{"node_id": "alpha", "address": "192.0.2.1"}],
                    "local_node_id": "missing",
                }
            },
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ConfigValidationError):
                config_from_dict(value)

    def test_safe_cross_field_values_are_accepted(self) -> None:
        config = config_from_dict(
            {
                "monitoring": {"interval_ms": 500, "stale_after_ms": 1_000},
                "nodes": {
                    "items": [
                        {
                            "node_id": "example-head",
                            "address": "192.0.2.10",
                            "role": "head",
                            "cpu_count": 4,
                        }
                    ],
                    "local_node_id": "EXAMPLE-HEAD",
                },
                "ray": {
                    "enabled": True,
                    "executable_path": (
                        r"C:\Synthetic\Python312\Scripts\ray.exe"
                    ),
                    "head_address": "192.0.2.10",
                },
                "remote": {"enabled": True, "bind_host": "::1"},
                "update": {
                    "enabled": True,
                    "manifest_url": "https://192.0.2.1/manifest.json",
                },
            }
        )

        self.assertEqual("example-head", config.nodes.items[0].node_id)
        self.assertTrue(config.ray.enabled)
        self.assertEqual(
            r"C:\Synthetic\Python312\Scripts\ray.exe",
            config.ray.executable_path,
        )
        self.assertEqual(config, config_from_dict(config_to_dict(config)))
        self.assertTrue(config.remote.enabled)
        self.assertTrue(config.update.enabled)

    def test_ray_executable_path_is_absolute_local_and_exact(self) -> None:
        rejected = (
            "ray.exe",
            r".\ray.exe",
            r"C:\Synthetic\..\ray.exe",
            "\\" * 2 + r"synthetic\share\ray.exe",
            "\\" * 2 + r"?\C:\Synthetic\ray.exe",
            "\\" * 2 + r".\C:\Synthetic\ray.exe",
            r"\??\C:\Synthetic\ray.exe",
            r"\Device\HarddiskVolume1\ray.exe",
            r"C:\Synthetic\ray.exe:alternate",
            r"C:\Synthetic\python.exe",
            "C:\\Synthetic\\ray.exe\n",
        )
        for executable_path in rejected:
            with (
                self.subTest(executable_path=executable_path),
                self.assertRaises(ConfigValidationError),
            ):
                config_from_dict({"ray": {"executable_path": executable_path}})

        legacy_2x = config_from_dict({
            "ray": {
                "enabled": True,
                "head_address": "192.0.2.10",
            }
        })
        self.assertTrue(legacy_2x.ray.enabled)
        self.assertEqual("", legacy_2x.ray.executable_path)

    def test_direct_dataclass_construction_is_revalidated_before_encoding(self) -> None:
        invalid = Config(
            nodes=NodesSection(
                items=(
                    Node(node_id="duplicate", address="192.0.2.1"),
                    Node(node_id="DUPLICATE", address="192.0.2.2"),
                )
            )
        )
        with self.assertRaises(ConfigValidationError):
            canonical_config_bytes(invalid)

        invalid_cleanup = Config(
            cleanup=CleanupSection(
                graceful_timeout_seconds=30,
                force_timeout_seconds=10,
            )
        )
        with self.assertRaises(ConfigValidationError):
            canonical_config_bytes(invalid_cleanup)

    def test_credential_values_and_embedded_url_credentials_are_not_schema_fields(self) -> None:
        with self.assertRaises(ConfigValidationError):
            config_from_dict({"rdp": {"password": None}})
        with self.assertRaises(ConfigValidationError):
            config_from_dict(
                {
                    "update": {
                        "enabled": True,
                        "manifest_url": (
                            "https://synthetic-user:"
                            "synthetic-test-value@192.0.2.1/manifest"
                        ),
                    }
                }
            )

    def test_secret_bearing_credential_references_and_update_urls_are_rejected(
        self,
    ) -> None:
        rejected_references = (
            "credential://",
            "credential://user:synthetic-test-value@vault",
            "credential://vault?access_token=synthetic-test-value",
            "credential://vault#synthetic-test-value",
            "credential://vault%2Fsynthetic-test-value",
            "credential://vault\\synthetic-test-value",
            "credential://vault\nsynthetic-test-value",
        )
        for reference in rejected_references:
            with self.subTest(reference=reference):
                with self.assertRaises(ConfigValidationError):
                    config_from_dict(
                        {"rdp": {"credential_reference": reference}}
                    )
        accepted = config_from_dict(
            {
                "rdp": {
                    "credential_reference": (
                        "credential://synthetic-store/worker_01"
                    )
                }
            }
        )
        self.assertEqual(
            "credential://synthetic-store/worker_01",
            accepted.rdp.credential_reference,
        )

        for enabled in (False, True):
            with self.subTest(update_enabled=enabled):
                with self.assertRaises(ConfigValidationError):
                    config_from_dict(
                        {
                            "update": {
                                "enabled": enabled,
                                "manifest_url": (
                                    "https://example.com/manifest"
                                    "?access_token=synthetic-test-value"
                                ),
                            }
                        }
                    )

    def test_canonical_output_is_compact_and_valid_json(self) -> None:
        raw = canonical_config_bytes(default_config())
        self.assertNotIn(b"\n", raw)
        self.assertNotIn(b": ", raw)
        self.assertEqual(config_to_dict(default_config()), json.loads(raw))

    def test_direct_invalid_section_values_are_rejected(self) -> None:
        with self.assertRaises(ConfigValidationError):
            canonical_config_bytes(Config(remote=RemoteSection(enabled=True, bind_host="example.invalid")))
        with self.assertRaises(ConfigValidationError):
            canonical_config_bytes(
                Config(update=UpdateSection(enabled=True, manifest_url=""))
            )


if __name__ == "__main__":
    unittest.main()
