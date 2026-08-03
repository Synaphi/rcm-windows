"""Strict, side-effect-free migration from the frozen RCM 1.x schema.

The importer is a planner: it never opens or writes a file and never mutates
the supplied bytes or mapping.  Successful plans separate public 2.x
configuration from machine/user-local overlay data.  Values that have no 2.x
home are represented by deterministic, value-free ``UnmappedField`` entries
instead of being silently discarded.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import ipaddress
import math
from typing import TypeAlias

from ..paths import absolute_local_path, safe_relative_path
from .schema import (
    MAX_CONFIG_BYTES,
    Config,
    ConfigDecodeError,
    ConfigTooLargeError,
    ConfigValidationError,
    Node,
    NodesSection,
    canonical_json_bytes,
    config_from_dict,
    config_to_dict,
    credential_reference_is_valid,
    decode_json_bytes,
    default_config,
)


MIN_LEGACY_SCHEMA = 0
MAX_LEGACY_SCHEMA = 15

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class MigrationError(Exception):
    """Base class for safe migration failures."""


class MigrationDecodeError(MigrationError):
    """Legacy input is not one accepted strict JSON document."""


class MigrationValidationError(MigrationError):
    """Legacy input does not satisfy the supported 1.x contract."""


class SecretMaterialError(MigrationValidationError):
    """Raw secret material was found where only references are allowed."""

    def __init__(self) -> None:
        super().__init__(
            "legacy configuration contains forbidden raw secret material"
        )


class NewerLegacySchemaError(MigrationValidationError):
    """The source belongs to a newer schema and must remain read-only."""

    read_only = True

    def __init__(self, schema_version: int) -> None:
        self.schema_version = schema_version
        super().__init__(
            "legacy schema is newer than the supported read-only boundary"
        )


class V1ImportProjectionError(MigrationValidationError):
    """A supported legacy document cannot be represented safely by 2.x."""

    def __init__(self, source_path: str, reason: str) -> None:
        self.source_path = source_path
        self.reason = reason
        super().__init__(f"legacy import rejected at {source_path}: {reason}")

    def __repr__(self) -> str:
        return (
            "V1ImportProjectionError("
            f"source_path={self.source_path!r}, reason={self.reason!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OverlayEntry:
    """One local-only value, stored canonically and redacted from repr."""

    path: str
    _canonical_value: bytes

    @classmethod
    def create(cls, path: str, value: object) -> "OverlayEntry":
        return cls(path=path, _canonical_value=canonical_json_bytes(value))

    def value(self) -> object:
        """Return a detached JSON value."""

        return decode_json_bytes(
            self._canonical_value,
            max_bytes=max(1, len(self._canonical_value)),
        )

    def __repr__(self) -> str:
        return f"OverlayEntry(path={self.path!r}, value=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class LocalOverlay:
    """Private/local values intentionally excluded from public ``Config``."""

    topology: tuple[OverlayEntry, ...] = ()
    per_user_ui: tuple[OverlayEntry, ...] = ()
    trust: tuple[OverlayEntry, ...] = ()
    controller_lists: tuple[OverlayEntry, ...] = ()
    update_paths: tuple[OverlayEntry, ...] = ()
    credential_references: tuple[OverlayEntry, ...] = ()
    legacy_passthrough: tuple[OverlayEntry, ...] = ()

    def __repr__(self) -> str:
        counts = {
            "topology": len(self.topology),
            "per_user_ui": len(self.per_user_ui),
            "trust": len(self.trust),
            "controller_lists": len(self.controller_lists),
            "update_paths": len(self.update_paths),
            "credential_references": len(self.credential_references),
            "legacy_passthrough": len(self.legacy_passthrough),
        }
        return f"LocalOverlay(counts={counts!r}, values=<redacted>)"


@dataclass(frozen=True, slots=True)
class MigrationDiff:
    """Value-free, sanitized mapping from a legacy path to a 2.x path."""

    source_path: str
    target_path: str
    action: str


@dataclass(frozen=True, slots=True)
class UnmappedField:
    """A supported source field with no semantically equivalent 2.x field."""

    source_path: str
    reason: str


@dataclass(frozen=True, slots=True, repr=False)
class MigrationPlan:
    """Immutable copy-convert result."""

    source_schema: int
    config: Config
    local_overlay: LocalOverlay
    diff: tuple[MigrationDiff, ...]
    unmapped_fields: tuple[UnmappedField, ...]

    @property
    def lossless(self) -> bool:
        """Every accepted source path is mapped or explicitly unmapped."""

        unmapped_paths = {
            item.source_path for item in self.unmapped_fields
        }
        passthrough_paths = {
            item.path for item in self.local_overlay.legacy_passthrough
        }
        return (
            len(unmapped_paths) == len(self.unmapped_fields)
            and len(passthrough_paths)
            == len(self.local_overlay.legacy_passthrough)
            and unmapped_paths == passthrough_paths
        )

    def __repr__(self) -> str:
        return (
            "MigrationPlan("
            f"source_schema={self.source_schema}, "
            "config=<typed>, local_overlay=<redacted>, "
            f"diff_count={len(self.diff)}, "
            f"unmapped_count={len(self.unmapped_fields)})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class V1ImportProjection:
    """Typed, value-redacted projection of one legacy plan onto 2.x state."""

    source_schema: int
    config: Config
    mapped_fields: tuple[MigrationDiff, ...]
    skipped_fields: tuple[UnmappedField, ...]
    rejected_fields: tuple[UnmappedField, ...]

    @property
    def unmapped_fields(self) -> tuple[UnmappedField, ...]:
        """Compatibility name for benign fields skipped by the projection."""

        return self.skipped_fields

    def __repr__(self) -> str:
        return (
            "V1ImportProjection("
            f"source_schema={self.source_schema}, config=<typed-redacted>, "
            f"mapped_count={len(self.mapped_fields)}, "
            f"skipped_count={len(self.skipped_fields)}, "
            f"rejected_count={len(self.rejected_fields)})"
        )


_ROOT_FIELDS = {
    "schema_version",
    "head_ip",
    "head_port",
    "dashboard_port",
    "ray_exe",
    "this",
    "nodes",
    "credential_controller_ips",
    "update_controller_ips",
    "cluster_controller_ips",
    "trusted_controller_ids",
    "credential_references",
    "official_exe_path",
    "cluster_manifest_path",
    "cluster_epoch",
    "poll_interval",
    "dashboard_timeout_sec",
    "dashboard_unreachable_failures",
    "dashboard_stale_grace_sec",
    "theme",
    "on_close",
    "stop_on_quit",
    "start_on_launch",
    "autostart_login",
    "temp_enabled",
    "temp_warn_c",
    "temp_critical_c",
    "temp_auto_pause",
    "temp_port",
    "temp_poll_sec",
    "metrics_enabled",
    "metrics_timeout_sec",
    "node_row_mode",
    "diagnostic_font",
    "process_cleanup",
    "ui_scale_mode",
    "ui_scaling",
    "main_width",
    "os_cpu_warn_pct",
    "os_cpu_critical_pct",
    "ram_warn_pct",
    "ram_critical_pct",
    "disk_warn_pct",
    "disk_critical_pct",
    "ray_worker_fixed_ports",
    "ray_worker_node_manager_port",
    "ray_worker_object_manager_port",
    "ray_worker_runtime_env_agent_port",
    "ray_worker_dashboard_agent_grpc_port",
    "ray_worker_dashboard_agent_listen_port",
    "ray_worker_metrics_export_port",
    "ray_worker_min_port",
    "ray_worker_max_port",
    "head_whoami",
    "watchdog_enabled",
    "watchdog_interval_sec",
    "watchdog_stale_cycles",
    "head_dashboard_guard_enabled",
    "head_dashboard_guard_interval_sec",
    "head_dashboard_guard_cycles",
}

_THIS_FIELDS = {"role", "mode", "ip", "num_cpus"}
_NODE_FIELDS = {
    "name",
    "ip",
    "address",
    "role",
    "mode",
    "num_cpus",
    "enabled",
    "rdp_user",
    "credential_reference",
}
_PROCESS_CLEANUP_FIELDS = {
    "sample_sec",
    "grace_sec",
    "result_max_age_sec",
    "ignored_fingerprints",
}

_TOPOLOGY_FIELDS = (
    "head_ip",
    "head_port",
    "dashboard_port",
    "ray_exe",
    "this",
    "cluster_manifest_path",
    "cluster_epoch",
    "ray_worker_fixed_ports",
    "ray_worker_node_manager_port",
    "ray_worker_object_manager_port",
    "ray_worker_runtime_env_agent_port",
    "ray_worker_dashboard_agent_grpc_port",
    "ray_worker_dashboard_agent_listen_port",
    "ray_worker_metrics_export_port",
    "ray_worker_min_port",
    "ray_worker_max_port",
    "head_whoami",
)
_PER_LOCAL_UI_FIELDS = (
    "theme",
    "on_close",
    "stop_on_quit",
    "start_on_launch",
    "autostart_login",
    "node_row_mode",
    "diagnostic_font",
    "ui_scale_mode",
    "ui_scaling",
    "main_width",
)
_CONTROLLER_FIELDS = (
    "credential_controller_ips",
    "update_controller_ips",
    "cluster_controller_ips",
)
_UPDATE_PATH_FIELDS = ("official_exe_path",)
_CREDENTIAL_REFERENCE_KEYS = {
    "credential_reference",
    "credential_references",
}
_RAW_SECRET_KEYS = {
    "api_key",
    "client_secret",
    "credential",
    "credential_value",
    "credentials",
    "password",
    "passwd",
    "private_key",
    "privatekey",
    "refresh_token",
    "secret",
    "token",
    "access_token",
}
_PRIVATE_KEY_MARKERS = tuple(
    "-----BEGIN "
    + (f"{prefix} " if prefix else "")
    + "PRIVATE KEY-----"
    for prefix in ("", "RSA", "EC", "OPENSSH")
)

_STRING_ROOT_FIELDS = {
    "ray_exe",
    "cluster_manifest_path",
    "theme",
    "on_close",
    "node_row_mode",
    "diagnostic_font",
    "ui_scale_mode",
    "ui_scaling",
    "official_exe_path",
    "head_whoami",
}
_BOOLEAN_ROOT_FIELDS = {
    "stop_on_quit",
    "start_on_launch",
    "autostart_login",
    "temp_enabled",
    "temp_auto_pause",
    "metrics_enabled",
    "ray_worker_fixed_ports",
    "watchdog_enabled",
    "head_dashboard_guard_enabled",
}
_INTEGER_ROOT_RANGES = {
    "head_port": (1, 65_535),
    "dashboard_port": (1, 65_535),
    "cluster_epoch": (0, (1 << 63) - 1),
    "dashboard_unreachable_failures": (1, 10_000),
    "temp_warn_c": (-100, 1_000),
    "temp_critical_c": (-100, 1_000),
    "temp_port": (1, 65_535),
    "main_width": (0, 100_000),
    "os_cpu_warn_pct": (0, 100),
    "os_cpu_critical_pct": (0, 100),
    "ram_warn_pct": (0, 100),
    "ram_critical_pct": (0, 100),
    "disk_warn_pct": (0, 100),
    "disk_critical_pct": (0, 100),
    "ray_worker_node_manager_port": (1, 65_535),
    "ray_worker_object_manager_port": (1, 65_535),
    "ray_worker_runtime_env_agent_port": (1, 65_535),
    "ray_worker_dashboard_agent_grpc_port": (1, 65_535),
    "ray_worker_dashboard_agent_listen_port": (1, 65_535),
    "ray_worker_metrics_export_port": (1, 65_535),
    "ray_worker_min_port": (1, 65_535),
    "ray_worker_max_port": (1, 65_535),
    "watchdog_interval_sec": (1, 86_400),
    "watchdog_stale_cycles": (1, 10_000),
    "head_dashboard_guard_interval_sec": (1, 86_400),
    "head_dashboard_guard_cycles": (1, 10_000),
}
_NUMBER_ROOT_RANGES = {
    "poll_interval": (0.25, 60.0),
    "dashboard_timeout_sec": (0.0, 3_600.0),
    "dashboard_stale_grace_sec": (0.5, 300.0),
    "temp_poll_sec": (0.0, 3_600.0),
    "metrics_timeout_sec": (0.0, 3_600.0),
}

_UNMAPPED_ROOT_REASONS = {
    "dashboard_timeout_sec": "no-equivalent-public-field",
    "dashboard_unreachable_failures": "no-equivalent-public-field",
    "temp_enabled": "temperature-service-not-yet-extracted",
    "temp_warn_c": "temperature-service-not-yet-extracted",
    "temp_critical_c": "temperature-service-not-yet-extracted",
    "temp_auto_pause": "temperature-service-not-yet-extracted",
    "temp_port": "temperature-service-not-yet-extracted",
    "temp_poll_sec": "temperature-service-not-yet-extracted",
    "metrics_timeout_sec": "monitoring-timeout-not-in-public-schema",
    "os_cpu_warn_pct": "threshold-schema-not-yet-extracted",
    "os_cpu_critical_pct": "threshold-schema-not-yet-extracted",
    "ram_warn_pct": "threshold-schema-not-yet-extracted",
    "ram_critical_pct": "threshold-schema-not-yet-extracted",
    "disk_warn_pct": "threshold-schema-not-yet-extracted",
    "disk_critical_pct": "threshold-schema-not-yet-extracted",
    "watchdog_enabled": "watchdog-service-not-yet-extracted",
    "watchdog_interval_sec": "watchdog-service-not-yet-extracted",
    "watchdog_stale_cycles": "watchdog-service-not-yet-extracted",
    "head_dashboard_guard_enabled": "dashboard-guard-not-yet-extracted",
    "head_dashboard_guard_interval_sec": "dashboard-guard-not-yet-extracted",
    "head_dashboard_guard_cycles": "dashboard-guard-not-yet-extracted",
}


def _validation_error(message: str) -> MigrationValidationError:
    return MigrationValidationError(message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _validation_error("legacy configuration must be an object")
    if any(not isinstance(key, str) for key in value):
        raise _validation_error("legacy object keys must be strings")
    return value


def _known_fields(
    value: Mapping[str, object],
    allowed: set[str],
) -> None:
    if set(value) - allowed:
        raise _validation_error(
            "legacy configuration contains unsupported fields"
        )


def _contains_secret_key(key: str) -> bool:
    normalized = key.strip().casefold().replace("-", "_")
    if normalized in _CREDENTIAL_REFERENCE_KEYS:
        return False
    if normalized in _RAW_SECRET_KEYS:
        return True
    compact = normalized.replace("_", "")
    return any(
        marker in compact
        for marker in (
            "password",
            "passwd",
            "privatekey",
            "credentialvalue",
            "credentials",
            "apikey",
            "token",
            "secret",
        )
    )


def _reject_secret_material(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _validation_error(
                    "legacy object keys must be strings"
                )
            if _contains_secret_key(key):
                raise SecretMaterialError()
            _reject_secret_material(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_secret_material(child)
    elif isinstance(value, str):
        folded = value.upper()
        if any(marker in folded for marker in _PRIVATE_KEY_MARKERS):
            raise SecretMaterialError()


def _decode_source(source: bytes | Mapping[str, object]) -> Mapping[str, object]:
    if isinstance(source, bytes):
        try:
            decoded = decode_json_bytes(source, max_bytes=MAX_CONFIG_BYTES)
        except (ConfigDecodeError, ConfigTooLargeError):
            raise MigrationDecodeError(
                "legacy input is not one accepted strict JSON document"
            ) from None
    elif isinstance(source, Mapping):
        try:
            encoded = canonical_json_bytes(source)
        except ConfigDecodeError:
            raise MigrationDecodeError(
                "legacy input is not JSON-compatible"
            ) from None
        if len(encoded) > MAX_CONFIG_BYTES:
            raise MigrationDecodeError(
                "legacy input exceeds the migration size limit"
            )
        try:
            decoded = decode_json_bytes(encoded, max_bytes=MAX_CONFIG_BYTES)
        except ConfigDecodeError:
            raise MigrationDecodeError(
                "legacy input is not one accepted strict JSON document"
            ) from None
    else:
        raise TypeError("source must be bytes or a mapping")
    return _mapping(decoded)


def _schema_version(root: Mapping[str, object]) -> int:
    value = root.get("schema_version", 0)
    if type(value) is not int:
        raise _validation_error("legacy schema_version must be an integer")
    if value > MAX_LEGACY_SCHEMA:
        raise NewerLegacySchemaError(value)
    if value < MIN_LEGACY_SCHEMA:
        raise _validation_error("legacy schema_version is outside 0..15")
    return value


def _boolean(value: object, field: str) -> bool:
    if type(value) is not bool:
        raise _validation_error(f"{field} must be a boolean")
    return value


def _number(
    value: object,
    field: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    if type(value) not in (int, float):
        raise _validation_error(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise _validation_error(f"{field} is outside its supported range")
    return result


def _integer(
    value: object,
    field: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        raise _validation_error(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise _validation_error(f"{field} is outside its supported range")
    return value


def _string(value: object, field: str, *, maximum: int = 2_048) -> str:
    if not isinstance(value, str):
        raise _validation_error(f"{field} must be a string")
    if len(value) > maximum or any(ord(character) < 0x20 for character in value):
        raise _validation_error(f"{field} is not an accepted string")
    return value


def _string_list(
    value: object,
    field: str,
    *,
    maximum_items: int = 4_096,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise _validation_error(f"{field} must be a bounded array")
    return [
        _string(item, f"{field}[]", maximum=256)
        for item in value
    ]


def _validate_nested(root: Mapping[str, object]) -> None:
    _known_fields(root, _ROOT_FIELDS)

    if "head_ip" in root:
        _ip_address(root["head_ip"], "head_ip", allow_empty=True)

    for key in _STRING_ROOT_FIELDS:
        if key in root:
            _string(root[key], key)
    for key in ("cluster_manifest_path", "official_exe_path"):
        if key in root:
            _local_path(root[key], key)
    for key in _BOOLEAN_ROOT_FIELDS:
        if key in root:
            _boolean(root[key], key)
    for key, (minimum, maximum) in _INTEGER_ROOT_RANGES.items():
        if key in root:
            _integer(
                root[key],
                key,
                minimum=minimum,
                maximum=maximum,
            )
    for key, (minimum, maximum) in _NUMBER_ROOT_RANGES.items():
        if key in root:
            _number(
                root[key],
                key,
                minimum=minimum,
                maximum=maximum,
            )

    if "this" in root:
        this = _mapping(root["this"])
        _known_fields(this, _THIS_FIELDS)
        for key in ("role", "mode"):
            if key in this:
                _string(this[key], f"this.{key}", maximum=64)
        if "ip" in this:
            _ip_address(
                this["ip"],
                "this.ip",
                allow_empty=True,
                allow_auto=True,
            )
        if "num_cpus" in this:
            _cpu_count(this["num_cpus"], "this.num_cpus")

    if "nodes" in root:
        nodes = root["nodes"]
        if not isinstance(nodes, list) or len(nodes) > 4_096:
            raise _validation_error("nodes must be a bounded array")
        for node in nodes:
            item = _mapping(node)
            _known_fields(item, _NODE_FIELDS)
            for key in ("name", "ip", "address", "role", "mode", "rdp_user"):
                if key in item:
                    _string(item[key], f"nodes[].{key}", maximum=253)
            if "ip" in item:
                _ip_address(item["ip"], "nodes[].ip", allow_empty=False)
            if "address" in item:
                _ip_address(
                    item["address"],
                    "nodes[].address",
                    allow_empty=False,
                )
            if "credential_reference" in item:
                _credential_reference(
                    item["credential_reference"],
                    "nodes[].credential_reference",
                )
            if "num_cpus" in item:
                _cpu_count(item["num_cpus"], "nodes[].num_cpus")
            if "enabled" in item:
                _boolean(item["enabled"], "nodes[].enabled")

    if "process_cleanup" in root:
        cleanup = _mapping(root["process_cleanup"])
        _known_fields(cleanup, _PROCESS_CLEANUP_FIELDS)
        for key in ("sample_sec", "grace_sec", "result_max_age_sec"):
            if key in cleanup:
                _number(
                    cleanup[key],
                    f"process_cleanup.{key}",
                    minimum=0.0,
                    maximum=86_400.0,
                )
        if "ignored_fingerprints" in cleanup:
            _string_list(
                cleanup["ignored_fingerprints"],
                "process_cleanup.ignored_fingerprints",
            )

    for key in _CONTROLLER_FIELDS:
        if key in root:
            for address in _string_list(root[key], key):
                _ip_address(address, f"{key}[]", allow_empty=False)
    if "trusted_controller_ids" in root:
        _string_list(root["trusted_controller_ids"], "trusted_controller_ids")
    if "credential_references" in root:
        references = _string_list(
            root["credential_references"],
            "credential_references",
        )
        for reference in references:
            _credential_reference(reference, "credential_references[]")

def _credential_reference(value: object, field: str) -> str:
    result = _string(value, field, maximum=256)
    if not credential_reference_is_valid(result):
        raise _validation_error(
            f"{field} must use an opaque credential reference"
        )
    return result


def _ip_address(
    value: object,
    field: str,
    *,
    allow_empty: bool,
    allow_auto: bool = False,
) -> str:
    result = _string(value, field, maximum=253)
    if not result and allow_empty:
        return result
    if result == "auto" and allow_auto:
        return result
    try:
        ipaddress.ip_address(result)
    except ValueError:
        raise _validation_error(f"{field} must be an IP address") from None
    return result


def _cpu_count(value: object, field: str) -> int | str:
    if isinstance(value, str):
        if value != "auto":
            raise _validation_error(
                f"{field} must be an integer or the auto sentinel"
            )
        return value
    return _integer(value, field, minimum=0, maximum=65_536)


def _local_path(value: object, field: str) -> str:
    result = _string(value, field)
    if not result:
        return result
    try:
        safe_relative_path(result, label=field)
        return result
    except (TypeError, ValueError):
        pass
    try:
        absolute_local_path(result, label=field)
    except (TypeError, ValueError):
        raise _validation_error(
            f"{field} must be a local path without traversal"
        ) from None
    return result


def _entry(path: str, value: object) -> OverlayEntry:
    return OverlayEntry.create(path, value)


def _sorted_entries(entries: list[OverlayEntry]) -> tuple[OverlayEntry, ...]:
    return tuple(sorted(entries, key=lambda item: item.path))


def _public_candidate(
    root: Mapping[str, object],
) -> tuple[Config, list[MigrationDiff], list[UnmappedField]]:
    candidate = config_to_dict(default_config())
    monitoring = candidate["monitoring"]
    cleanup = candidate["cleanup"]
    assert isinstance(monitoring, dict)
    assert isinstance(cleanup, dict)
    diff: list[MigrationDiff] = []
    unmapped: list[UnmappedField] = []

    if "metrics_enabled" in root:
        monitoring["enabled"] = _boolean(
            root["metrics_enabled"],
            "metrics_enabled",
        )
        diff.append(
            MigrationDiff(
                "metrics_enabled",
                "config.monitoring.enabled",
                "copied",
            )
        )

    interval_ms = int(monitoring["interval_ms"])
    if "poll_interval" in root:
        seconds = _number(
            root["poll_interval"],
            "poll_interval",
            minimum=0.25,
            maximum=60.0,
        )
        milliseconds = seconds * 1_000
        if not milliseconds.is_integer():
            raise _validation_error(
                "poll_interval must resolve to whole milliseconds"
            )
        interval_ms = int(milliseconds)
        monitoring["interval_ms"] = interval_ms
        diff.append(
            MigrationDiff(
                "poll_interval",
                "config.monitoring.interval_ms",
                "converted-seconds-to-milliseconds",
            )
        )

    if "dashboard_stale_grace_sec" in root:
        seconds = _number(
            root["dashboard_stale_grace_sec"],
            "dashboard_stale_grace_sec",
            minimum=0.5,
            maximum=300.0,
        )
        milliseconds = seconds * 1_000
        if not milliseconds.is_integer():
            raise _validation_error(
                "dashboard_stale_grace_sec must resolve to whole milliseconds"
            )
        monitoring["stale_after_ms"] = max(
            int(milliseconds),
            interval_ms * 2,
        )
        diff.append(
            MigrationDiff(
                "dashboard_stale_grace_sec",
                "config.monitoring.stale_after_ms",
                "converted-seconds-to-milliseconds",
            )
        )
    elif int(monitoring["stale_after_ms"]) < interval_ms * 2:
        monitoring["stale_after_ms"] = interval_ms * 2

    if "process_cleanup" in root:
        raw_cleanup = _mapping(root["process_cleanup"])
        if "grace_sec" in raw_cleanup:
            grace = _number(
                raw_cleanup["grace_sec"],
                "process_cleanup.grace_sec",
                minimum=0.0,
                maximum=3_600.0,
            )
            if grace.is_integer():
                cleanup["graceful_timeout_seconds"] = int(grace)
                cleanup["force_timeout_seconds"] = max(30, int(grace))
                diff.append(
                    MigrationDiff(
                        "process_cleanup.grace_sec",
                        "config.cleanup.graceful_timeout_seconds",
                        "copied",
                    )
                )
            else:
                unmapped.append(
                    UnmappedField(
                        "process_cleanup.grace_sec",
                        "fractional-timeout-has-no-equivalent",
                    )
                )
        for key in (
            "sample_sec",
            "result_max_age_sec",
            "ignored_fingerprints",
        ):
            if key in raw_cleanup:
                unmapped.append(
                    UnmappedField(
                        f"process_cleanup.{key}",
                        "no-equivalent-public-field",
                    )
                )

    for path, reason in _UNMAPPED_ROOT_REASONS.items():
        if path in root:
            unmapped.append(UnmappedField(path, reason))

    return (
        config_from_dict(candidate),
        diff,
        unmapped,
    )


def _local_overlay(
    root: Mapping[str, object],
) -> tuple[LocalOverlay, list[MigrationDiff], list[UnmappedField]]:
    topology: list[OverlayEntry] = []
    per_user_ui: list[OverlayEntry] = []
    trust: list[OverlayEntry] = []
    controllers: list[OverlayEntry] = []
    update_paths: list[OverlayEntry] = []
    credentials: list[OverlayEntry] = []
    diff: list[MigrationDiff] = []
    unmapped: list[UnmappedField] = []

    for path in _TOPOLOGY_FIELDS:
        if path in root:
            topology.append(_entry(path, root[path]))
            diff.append(
                MigrationDiff(path, f"local.topology.{path}", "copied")
            )

    if "nodes" in root:
        sanitized_nodes: list[dict[str, object]] = []
        node_references: list[str] = []
        has_rdp_user = False
        for raw_node in root["nodes"]:
            node = _mapping(raw_node)
            sanitized: dict[str, object] = {}
            for key in sorted(_NODE_FIELDS - {"rdp_user", "credential_reference"}):
                if key in node:
                    sanitized[key] = node[key]
            if "rdp_user" in node:
                has_rdp_user = True
            if "credential_reference" in node:
                node_references.append(
                    _credential_reference(
                        node["credential_reference"],
                        "nodes[].credential_reference",
                    )
                )
            sanitized_nodes.append(sanitized)
        topology.append(_entry("nodes", sanitized_nodes))
        diff.append(MigrationDiff("nodes", "local.topology.nodes", "copied"))
        if has_rdp_user:
            unmapped.append(
                UnmappedField(
                    "nodes[].rdp_user",
                    "legacy-user-name-requires-credential-store-adoption",
                )
            )
        if node_references:
            credentials.append(
                _entry("nodes[].credential_reference", node_references)
            )
            diff.append(
                MigrationDiff(
                    "nodes[].credential_reference",
                    "local.credential_references.nodes[]",
                    "copied-reference-only",
                )
            )

    for path in _PER_LOCAL_UI_FIELDS:
        if path in root:
            per_user_ui.append(_entry(path, root[path]))
            diff.append(
                MigrationDiff(path, f"local.per_user_ui.{path}", "copied")
            )

    if "trusted_controller_ids" in root:
        trust.append(
            _entry("trusted_controller_ids", root["trusted_controller_ids"])
        )
        diff.append(
            MigrationDiff(
                "trusted_controller_ids",
                "local.trust.trusted_controller_ids",
                "copied",
            )
        )

    for path in _CONTROLLER_FIELDS:
        if path in root:
            controllers.append(_entry(path, root[path]))
            diff.append(
                MigrationDiff(
                    path,
                    f"local.controller_lists.{path}",
                    "copied",
                )
            )

    for path in _UPDATE_PATH_FIELDS:
        if path in root:
            update_paths.append(_entry(path, root[path]))
            diff.append(
                MigrationDiff(path, f"local.update_paths.{path}", "copied")
            )

    if "credential_references" in root:
        references = [
            _credential_reference(item, "credential_references[]")
            for item in root["credential_references"]
        ]
        credentials.append(_entry("credential_references", references))
        diff.append(
            MigrationDiff(
                "credential_references",
                "local.credential_references",
                "copied-reference-only",
            )
        )

    return (
        LocalOverlay(
            topology=_sorted_entries(topology),
            per_user_ui=_sorted_entries(per_user_ui),
            trust=_sorted_entries(trust),
            controller_lists=_sorted_entries(controllers),
            update_paths=_sorted_entries(update_paths),
            credential_references=_sorted_entries(credentials),
        ),
        diff,
        unmapped,
    )


def _passthrough_value(
    root: Mapping[str, object],
    source_path: str,
) -> object:
    if source_path.startswith("process_cleanup."):
        cleanup = _mapping(root["process_cleanup"])
        key = source_path.split(".", 1)[1]
        return cleanup[key]
    if source_path == "nodes[].rdp_user":
        values: list[dict[str, object]] = []
        for index, raw_node in enumerate(root["nodes"]):
            node = _mapping(raw_node)
            if "rdp_user" in node:
                values.append(
                    {"index": index, "value": node["rdp_user"]}
                )
        return values
    return root[source_path]


def _attach_legacy_passthrough(
    root: Mapping[str, object],
    overlay: LocalOverlay,
    unmapped: tuple[UnmappedField, ...],
) -> LocalOverlay:
    passthrough = _sorted_entries(
        [
            _entry(
                item.source_path,
                _passthrough_value(root, item.source_path),
            )
            for item in unmapped
        ]
    )
    return LocalOverlay(
        topology=overlay.topology,
        per_user_ui=overlay.per_user_ui,
        trust=overlay.trust,
        controller_lists=overlay.controller_lists,
        update_paths=overlay.update_paths,
        credential_references=overlay.credential_references,
        legacy_passthrough=passthrough,
    )


def plan_v1_migration(
    source: bytes | Mapping[str, object],
) -> MigrationPlan:
    """Create a strict schema-0-through-15 copy-convert plan."""

    root = _decode_source(source)
    _reject_secret_material(root)
    source_schema = _schema_version(root)
    _validate_nested(root)

    config, public_diff, public_unmapped = _public_candidate(root)
    overlay, local_diff, local_unmapped = _local_overlay(root)
    diff = public_diff + local_diff
    if "schema_version" in root:
        diff.append(
            MigrationDiff(
                "schema_version",
                "migration.source_schema",
                "recorded",
            )
        )

    unmapped_fields = tuple(
        sorted(
            set(public_unmapped + local_unmapped),
            key=lambda item: (item.source_path, item.reason),
        )
    )
    overlay = _attach_legacy_passthrough(
        root,
        overlay,
        unmapped_fields,
    )

    return MigrationPlan(
        source_schema=source_schema,
        config=config,
        local_overlay=overlay,
        diff=tuple(
            sorted(
                set(diff),
                key=lambda item: (
                    item.source_path,
                    item.target_path,
                    item.action,
                ),
            )
        ),
        unmapped_fields=unmapped_fields,
    )


def _projection_entries(
    entries: tuple[OverlayEntry, ...],
) -> dict[str, object]:
    return {entry.path: entry.value() for entry in entries}


def _projection_reject(source_path: str, reason: str) -> None:
    raise V1ImportProjectionError(source_path, reason)


def _project_cpu_count(
    value: object,
    *,
    source_schema: int,
    source_path: str,
) -> int:
    if value == "auto":
        return 0
    if type(value) is not int:
        _projection_reject(source_path, "cpu-invalid")
    if value == 0 and source_schema >= 14:
        _projection_reject(
            source_path,
            "driver-zero-ambiguous",
        )
    return value


def _validate_projected_mode(
    value: object,
    *,
    source_path: str,
    allow_auto: bool,
) -> None:
    if not isinstance(value, str):
        _projection_reject(source_path, "mode-invalid")
    normalized = value.strip().casefold()
    if normalized in {"controller", "rdp", "rdp-client"}:
        _projection_reject(source_path, "retired-remote-mode")
    allowed = {"", "ray"}
    if allow_auto:
        allowed.add("auto")
    if normalized not in allowed:
        _projection_reject(source_path, "mode-invalid")


def _project_nodes(
    raw_nodes: object,
    *,
    source_schema: int,
) -> tuple[Node, ...]:
    if not isinstance(raw_nodes, list):
        _projection_reject("nodes", "nodes-not-array")
    projected: list[Node] = []
    identifiers: set[str] = set()
    addresses: set[tuple[int, int]] = set()
    head_count = 0
    for raw_node in raw_nodes:
        node = _mapping(raw_node)
        name = node.get("name")
        if not isinstance(name, str) or not name:
            _projection_reject(
                "nodes[].name",
                "node-id-required",
            )
        folded_name = name.casefold()
        if folded_name in identifiers:
            _projection_reject(
                "nodes[].name",
                "node-id-casefold-duplicate",
            )
        identifiers.add(folded_name)

        ip_value = node.get("ip")
        address_value = node.get("address")
        if ip_value is None and address_value is None:
            _projection_reject(
                "nodes[].address",
                "node-address-required",
            )
        if ip_value is not None and address_value is not None:
            try:
                same_address = (
                    ipaddress.ip_address(str(ip_value))
                    == ipaddress.ip_address(str(address_value))
                )
            except ValueError:
                same_address = False
            if not same_address:
                _projection_reject(
                    "nodes[].address",
                    "node-address-conflict",
                )
        address = address_value if address_value is not None else ip_value
        if not isinstance(address, str):
            _projection_reject(
                "nodes[].address",
                "node-address-invalid",
            )
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            _projection_reject(
                "nodes[].address",
                "node-address-invalid",
            )
        address_key = (parsed_address.version, int(parsed_address))
        if address_key in addresses:
            _projection_reject(
                "nodes[].address",
                "node-address-duplicate",
            )
        addresses.add(address_key)

        if "mode" in node:
            _validate_projected_mode(
                node["mode"],
                source_path="nodes[].mode",
                allow_auto=False,
            )
        role = node.get("role", "worker")
        if role not in {"head", "observer", "worker"}:
            _projection_reject(
                "nodes[].role",
                "node-role-invalid",
            )
        head_count += role == "head" and node.get("enabled", True)
        if head_count > 1:
            _projection_reject(
                "nodes[].role",
                "multiple-heads",
            )
        cpu_count = _project_cpu_count(
            node.get("num_cpus", "auto"),
            source_schema=source_schema,
            source_path="nodes[].num_cpus",
        )
        projected.append(
            Node(
                node_id=name,
                address=address,
                role=role,
                enabled=node.get("enabled", True),
                cpu_count=cpu_count,
            )
        )
    return tuple(projected)


def _address_identity(value: str) -> tuple[int, int] | None:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return parsed.version, int(parsed)


def project_v1_import(
    source: bytes | Mapping[str, object],
    current: Config,
) -> V1ImportProjection:
    """Project safe 1.x settings onto *current* without applying effects.

    The source is first processed by :func:`plan_v1_migration`.  This second
    stage adopts only typed local configuration: supported monitoring and
    cleanup values, a safe node inventory, local-node inference, and inert Ray
    connection settings.  Credential, controller, trust, update, manifest,
    remote-authority, and retired-mode data are never copied into ``Config``.
    """

    if not isinstance(current, Config):
        raise TypeError("current must be Config")
    config_to_dict(current)
    plan = plan_v1_migration(source)
    source_paths = {item.source_path for item in plan.diff}
    mapped: list[MigrationDiff] = []
    skipped: list[UnmappedField] = [
        UnmappedField(item.source_path, "legacy-field-unsupported")
        for item in plan.unmapped_fields
        if item.source_path != "nodes[].rdp_user"
    ]
    rejected: list[UnmappedField] = [
        UnmappedField(item.source_path, "rdp-user-dropped")
        for item in plan.unmapped_fields
        if item.source_path == "nodes[].rdp_user"
    ]

    monitoring = current.monitoring
    if "metrics_enabled" in source_paths:
        monitoring = replace(
            monitoring,
            enabled=plan.config.monitoring.enabled,
        )
        mapped.append(MigrationDiff(
            "metrics_enabled", "config.monitoring.enabled", "copied"
        ))
    if "poll_interval" in source_paths:
        monitoring = replace(
            monitoring,
            interval_ms=plan.config.monitoring.interval_ms,
        )
        mapped.append(MigrationDiff(
            "poll_interval",
            "config.monitoring.interval_ms",
            "converted-seconds-to-milliseconds",
        ))
    if "dashboard_stale_grace_sec" in source_paths:
        monitoring = replace(
            monitoring,
            stale_after_ms=max(
                plan.config.monitoring.stale_after_ms,
                monitoring.interval_ms * 2,
            ),
        )
        mapped.append(MigrationDiff(
            "dashboard_stale_grace_sec",
            "config.monitoring.stale_after_ms",
            "converted-seconds-to-milliseconds",
        ))
    elif monitoring.stale_after_ms < monitoring.interval_ms * 2:
        _projection_reject(
            "poll_interval",
            "interval-stale-conflict",
        )

    cleanup = current.cleanup
    if "process_cleanup.grace_sec" in source_paths:
        imported_grace = plan.config.cleanup.graceful_timeout_seconds
        force_timeout = max(
            current.cleanup.force_timeout_seconds,
            imported_grace,
        )
        cleanup = replace(
            cleanup,
            graceful_timeout_seconds=imported_grace,
            force_timeout_seconds=force_timeout,
        )
        mapped.append(MigrationDiff(
            "process_cleanup.grace_sec",
            "config.cleanup.graceful_timeout_seconds",
            "copied",
        ))
        if force_timeout != current.cleanup.force_timeout_seconds:
            mapped.append(MigrationDiff(
                "process_cleanup.grace_sec",
                "config.cleanup.force_timeout_seconds",
                "raised-for-timeout-invariant",
            ))

    topology = _projection_entries(plan.local_overlay.topology)
    nodes = current.nodes
    ray = current.ray

    if "nodes" in topology:
        node_items = _project_nodes(
            topology["nodes"],
            source_schema=plan.source_schema,
        )
        current_local = current.nodes.local_node_id.casefold()
        local_node_id = next(
            (
                current.nodes.local_node_id
                for node in node_items
                if current_local and node.node_id.casefold() == current_local
            ),
            "",
        )
        nodes = NodesSection(node_items, local_node_id)
        mapped.append(MigrationDiff(
            "nodes", "config.nodes.items", "copy-converted"
        ))

    raw_this = topology.get("this")
    if raw_this is not None:
        this = _mapping(raw_this)
        if "mode" in this:
            _validate_projected_mode(
                this["mode"],
                source_path="this.mode",
                allow_auto=True,
            )
            skipped.append(UnmappedField(
                "this.mode", "local-mode-not-stored"
            ))
        if "role" in this:
            if this["role"] not in {"auto", "head", "observer", "worker"}:
                _projection_reject(
                    "this.role",
                    "local-role-invalid",
                )
            skipped.append(UnmappedField(
                "this.role", "local-role-from-inventory"
            ))
        if "num_cpus" in this:
            ray = replace(
                ray,
                cpu_count=_project_cpu_count(
                    this["num_cpus"],
                    source_schema=plan.source_schema,
                    source_path="this.num_cpus",
                ),
            )
            mapped.append(MigrationDiff(
                "this.num_cpus", "config.ray.cpu_count", "copy-converted"
            ))
        if "ip" in this:
            local_ip = this["ip"]
            if local_ip in {"", "auto"}:
                skipped.append(UnmappedField(
                    "this.ip", "local-address-auto"
                ))
            elif isinstance(local_ip, str):
                identity = _address_identity(local_ip)
                matches = tuple(
                    node.node_id
                    for node in nodes.items
                    if _address_identity(node.address) == identity
                )
                if len(matches) > 1:
                    _projection_reject(
                        "this.ip",
                        "local-inference-ambiguous",
                    )
                if matches:
                    nodes = NodesSection(nodes.items, matches[0])
                    mapped.append(MigrationDiff(
                        "this.ip",
                        "config.nodes.local_node_id",
                        "inferred-by-address",
                    ))
                else:
                    skipped.append(UnmappedField(
                        "this.ip", "local-address-unmatched"
                    ))

    if (
        "nodes" in topology
        and nodes.local_node_id != current.nodes.local_node_id
        and not any(
            item.target_path == "config.nodes.local_node_id"
            for item in mapped
        )
    ):
        mapped.append(MigrationDiff(
            "nodes",
            "config.nodes.local_node_id",
            "cleared-not-in-import",
        ))

    for source_path, target_path in (
        ("head_ip", "head_address"),
        ("head_port", "client_port"),
        ("dashboard_port", "dashboard_port"),
    ):
        if source_path not in topology:
            continue
        ray = replace(ray, **{target_path: topology[source_path]})
        mapped.append(MigrationDiff(
            source_path,
            f"config.ray.{target_path}",
            "copied",
        ))
    ray = replace(ray, enabled=False)

    mapped_topology = {
        "dashboard_port",
        "head_ip",
        "head_port",
        "nodes",
        "this",
    }
    for path in sorted(set(topology) - mapped_topology):
        if path in {"cluster_manifest_path", "cluster_epoch"}:
            rejected.append(UnmappedField(path, "remote-authority-dropped"))
        else:
            skipped.append(UnmappedField(path, "ray-field-unsupported"))
    if current.ray.enabled:
        mapped.append(MigrationDiff(
            "projection.safety",
            "config.ray.enabled",
            "disabled-for-review",
        ))
    for entry in plan.local_overlay.per_user_ui:
        skipped.append(UnmappedField(
            entry.path, "legacy-ui-skipped"
        ))
    for entries, reason in (
        (plan.local_overlay.trust, "trust-dropped"),
        (
            plan.local_overlay.controller_lists,
            "controller-authority-dropped",
        ),
        (plan.local_overlay.update_paths, "update-authority-dropped"),
        (
            plan.local_overlay.credential_references,
            "credential-metadata-dropped",
        ),
    ):
        for entry in entries:
            rejected.append(UnmappedField(entry.path, reason))
    if "schema_version" in source_paths:
        mapped.append(MigrationDiff(
            "schema_version", "projection.source_schema", "recorded"
        ))

    projected = replace(
        current,
        monitoring=monitoring,
        cleanup=cleanup,
        nodes=nodes,
        ray=ray,
    )
    try:
        config_to_dict(projected)
    except ConfigValidationError as exc:
        if exc.path.startswith("nodes.items") and exc.path.endswith(".node_id"):
            source_path = "nodes[].name"
            reason = "node-id-invalid"
        elif exc.path.startswith("nodes"):
            source_path = "nodes"
            reason = "target-config-invalid"
        elif exc.path.startswith("monitoring"):
            source_path = "monitoring"
            reason = "target-config-invalid"
        elif exc.path.startswith("cleanup"):
            source_path = "process_cleanup"
            reason = "target-config-invalid"
        else:
            source_path = "ray"
            reason = "target-config-invalid"
        _projection_reject(
            source_path,
            reason,
        )
    return V1ImportProjection(
        source_schema=plan.source_schema,
        config=projected,
        mapped_fields=tuple(sorted(
            set(mapped),
            key=lambda item: (item.source_path, item.target_path, item.action),
        )),
        skipped_fields=tuple(sorted(
            set(skipped),
            key=lambda item: (item.source_path, item.reason),
        )),
        rejected_fields=tuple(sorted(
            set(rejected),
            key=lambda item: (item.source_path, item.reason),
        )),
    )


def local_overlay_to_dict(overlay: LocalOverlay) -> dict[str, object]:
    """Return local values for in-memory projection, never for provenance."""

    if not isinstance(overlay, LocalOverlay):
        raise TypeError("overlay must be LocalOverlay")

    def entries(values: tuple[OverlayEntry, ...]) -> list[dict[str, object]]:
        return [
            {"path": entry.path, "value": entry.value()}
            for entry in values
        ]

    return {
        "topology": entries(overlay.topology),
        "per_user_ui": entries(overlay.per_user_ui),
        "trust": entries(overlay.trust),
        "controller_lists": entries(overlay.controller_lists),
        "update_paths": entries(overlay.update_paths),
        "credential_references": entries(overlay.credential_references),
        "legacy_passthrough": entries(overlay.legacy_passthrough),
    }


def canonical_migration_bytes(plan: MigrationPlan) -> bytes:
    """Serialize a deterministic, value-free migration summary."""

    if not isinstance(plan, MigrationPlan):
        raise TypeError("plan must be MigrationPlan")
    overlay_paths = {
        name: sorted(entry.path for entry in entries)
        for name, entries in (
            ("topology", plan.local_overlay.topology),
            ("per_user_ui", plan.local_overlay.per_user_ui),
            ("trust", plan.local_overlay.trust),
            ("controller_lists", plan.local_overlay.controller_lists),
            ("update_paths", plan.local_overlay.update_paths),
            (
                "credential_references",
                plan.local_overlay.credential_references,
            ),
            ("legacy_passthrough", plan.local_overlay.legacy_passthrough),
        )
    }
    return canonical_json_bytes(
        {
            "source_schema": plan.source_schema,
            "local_overlay_paths": overlay_paths,
            "diff": [
                {
                    "source_path": item.source_path,
                    "target_path": item.target_path,
                    "action": item.action,
                }
                for item in plan.diff
            ],
            "unmapped_fields": [
                {
                    "source_path": item.source_path,
                    "reason": item.reason,
                }
                for item in plan.unmapped_fields
            ],
        }
    )


__all__ = [
    "MAX_LEGACY_SCHEMA",
    "MIN_LEGACY_SCHEMA",
    "LocalOverlay",
    "MigrationDecodeError",
    "MigrationDiff",
    "MigrationError",
    "MigrationPlan",
    "MigrationValidationError",
    "NewerLegacySchemaError",
    "OverlayEntry",
    "SecretMaterialError",
    "UnmappedField",
    "V1ImportProjection",
    "V1ImportProjectionError",
    "canonical_migration_bytes",
    "local_overlay_to_dict",
    "plan_v1_migration",
    "project_v1_import",
]
