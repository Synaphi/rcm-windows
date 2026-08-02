"""Typed, side-effect-free configuration schema for RCM 2.x.

The public parser deliberately performs no coercion.  A JSON boolean is not an
integer, a string containing a number is not a number, and unknown keys are
rejected at every level.  This keeps migration decisions out of the runtime
configuration boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping, NoReturn
from urllib.parse import urlsplit


CURRENT_SCHEMA_VERSION = 1
MAX_CONFIG_BYTES = 1_048_576
_MAX_GENERATION = (1 << 63) - 1
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CREDENTIAL_REFERENCE = re.compile(
    r"^credential://"
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126})"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}))*$"
)


class ConfigError(Exception):
    """Base class for all public configuration failures."""


class ConfigDecodeError(ConfigError):
    """The input is not one strict UTF-8 JSON document."""


class DuplicateKeyError(ConfigDecodeError):
    """A JSON object contains a duplicate member name."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"duplicate JSON key: {key!r}")


class ConfigTooLargeError(ConfigDecodeError):
    """The encoded configuration exceeds the configured byte limit."""

    def __init__(self, actual: int, limit: int) -> None:
        self.actual = actual
        self.limit = limit
        super().__init__(f"configuration is {actual} bytes; limit is {limit}")


class ConfigValidationError(ConfigError):
    """A decoded value violates the typed schema."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        location = path or "$"
        super().__init__(f"{location}: {message}")


@dataclass(frozen=True, slots=True)
class AppSection:
    name: str = "RayClusterManager"
    environment: str = "development"
    start_minimized: bool = False
    log_level: str = "info"


@dataclass(frozen=True, slots=True)
class UiSection:
    theme: str = "system"
    scale_percent: int = 100
    compact_view: bool = False
    locale: str = ""


@dataclass(frozen=True, slots=True)
class MonitoringSection:
    enabled: bool = True
    interval_ms: int = 1_000
    stale_after_ms: int = 5_000
    history_samples: int = 300


@dataclass(frozen=True, slots=True)
class Node:
    node_id: str
    address: str
    role: str = "worker"
    enabled: bool = True
    cpu_count: int = 0


@dataclass(frozen=True, slots=True)
class NodesSection:
    items: tuple[Node, ...] = ()
    local_node_id: str = ""


@dataclass(frozen=True, slots=True)
class RdpSection:
    enabled: bool = False
    port: int = 3_389
    connect_timeout_seconds: int = 10
    credential_reference: str = ""


@dataclass(frozen=True, slots=True)
class CleanupSection:
    enabled: bool = False
    graceful_timeout_seconds: int = 10
    force_timeout_seconds: int = 30
    max_processes: int = 256


@dataclass(frozen=True, slots=True)
class RaySection:
    enabled: bool = False
    head_address: str = ""
    client_port: int = 6_379
    dashboard_port: int = 8_265
    cpu_count: int = 0
    startup_timeout_seconds: int = 60


@dataclass(frozen=True, slots=True)
class RemoteSection:
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    port: int = 8_765
    max_request_bytes: int = 1_048_576
    request_timeout_seconds: int = 15


@dataclass(frozen=True, slots=True)
class UpdateSection:
    enabled: bool = False
    channel: str = "stable"
    manifest_url: str = ""
    check_interval_hours: int = 24


@dataclass(frozen=True, slots=True)
class Config:
    schema_version: int = CURRENT_SCHEMA_VERSION
    app: AppSection = AppSection()
    ui: UiSection = UiSection()
    monitoring: MonitoringSection = MonitoringSection()
    nodes: NodesSection = NodesSection()
    rdp: RdpSection = RdpSection()
    cleanup: CleanupSection = CleanupSection()
    ray: RaySection = RaySection()
    remote: RemoteSection = RemoteSection()
    update: UpdateSection = UpdateSection()


def default_config() -> Config:
    """Return public, topology-free defaults."""

    return Config()


def _fail(path: str, message: str) -> NoReturn:
    raise ConfigValidationError(path, message)


def _path(parent: str, child: str) -> str:
    return f"{parent}.{child}" if parent else child


def _mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(path, "must be an object")
    for key in value:
        if not isinstance(key, str):
            _fail(path, "object keys must be strings")
    return value


def _known(mapping: Mapping[str, object], allowed: set[str], path: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        _fail(_path(path, unknown[0]), "unknown key")


def _string(
    value: object,
    path: str,
    *,
    minimum: int = 0,
    maximum: int,
) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if not minimum <= len(value) <= maximum:
        _fail(path, f"length must be between {minimum} and {maximum}")
    if any(ord(character) < 0x20 for character in value):
        _fail(path, "must not contain control characters")
    return value


def _boolean(value: object, path: str) -> bool:
    if type(value) is not bool:
        _fail(path, "must be a boolean")
    return value


def _integer(value: object, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        _fail(path, "must be an integer")
    if not minimum <= value <= maximum:
        _fail(path, f"must be between {minimum} and {maximum}")
    return value


def _choice(value: object, path: str, choices: set[str]) -> str:
    result = _string(value, path, maximum=64)
    if result not in choices:
        _fail(path, f"must be one of {', '.join(sorted(choices))}")
    return result


def _address(value: object, path: str, *, allow_empty: bool = False) -> str:
    result = _string(value, path, maximum=253)
    if not result and allow_empty:
        return result
    if not result:
        _fail(path, "must not be empty")
    candidate = result[:-1] if result.endswith(".") else result
    try:
        ipaddress.ip_address(candidate)
        return result
    except ValueError:
        pass
    labels = candidate.split(".")
    if not labels or any(not _HOST_LABEL.fullmatch(label) for label in labels):
        _fail(path, "must be an IP address or DNS host name")
    return result


def _section(
    root: Mapping[str, object],
    name: str,
) -> Mapping[str, object]:
    if name not in root:
        return {}
    value = root[name]
    return _mapping(value, name)


def _parse_app(root: Mapping[str, object]) -> AppSection:
    data = _section(root, "app")
    _known(data, {"name", "environment", "start_minimized", "log_level"}, "app")
    defaults = AppSection()
    return AppSection(
        name=_string(data.get("name", defaults.name), "app.name", minimum=1, maximum=64),
        environment=_choice(
            data.get("environment", defaults.environment),
            "app.environment",
            {"development", "installed", "portable"},
        ),
        start_minimized=_boolean(
            data.get("start_minimized", defaults.start_minimized),
            "app.start_minimized",
        ),
        log_level=_choice(
            data.get("log_level", defaults.log_level),
            "app.log_level",
            {"debug", "info", "warning", "error"},
        ),
    )


def _parse_ui(root: Mapping[str, object]) -> UiSection:
    data = _section(root, "ui")
    _known(data, {"theme", "scale_percent", "compact_view", "locale"}, "ui")
    defaults = UiSection()
    locale = _string(data.get("locale", defaults.locale), "ui.locale", maximum=16)
    if locale and not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", locale):
        _fail("ui.locale", "must be empty or a BCP-47-style language tag")
    return UiSection(
        theme=_choice(data.get("theme", defaults.theme), "ui.theme", {"dark", "light", "system"}),
        scale_percent=_integer(
            data.get("scale_percent", defaults.scale_percent),
            "ui.scale_percent",
            50,
            400,
        ),
        compact_view=_boolean(
            data.get("compact_view", defaults.compact_view),
            "ui.compact_view",
        ),
        locale=locale,
    )


def _parse_monitoring(root: Mapping[str, object]) -> MonitoringSection:
    data = _section(root, "monitoring")
    _known(data, {"enabled", "interval_ms", "stale_after_ms", "history_samples"}, "monitoring")
    defaults = MonitoringSection()
    result = MonitoringSection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "monitoring.enabled"),
        interval_ms=_integer(
            data.get("interval_ms", defaults.interval_ms),
            "monitoring.interval_ms",
            250,
            60_000,
        ),
        stale_after_ms=_integer(
            data.get("stale_after_ms", defaults.stale_after_ms),
            "monitoring.stale_after_ms",
            500,
            300_000,
        ),
        history_samples=_integer(
            data.get("history_samples", defaults.history_samples),
            "monitoring.history_samples",
            1,
            100_000,
        ),
    )
    if result.stale_after_ms < result.interval_ms * 2:
        _fail("monitoring.stale_after_ms", "must be at least twice interval_ms")
    return result


def _parse_node(value: object, index: int) -> Node:
    path = f"nodes.items[{index}]"
    data = _mapping(value, path)
    _known(data, {"node_id", "address", "role", "enabled", "cpu_count"}, path)
    if "node_id" not in data:
        _fail(f"{path}.node_id", "is required")
    if "address" not in data:
        _fail(f"{path}.address", "is required")
    node_id = _string(data["node_id"], f"{path}.node_id", minimum=1, maximum=64)
    if not _IDENTIFIER.fullmatch(node_id):
        _fail(f"{path}.node_id", "contains unsupported characters")
    return Node(
        node_id=node_id,
        address=_address(data["address"], f"{path}.address"),
        role=_choice(data.get("role", "worker"), f"{path}.role", {"head", "observer", "worker"}),
        enabled=_boolean(data.get("enabled", True), f"{path}.enabled"),
        cpu_count=_integer(data.get("cpu_count", 0), f"{path}.cpu_count", 0, 65_536),
    )


def _parse_nodes(root: Mapping[str, object]) -> NodesSection:
    data = _section(root, "nodes")
    _known(data, {"items", "local_node_id"}, "nodes")
    raw_items = data.get("items", ())
    if not isinstance(raw_items, (list, tuple)):
        _fail("nodes.items", "must be an array")
    if len(raw_items) > 4_096:
        _fail("nodes.items", "must contain at most 4096 entries")
    items = tuple(_parse_node(value, index) for index, value in enumerate(raw_items))
    local = _string(data.get("local_node_id", ""), "nodes.local_node_id", maximum=64)
    identifiers = [node.node_id for node in items]
    folded = [identifier.casefold() for identifier in identifiers]
    if len(folded) != len(set(folded)):
        _fail("nodes.items", "node_id values must be unique (case-insensitive)")
    enabled_heads = [node for node in items if node.enabled and node.role == "head"]
    if len(enabled_heads) > 1:
        _fail("nodes.items", "at most one enabled head is allowed")
    if local and local.casefold() not in set(folded):
        _fail("nodes.local_node_id", "must reference an item in nodes.items")
    return NodesSection(items=items, local_node_id=local)


def _parse_rdp(root: Mapping[str, object]) -> RdpSection:
    data = _section(root, "rdp")
    _known(data, {"enabled", "port", "connect_timeout_seconds", "credential_reference"}, "rdp")
    defaults = RdpSection()
    credential_reference = _string(
        data.get("credential_reference", defaults.credential_reference),
        "rdp.credential_reference",
        maximum=256,
    )
    if credential_reference and not credential_reference_is_valid(
        credential_reference
    ):
        _fail(
            "rdp.credential_reference",
            "must be an opaque credential:// reference",
        )
    return RdpSection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "rdp.enabled"),
        port=_integer(data.get("port", defaults.port), "rdp.port", 1, 65_535),
        connect_timeout_seconds=_integer(
            data.get("connect_timeout_seconds", defaults.connect_timeout_seconds),
            "rdp.connect_timeout_seconds",
            1,
            300,
        ),
        credential_reference=credential_reference,
    )


def _parse_cleanup(root: Mapping[str, object]) -> CleanupSection:
    data = _section(root, "cleanup")
    _known(
        data,
        {"enabled", "graceful_timeout_seconds", "force_timeout_seconds", "max_processes"},
        "cleanup",
    )
    defaults = CleanupSection()
    result = CleanupSection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "cleanup.enabled"),
        graceful_timeout_seconds=_integer(
            data.get("graceful_timeout_seconds", defaults.graceful_timeout_seconds),
            "cleanup.graceful_timeout_seconds",
            0,
            3_600,
        ),
        force_timeout_seconds=_integer(
            data.get("force_timeout_seconds", defaults.force_timeout_seconds),
            "cleanup.force_timeout_seconds",
            0,
            3_600,
        ),
        max_processes=_integer(
            data.get("max_processes", defaults.max_processes),
            "cleanup.max_processes",
            1,
            100_000,
        ),
    )
    if result.force_timeout_seconds < result.graceful_timeout_seconds:
        _fail("cleanup.force_timeout_seconds", "must be at least graceful_timeout_seconds")
    return result


def _parse_ray(root: Mapping[str, object]) -> RaySection:
    data = _section(root, "ray")
    _known(
        data,
        {
            "enabled",
            "head_address",
            "client_port",
            "dashboard_port",
            "cpu_count",
            "startup_timeout_seconds",
        },
        "ray",
    )
    defaults = RaySection()
    result = RaySection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "ray.enabled"),
        head_address=_address(
            data.get("head_address", defaults.head_address),
            "ray.head_address",
            allow_empty=True,
        ),
        client_port=_integer(
            data.get("client_port", defaults.client_port),
            "ray.client_port",
            1,
            65_535,
        ),
        dashboard_port=_integer(
            data.get("dashboard_port", defaults.dashboard_port),
            "ray.dashboard_port",
            1,
            65_535,
        ),
        cpu_count=_integer(data.get("cpu_count", defaults.cpu_count), "ray.cpu_count", 0, 65_536),
        startup_timeout_seconds=_integer(
            data.get("startup_timeout_seconds", defaults.startup_timeout_seconds),
            "ray.startup_timeout_seconds",
            1,
            3_600,
        ),
    )
    if result.enabled and not result.head_address:
        _fail("ray.head_address", "is required when ray.enabled is true")
    if result.client_port == result.dashboard_port:
        _fail("ray.dashboard_port", "must differ from client_port")
    return result


def _parse_remote(root: Mapping[str, object]) -> RemoteSection:
    data = _section(root, "remote")
    _known(
        data,
        {"enabled", "bind_host", "port", "max_request_bytes", "request_timeout_seconds"},
        "remote",
    )
    defaults = RemoteSection()
    result = RemoteSection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "remote.enabled"),
        bind_host=_address(data.get("bind_host", defaults.bind_host), "remote.bind_host"),
        port=_integer(data.get("port", defaults.port), "remote.port", 1, 65_535),
        max_request_bytes=_integer(
            data.get("max_request_bytes", defaults.max_request_bytes),
            "remote.max_request_bytes",
            1_024,
            16_777_216,
        ),
        request_timeout_seconds=_integer(
            data.get("request_timeout_seconds", defaults.request_timeout_seconds),
            "remote.request_timeout_seconds",
            1,
            300,
        ),
    )
    if result.enabled:
        try:
            loopback = ipaddress.ip_address(result.bind_host).is_loopback
        except ValueError:
            loopback = result.bind_host.casefold() == "localhost"
        if not loopback:
            _fail("remote.bind_host", "must be loopback while remote service is enabled")
    return result


def _parse_update(root: Mapping[str, object]) -> UpdateSection:
    data = _section(root, "update")
    _known(data, {"enabled", "channel", "manifest_url", "check_interval_hours"}, "update")
    defaults = UpdateSection()
    result = UpdateSection(
        enabled=_boolean(data.get("enabled", defaults.enabled), "update.enabled"),
        channel=_choice(
            data.get("channel", defaults.channel),
            "update.channel",
            {"beta", "stable"},
        ),
        manifest_url=_string(
            data.get("manifest_url", defaults.manifest_url),
            "update.manifest_url",
            maximum=2_048,
        ),
        check_interval_hours=_integer(
            data.get("check_interval_hours", defaults.check_interval_hours),
            "update.check_interval_hours",
            1,
            720,
        ),
    )
    if result.manifest_url:
        try:
            parts = urlsplit(result.manifest_url)
            valid_url = (
                parts.scheme == "https"
                and bool(parts.hostname)
                and parts.username is None
                and parts.password is None
                and not parts.query
                and not parts.fragment
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            _fail(
                "update.manifest_url",
                "must be an HTTPS URL without credentials, query, or fragment",
            )
    elif result.enabled:
        _fail("update.manifest_url", "is required when update.enabled is true")
    return result


def credential_reference_is_valid(value: str) -> bool:
    """Return whether *value* is one strict, non-secret opaque reference."""

    return (
        type(value) is str
        and len(value) <= 256
        and _CREDENTIAL_REFERENCE.fullmatch(value) is not None
    )


def config_from_dict(value: Mapping[str, object] | object) -> Config:
    """Validate and freeze a decoded configuration object."""

    root = _mapping(value, "")
    allowed = {
        "schema_version",
        "app",
        "ui",
        "monitoring",
        "nodes",
        "rdp",
        "cleanup",
        "ray",
        "remote",
        "update",
    }
    _known(root, allowed, "")
    version = _integer(
        root.get("schema_version", CURRENT_SCHEMA_VERSION),
        "schema_version",
        1,
        CURRENT_SCHEMA_VERSION,
    )
    return Config(
        schema_version=version,
        app=_parse_app(root),
        ui=_parse_ui(root),
        monitoring=_parse_monitoring(root),
        nodes=_parse_nodes(root),
        rdp=_parse_rdp(root),
        cleanup=_parse_cleanup(root),
        ray=_parse_ray(root),
        remote=_parse_remote(root),
        update=_parse_update(root),
    )


def config_to_dict(config: Config) -> dict[str, object]:
    """Return the stable public JSON representation of *config*."""

    if not isinstance(config, Config):
        raise TypeError("config must be Config")
    # Revalidation protects callers that constructed dataclasses directly.
    result: dict[str, object] = {
        "schema_version": config.schema_version,
        "app": {
            "name": config.app.name,
            "environment": config.app.environment,
            "start_minimized": config.app.start_minimized,
            "log_level": config.app.log_level,
        },
        "ui": {
            "theme": config.ui.theme,
            "scale_percent": config.ui.scale_percent,
            "compact_view": config.ui.compact_view,
            "locale": config.ui.locale,
        },
        "monitoring": {
            "enabled": config.monitoring.enabled,
            "interval_ms": config.monitoring.interval_ms,
            "stale_after_ms": config.monitoring.stale_after_ms,
            "history_samples": config.monitoring.history_samples,
        },
        "nodes": {
            "items": [
                {
                    "node_id": node.node_id,
                    "address": node.address,
                    "role": node.role,
                    "enabled": node.enabled,
                    "cpu_count": node.cpu_count,
                }
                for node in config.nodes.items
            ],
            "local_node_id": config.nodes.local_node_id,
        },
        "rdp": {
            "enabled": config.rdp.enabled,
            "port": config.rdp.port,
            "connect_timeout_seconds": config.rdp.connect_timeout_seconds,
            "credential_reference": config.rdp.credential_reference,
        },
        "cleanup": {
            "enabled": config.cleanup.enabled,
            "graceful_timeout_seconds": config.cleanup.graceful_timeout_seconds,
            "force_timeout_seconds": config.cleanup.force_timeout_seconds,
            "max_processes": config.cleanup.max_processes,
        },
        "ray": {
            "enabled": config.ray.enabled,
            "head_address": config.ray.head_address,
            "client_port": config.ray.client_port,
            "dashboard_port": config.ray.dashboard_port,
            "cpu_count": config.ray.cpu_count,
            "startup_timeout_seconds": config.ray.startup_timeout_seconds,
        },
        "remote": {
            "enabled": config.remote.enabled,
            "bind_host": config.remote.bind_host,
            "port": config.remote.port,
            "max_request_bytes": config.remote.max_request_bytes,
            "request_timeout_seconds": config.remote.request_timeout_seconds,
        },
        "update": {
            "enabled": config.update.enabled,
            "channel": config.update.channel,
            "manifest_url": config.update.manifest_url,
            "check_interval_hours": config.update.check_interval_hours,
        },
    }
    # Raises a typed validation error if a directly-created dataclass is invalid.
    config_from_dict(result)
    return result


def _reject_constant(value: str) -> NoReturn:
    raise ConfigDecodeError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(key)
        result[key] = value
    return result


def decode_json_bytes(raw: bytes, *, max_bytes: int = MAX_CONFIG_BYTES) -> object:
    """Decode exactly one strict UTF-8 JSON value, rejecting duplicate keys."""

    if not isinstance(raw, bytes):
        raise TypeError("raw must be bytes")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if len(raw) > max_bytes:
        raise ConfigTooLargeError(len(raw), max_bytes)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ConfigDecodeError("configuration is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ConfigDecodeError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ConfigDecodeError("configuration is not one valid JSON document") from exc


def parse_config_bytes(raw: bytes, *, max_bytes: int = MAX_CONFIG_BYTES) -> Config:
    """Decode and validate configuration bytes."""

    return config_from_dict(decode_json_bytes(raw, max_bytes=max_bytes))


def canonical_json_bytes(value: object) -> bytes:
    """Encode deterministic UTF-8 JSON without insignificant whitespace."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ConfigDecodeError("value cannot be encoded as canonical JSON") from exc


def canonical_config_bytes(config: Config) -> bytes:
    """Return the canonical persisted bytes for a typed configuration."""

    encoded = canonical_json_bytes(config_to_dict(config))
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ConfigTooLargeError(len(encoded), MAX_CONFIG_BYTES)
    return encoded


def config_checksum(config: Config) -> str:
    """Return the lowercase SHA-256 of the canonical configuration."""

    return hashlib.sha256(canonical_config_bytes(config)).hexdigest()


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "MAX_CONFIG_BYTES",
    "AppSection",
    "CleanupSection",
    "Config",
    "ConfigDecodeError",
    "ConfigError",
    "ConfigTooLargeError",
    "ConfigValidationError",
    "DuplicateKeyError",
    "MonitoringSection",
    "Node",
    "NodesSection",
    "RaySection",
    "RdpSection",
    "RemoteSection",
    "UiSection",
    "UpdateSection",
    "canonical_config_bytes",
    "canonical_json_bytes",
    "config_checksum",
    "config_from_dict",
    "config_to_dict",
    "decode_json_bytes",
    "default_config",
    "parse_config_bytes",
]
