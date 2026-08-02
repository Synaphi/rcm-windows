"""Typed, import-safe contracts for the local one-shot privilege boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hmac, json, math, re
from typing import Mapping, Protocol


MAX_BROKER_REQUEST_BYTES = 65_536
CHALLENGE_LIFETIME_SECONDS = 30.0
OPERATION_DEADLINE_SECONDS = 120.0
HELPER_EXIT_SECONDS = 5.0
BROKER_PROTOCOL_VERSION = 1
LOCAL_ADMIN_ELEVATION_ENABLED = False

_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")
_CHALLENGE = re.compile(r"^[a-f0-9]{64}$")
_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_EXACT_RULE_COUNT = 3


def _bool(value: object, name: str) -> bool:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a bool")
    return value


def _time(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    return result


def _exact_keys(
    value: object,
    expected: frozenset[str],
    name: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} has an invalid schema")
    return value


class IntegrityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    SYSTEM = "system"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PrivilegeSnapshot:
    """Current token facts; the application default is medium and non-elevated."""

    integrity: IntegrityLevel = IntegrityLevel.MEDIUM
    administrator_member: bool = False
    elevated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.integrity, IntegrityLevel):
            raise TypeError("integrity must be an IntegrityLevel")
        _bool(self.administrator_member, "administrator_member")
        _bool(self.elevated, "elevated")
        if self.elevated and self.integrity not in {
            IntegrityLevel.HIGH,
            IntegrityLevel.SYSTEM,
        }:
            raise ValueError("an elevated token must have high or system integrity")


class PrivilegedOperation(str, Enum):
    """The complete PR-07 privileged semantic action set."""

    RDP_HOST_APPLY = "rdp_host_apply"
    PRIVATE_FIREWALL_APPLY = "private_firewall_apply"


class FirewallRuleState(str, Enum):
    ABSENT = "absent"
    DISABLED = "disabled"
    ENABLED = "enabled"


@dataclass(frozen=True, slots=True)
class RdpHostApply:
    enabled: bool
    require_nla: bool = True

    def __post_init__(self) -> None:
        _bool(self.enabled, "RDP enabled")
        _bool(self.require_nla, "RDP require_nla")
        if self.enabled and not self.require_nla:
            raise ValueError("enabled RDP requires NLA")

    def to_dict(self) -> dict[str, object]:
        return {"enabled": self.enabled, "require_nla": self.require_nla}

    @classmethod
    def from_dict(cls, value: object) -> RdpHostApply:
        data = _exact_keys(
            value,
            frozenset({"enabled", "require_nla"}),
            "RDP host arguments",
        )
        return cls(
            _bool(data["enabled"], "RDP enabled"),
            _bool(data["require_nla"], "RDP require_nla"),
        )


@dataclass(frozen=True, slots=True)
class PrivateFirewallApply:
    """Desired state of the exact three application-owned private rules."""

    rules: tuple[FirewallRuleState, ...]

    def __post_init__(self) -> None:
        values = tuple(self.rules)
        if (
            len(values) != _EXACT_RULE_COUNT
            or any(not isinstance(item, FirewallRuleState) for item in values)
        ):
            raise ValueError("private firewall requires exactly three rule states")
        object.__setattr__(self, "rules", values)

    @classmethod
    def enabled(cls) -> PrivateFirewallApply:
        return cls((FirewallRuleState.ENABLED,) * _EXACT_RULE_COUNT)

    @classmethod
    def absent(cls) -> PrivateFirewallApply:
        return cls((FirewallRuleState.ABSENT,) * _EXACT_RULE_COUNT)

    def to_dict(self) -> dict[str, object]:
        return {"rules": [item.value for item in self.rules]}

    @classmethod
    def from_dict(cls, value: object) -> PrivateFirewallApply:
        data = _exact_keys(value, frozenset({"rules"}), "firewall arguments")
        raw = data["rules"]
        if not isinstance(raw, list):
            raise TypeError("firewall rules must be a list")
        try:
            return cls(tuple(FirewallRuleState(item) for item in raw))
        except (TypeError, ValueError):
            raise ValueError("firewall rules contain an invalid state") from None


PrivilegeArguments = RdpHostApply | PrivateFirewallApply


@dataclass(frozen=True, slots=True, repr=False)
class PrivilegeRequest:
    request_id: str
    operation: PrivilegedOperation
    arguments: PrivilegeArguments = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _IDENTIFIER.fullmatch(
            self.request_id
        ):
            raise ValueError("request_id must be 32 lowercase hexadecimal characters")
        if not isinstance(self.operation, PrivilegedOperation):
            raise TypeError("operation must be a PrivilegedOperation")
        expected = {
            PrivilegedOperation.RDP_HOST_APPLY: RdpHostApply,
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY: PrivateFirewallApply,
        }[self.operation]
        if not isinstance(self.arguments, expected):
            raise TypeError("request arguments do not match the operation")

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "operation": self.operation.value,
            "arguments": self.arguments.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> PrivilegeRequest:
        keys = frozenset({"request_id", "operation", "arguments"})
        data = _exact_keys(value, keys, "privilege request")
        try:
            operation = PrivilegedOperation(data["operation"])
        except (TypeError, ValueError):
            raise ValueError("privilege request operation is not allowed") from None
        decode = {
            PrivilegedOperation.RDP_HOST_APPLY: RdpHostApply.from_dict,
            PrivilegedOperation.PRIVATE_FIREWALL_APPLY:
                PrivateFirewallApply.from_dict,
        }[operation]
        return cls(data["request_id"], operation, decode(data["arguments"]))


class PrivilegeStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True, repr=False)
class PrivilegeReceipt:
    request_id: str
    operation: PrivilegedOperation
    status: PrivilegeStatus
    code: str
    changed: bool = False
    verified: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not _IDENTIFIER.fullmatch(
            self.request_id
        ):
            raise ValueError("receipt request_id is invalid")
        if not isinstance(self.operation, PrivilegedOperation):
            raise TypeError("receipt operation must be a PrivilegedOperation")
        if not isinstance(self.status, PrivilegeStatus):
            raise TypeError("receipt status must be a PrivilegeStatus")
        if not isinstance(self.code, str) or not _CODE.fullmatch(self.code):
            raise ValueError("receipt code must be a safe public code")
        _bool(self.changed, "receipt changed")
        _bool(self.verified, "receipt verified")
        if self.status is not PrivilegeStatus.SUCCEEDED and self.verified:
            raise ValueError("a failed or cancelled operation cannot be verified")

    @property
    def ok(self) -> bool:
        return self.status is PrivilegeStatus.SUCCEEDED and self.verified

    def to_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "operation": self.operation.value,
            "status": self.status.value,
            "code": self.code,
            "changed": self.changed,
            "verified": self.verified,
        }

    @classmethod
    def from_dict(cls, value: object) -> PrivilegeReceipt:
        keys = frozenset({
            "request_id", "operation", "status", "code", "changed", "verified",
        })
        data = _exact_keys(value, keys, "privilege receipt")
        try:
            return cls(
                data["request_id"], PrivilegedOperation(data["operation"]),
                PrivilegeStatus(data["status"]), data["code"],
                _bool(data["changed"], "receipt changed"),
                _bool(data["verified"], "receipt verified"))
        except (TypeError, ValueError):
            raise ValueError("privilege receipt contains an invalid value") from None


@dataclass(frozen=True, slots=True, repr=False)
class BrokerRequestEnvelope:
    challenge: str = field(repr=False)
    issued_at: float
    challenge_expires_at: float
    operation_deadline: float
    request: PrivilegeRequest

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, str) or not _CHALLENGE.fullmatch(
            self.challenge
        ):
            raise ValueError("broker challenge must be 64 lowercase hex characters")
        issued = _time(self.issued_at, "issued_at")
        expires = _time(self.challenge_expires_at, "challenge_expires_at")
        deadline = _time(self.operation_deadline, "operation_deadline")
        if not issued < expires <= issued + CHALLENGE_LIFETIME_SECONDS:
            raise ValueError("broker challenge lifetime exceeds 30 seconds")
        if not issued < deadline <= issued + OPERATION_DEADLINE_SECONDS:
            raise ValueError("broker operation deadline exceeds 120 seconds")
        if not isinstance(self.request, PrivilegeRequest):
            raise TypeError("broker request must be a PrivilegeRequest")
        object.__setattr__(self, "issued_at", issued)
        object.__setattr__(self, "challenge_expires_at", expires)
        object.__setattr__(self, "operation_deadline", deadline)

    def to_dict(self) -> dict[str, object]:
        return {
            "version": BROKER_PROTOCOL_VERSION,
            "challenge": self.challenge,
            "issued_at": self.issued_at,
            "challenge_expires_at": self.challenge_expires_at,
            "operation_deadline": self.operation_deadline,
            "request": self.request.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> BrokerRequestEnvelope:
        keys = frozenset({
            "version", "challenge", "issued_at", "challenge_expires_at",
            "operation_deadline", "request",
        })
        data = _exact_keys(value, keys, "broker envelope")
        if data["version"] != BROKER_PROTOCOL_VERSION:
            raise ValueError("broker protocol version is unsupported")
        return cls(
            data["challenge"], data["issued_at"],
            data["challenge_expires_at"], data["operation_deadline"],
            PrivilegeRequest.from_dict(data["request"]))

    def validate(self, *, expected_challenge: str, now: float) -> None:
        current = _time(now, "broker validation time")
        if (not isinstance(expected_challenge, str)
                or not hmac.compare_digest(self.challenge, expected_challenge)):
            raise ValueError("broker challenge does not match")
        if current > self.challenge_expires_at:
            raise TimeoutError("broker challenge expired")
        if current > self.operation_deadline:
            raise TimeoutError("broker operation deadline expired")


def encode_broker_request(envelope: BrokerRequestEnvelope) -> bytes:
    if not isinstance(envelope, BrokerRequestEnvelope):
        raise TypeError("envelope must be a BrokerRequestEnvelope")
    payload = json.dumps(
        envelope.to_dict(), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")
    if len(payload) > MAX_BROKER_REQUEST_BYTES:
        raise ValueError("broker request exceeds 64 KiB")
    return payload


def decode_broker_request(
    payload: bytes,
    *,
    expected_challenge: str,
    now: float,
) -> BrokerRequestEnvelope:
    if (not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_BROKER_REQUEST_BYTES):
        raise ValueError("broker request size is invalid")
    try:
        data = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("broker request is not canonical JSON") from None
    envelope = BrokerRequestEnvelope.from_dict(data)
    if encode_broker_request(envelope) != payload:
        raise ValueError("broker request is not canonical JSON")
    envelope.validate(expected_challenge=expected_challenge, now=now)
    return envelope


def encode_broker_receipt(receipt: PrivilegeReceipt) -> bytes:
    if not isinstance(receipt, PrivilegeReceipt):
        raise TypeError("receipt must be a PrivilegeReceipt")
    return json.dumps(
        {"version": BROKER_PROTOCOL_VERSION, "receipt": receipt.to_dict()},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode_broker_receipt(payload: bytes) -> PrivilegeReceipt:
    if (not isinstance(payload, bytes)
            or not 0 < len(payload) <= MAX_BROKER_REQUEST_BYTES):
        raise ValueError("broker receipt size is invalid")
    try:
        raw = json.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("broker receipt is not canonical JSON") from None
    data = _exact_keys(raw, frozenset({"version", "receipt"}), "broker response")
    if data["version"] != BROKER_PROTOCOL_VERSION:
        raise ValueError("broker response version is unsupported")
    receipt = PrivilegeReceipt.from_dict(data["receipt"])
    if encode_broker_receipt(receipt) != payload:
        raise ValueError("broker receipt is not canonical JSON")
    return receipt


class PrivilegeBroker(Protocol):
    def apply(self, request: PrivilegeRequest) -> PrivilegeReceipt: ...


__all__ = [
    "BROKER_PROTOCOL_VERSION",
    "CHALLENGE_LIFETIME_SECONDS",
    "HELPER_EXIT_SECONDS",
    "LOCAL_ADMIN_ELEVATION_ENABLED",
    "MAX_BROKER_REQUEST_BYTES",
    "OPERATION_DEADLINE_SECONDS",
    "BrokerRequestEnvelope",
    "FirewallRuleState",
    "IntegrityLevel",
    "PrivateFirewallApply",
    "PrivilegeBroker",
    "PrivilegeReceipt",
    "PrivilegeRequest",
    "PrivilegeSnapshot",
    "PrivilegeStatus",
    "PrivilegedOperation",
    "RdpHostApply",
    "decode_broker_receipt",
    "decode_broker_request",
    "encode_broker_receipt",
    "encode_broker_request",
]
