"""Typed add/edit node dialog model."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress, re

from ..config.schema import Node


_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _address(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or "%" in value:
        raise ValueError("node address is invalid")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        if any(_LABEL.fullmatch(label) is None for label in value.split(".")):
            raise ValueError("node address is invalid") from None
        return value.casefold()


@dataclass(frozen=True, slots=True)
class NodeDraft:
    node_id: str
    address: str
    role: str = "worker"
    enabled: bool = True
    cpu_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or _NODE_ID.fullmatch(self.node_id) is None:
            raise ValueError("node_id must be a safe identifier")
        object.__setattr__(self, "address", _address(self.address))
        if self.role not in {"head", "worker", "observer"}:
            raise ValueError("role must be head, worker, or observer")
        if type(self.enabled) is not bool:
            raise TypeError("enabled must be a bool")
        if type(self.cpu_count) is not int or not 0 <= self.cpu_count <= 4_096:
            raise ValueError("cpu_count must be between 0 and 4096")

    @classmethod
    def from_node(cls, node: Node) -> NodeDraft:
        if not isinstance(node, Node):
            raise TypeError("node must be a config Node")
        return cls(node.node_id, node.address, node.role, node.enabled, node.cpu_count)

    def to_node(self) -> Node:
        return Node(
            node_id=self.node_id,
            address=self.address,
            role=self.role,
            enabled=self.enabled,
            cpu_count=self.cpu_count,
        )
