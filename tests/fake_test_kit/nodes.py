from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib


SUPPORTED_NODE_COUNTS = frozenset({1, 8, 32})


@dataclass(frozen=True, slots=True)
class SyntheticNode:
    node_id: str
    host: str
    role: str
    cpu_count: int
    memory_mb: int
    sensor_baseline: int

    def snapshot(self) -> dict[str, int | str]:
        return asdict(self)


def _derived_byte(seed: int, count: int, index: int, field: str) -> int:
    material = f"{seed}:{count}:{index}:{field}".encode("ascii")
    return hashlib.sha256(material).digest()[0]


def synthetic_nodes(count: int, *, seed: int) -> tuple[SyntheticNode, ...]:
    if isinstance(count, bool) or count not in SUPPORTED_NODE_COUNTS:
        raise ValueError("synthetic node count must be exactly 1, 8, or 32")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")

    cpu_options = (4, 8, 12, 16)
    memory_options = (8192, 16384, 32768, 65536)
    nodes = []
    for index in range(count):
        ordinal = index + 1
        nodes.append(
            SyntheticNode(
                node_id=f"node-{ordinal:03d}",
                host=f"synthetic-node-{ordinal:03d}",
                role="head" if index == 0 else "worker",
                cpu_count=cpu_options[
                    _derived_byte(seed, count, index, "cpu") % len(cpu_options)
                ],
                memory_mb=memory_options[
                    _derived_byte(seed, count, index, "memory")
                    % len(memory_options)
                ],
                sensor_baseline=35
                + _derived_byte(seed, count, index, "sensor") % 31,
            )
        )
    return tuple(nodes)


def nodes_snapshot(
    nodes: tuple[SyntheticNode, ...],
) -> list[dict[str, int | str]]:
    return [node.snapshot() for node in nodes]
