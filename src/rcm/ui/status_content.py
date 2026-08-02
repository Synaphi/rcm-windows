"""Stable formatting helpers shared by status views."""

from __future__ import annotations

from .state import NodeRenderState


def percent_text(value: float | None) -> str:
    return "--" if value is None else f"{max(0.0, min(100.0, value)):5.1f}%"


def temperature_text(value: float | None) -> str:
    return "--" if value is None else f"{value:5.1f} C"


def node_status_line(node: NodeRenderState) -> str:
    if not isinstance(node, NodeRenderState):
        raise TypeError("node must be a NodeRenderState")
    return (
        f"{node.name:<18.18} {node.role:<8.8} {node.status:<12.12} "
        f"CPU {percent_text(node.cpu_percent)} "
        f"RAM {percent_text(node.memory_percent)} "
        f"TEMP {temperature_text(node.temperature_celsius)}"
    )


def cluster_summary(nodes: tuple[NodeRenderState, ...]) -> str:
    if any(not isinstance(node, NodeRenderState) for node in nodes):
        raise TypeError("nodes must contain NodeRenderState values")
    available = sum(node.status.casefold() in {"ok", "ready", "running"} for node in nodes)
    return f"Nodes {available}/{len(nodes)} available"
