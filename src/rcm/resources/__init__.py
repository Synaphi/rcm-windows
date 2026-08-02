"""Explicit readers for packaged, non-executable resources."""

from __future__ import annotations

from importlib.resources import files


def read_help_bytes() -> bytes:
    raw = files(__package__).joinpath("help.json").read_bytes()
    if not raw or len(raw) > 131_072:
        raise ValueError("packaged help resource size is invalid")
    return raw


__all__ = ("read_help_bytes",)
