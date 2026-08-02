"""Fail-closed entrypoint for the separately authorized PR-07 T1 lab.

This probe is intentionally excluded from unit-test discovery.  Merely
importing it has no product, process, network, profile, or desktop effect.
The disposable-lab controller must provide the exact environment sentinel
before calling :func:`main`.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from collections.abc import Sequence


LAB_SENTINEL = "RCM_PR07_DISPOSABLE_LAB"
EXPECTED_MODULES = (
    "rcm.app",
    "rcm.desktop",
    "rcm.ui.app",
    "rcm.ui.geometry",
    "rcm.ui.state",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("rayless",), required=True)
    parser.add_argument("--expected-integrity", choices=("medium",), required=True)
    parser.add_argument("--expected-admin-membership", type=int, choices=(0,), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Import the reviewed T1 surface after the lab controller binds identity."""

    if os.environ.get(LAB_SENTINEL) != "1":
        raise RuntimeError("PR-07 T1 probe requires the disposable-lab sentinel")
    arguments = _parser().parse_args(argv)
    before = frozenset(sys.modules)
    for module in EXPECTED_MODULES:
        importlib.import_module(module)
    forbidden = sorted(
        name
        for name in ("ray", "requests", "tkinter")
        if name in sys.modules and name not in before
    )
    if forbidden:
        raise RuntimeError("T1 import crossed a deferred runtime boundary")
    result = {
        "schema": "rcm-pr07-t1-probe-v1",
        "role": arguments.role,
        "integrity": arguments.expected_integrity,
        "admin_membership": arguments.expected_admin_membership,
        "imports": list(EXPECTED_MODULES),
        "new_forbidden_modules": forbidden,
        "product_process_started": False,
        "network_probe": False,
        "mutation": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
