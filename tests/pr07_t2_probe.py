"""Fail-closed contract probe for a separately authorized PR-07 T2 lab.

The standard, administrator-baseline, and attacker roles are distinct
manual boundaries.  This module records only sanitized capability results;
it does not elevate, open a pipe, apply a setting, or contact a peer.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence


LAB_SENTINEL = "RCM_PR07_DISPOSABLE_LAB"
ROLES = ("standard", "admin", "attacker")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("--integrity", choices=("medium", "high"), required=True)
    parser.add_argument("--admin-membership", type=int, choices=(0, 1), required=True)
    parser.add_argument("--broker-requested", type=int, choices=(0,), required=True)
    return parser


def _role_is_consistent(role: str, integrity: str, membership: int) -> bool:
    if role in {"standard", "attacker"}:
        return integrity == "medium" and membership == 0
    return role == "admin" and membership == 1


def main(argv: Sequence[str] | None = None) -> int:
    """Emit one sanitized pre-action role receipt."""

    if os.environ.get(LAB_SENTINEL) != "1":
        raise RuntimeError("PR-07 T2 probe requires the disposable-lab sentinel")
    arguments = _parser().parse_args(argv)
    if not _role_is_consistent(
        arguments.role,
        arguments.integrity,
        arguments.admin_membership,
    ):
        raise RuntimeError("T2 role does not match the bound token baseline")
    result = {
        "schema": "rcm-pr07-t2-role-v1",
        "role": arguments.role,
        "integrity": arguments.integrity,
        "admin_membership": arguments.admin_membership,
        "broker_requested": bool(arguments.broker_requested),
        "apply_attempted": False,
        "credential_value_observed": False,
        "network_probe": False,
        "mutation": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
