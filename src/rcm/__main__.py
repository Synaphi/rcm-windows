"""Module entrypoint for ``python -m rcm``."""

from __future__ import annotations

import os, sys
from typing import Sequence

from .bootstrap import Launcher, run_launcher


def _run_local_admin_helper(arguments: tuple[str, ...]) -> int:
    from .privilege import LOCAL_ADMIN_ELEVATION_ENABLED

    if (not LOCAL_ADMIN_ELEVATION_ENABLED
            or not getattr(sys, "frozen", False)
            or "_PYI_APPLICATION_HOME_DIR" in os.environ):
        return 2
    from .adapters.windows_broker import (
        parse_one_shot_helper_arguments,
        run_one_shot_helper,
    )

    command = parse_one_shot_helper_arguments(arguments)
    if command is None:
        raise ValueError("local admin helper arguments are invalid")
    from .adapters.windows_admin import WindowsAdminApplier

    return run_one_shot_helper(command, applier=WindowsAdminApplier())


def main(
    launcher: Launcher | None = None,
    *,
    argv: Sequence[str] | None = None,
) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ("--rcm-local-admin-helper",):
        if launcher is not None:
            raise ValueError(
                "a launcher cannot be supplied to local admin helper"
            )
        return _run_local_admin_helper(arguments)
    if arguments == ("--foundation-check",):
        if launcher is not None:
            raise ValueError("a launcher cannot be supplied to foundation check")
        from .foundation_check import print_foundation_report

        return print_foundation_report()
    start_minimized = arguments == ("--start-minimized",)
    lifecycle_scenario = None
    if len(arguments) == 2 and arguments[0] == "--lifecycle-check":
        from .desktop import LifecycleScenario

        try:
            lifecycle_scenario = LifecycleScenario(arguments[1])
        except ValueError:
            raise ValueError(
                f"unsupported lifecycle scenario: {arguments[1]!r}"
            ) from None
    elif arguments and not start_minimized:
        raise ValueError(f"unsupported arguments: {arguments!r}")
    if launcher is not None:
        if start_minimized or lifecycle_scenario is not None:
            raise ValueError(
                "desktop lifecycle arguments require the desktop launcher"
            )
        return run_launcher(launcher)
    from .app import main as run_desktop

    return run_desktop(
        start_minimized=start_minimized,
        lifecycle_scenario=lifecycle_scenario,
    )


if __name__ == "__main__":
    raise SystemExit(main())
