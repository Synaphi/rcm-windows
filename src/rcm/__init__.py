"""Import-safe Ray Cluster Manager 2.x application foundation."""

from .bootstrap import (
    BootstrapPlan,
    BootstrapRequest,
    CompatibilityLauncher,
    Environment,
    ensure_bootstrap_directories,
    plan_bootstrap,
    run_launcher,
    select_deployment,
)
from .identity import (
    ApplicationIdentity,
    DeploymentKind,
    identity_for,
)
from .paths import KnownFolders, RuntimePaths

__all__ = (
    "ApplicationIdentity",
    "BootstrapPlan",
    "BootstrapRequest",
    "CompatibilityLauncher",
    "DeploymentKind",
    "Environment",
    "KnownFolders",
    "RuntimePaths",
    "ensure_bootstrap_directories",
    "identity_for",
    "plan_bootstrap",
    "run_launcher",
    "select_deployment",
)

__version__ = "2.8.3a1"
