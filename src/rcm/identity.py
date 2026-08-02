"""Application identity policy.

This module deliberately contains no host discovery.  Callers select a
deployment kind explicitly (or ask :mod:`rcm.bootstrap` to select one from an
injected environment) and receive an immutable identity description.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


APPLICATION_NAME = "RayClusterManager"
PRODUCTION_CONFIG_NAMESPACE = APPLICATION_NAME
DEVELOPMENT_CONFIG_NAMESPACE = f"{APPLICATION_NAME}-dev"
VALIDATION_CONFIG_NAMESPACE = f"{APPLICATION_NAME}-preview-validation"
PRODUCTION_MUTEX_NAME = rf"Global\{APPLICATION_NAME}_singleton"
DEVELOPMENT_MUTEX_NAME = rf"Global\{APPLICATION_NAME}_dev_singleton"
VALIDATION_MUTEX_NAME = rf"Local\{APPLICATION_NAME}_preview_validation_singleton"


class DeploymentKind(str, Enum):
    """Supported application layouts."""

    DEVELOPMENT = "development"
    PORTABLE = "portable"
    INSTALLED = "installed"


@dataclass(frozen=True, slots=True)
class ApplicationIdentity:
    """Names that distinguish production and development instances."""

    application_name: str
    deployment: DeploymentKind
    config_namespace: str
    mutex_name: str
    production: bool


def identity_for(deployment: DeploymentKind) -> ApplicationIdentity:
    """Return the immutable identity for *deployment*.

    Portable and installed distributions are both production identities.  They
    use different storage roots, but intentionally share the production mutex:
    two production copies must not own the desktop lifecycle simultaneously.
    Development runs use a separate config namespace and mutex so a local build
    cannot collide with or replace a production instance.
    """

    if not isinstance(deployment, DeploymentKind):
        raise TypeError("deployment must be a DeploymentKind")

    production = deployment is not DeploymentKind.DEVELOPMENT
    return ApplicationIdentity(
        application_name=APPLICATION_NAME,
        deployment=deployment,
        config_namespace=(
            PRODUCTION_CONFIG_NAMESPACE
            if production
            else DEVELOPMENT_CONFIG_NAMESPACE
        ),
        mutex_name=(
            PRODUCTION_MUTEX_NAME
            if production
            else DEVELOPMENT_MUTEX_NAME
        ),
        production=production,
    )


def preview_validation_identity() -> ApplicationIdentity:
    """Return the isolated identity used only by the explicit lifecycle gate."""

    return ApplicationIdentity(
        application_name=APPLICATION_NAME,
        deployment=DeploymentKind.DEVELOPMENT,
        config_namespace=VALIDATION_CONFIG_NAMESPACE,
        mutex_name=VALIDATION_MUTEX_NAME,
        production=False,
    )
