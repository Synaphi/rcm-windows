"""Local, secret-free configuration bootstrap and setup wizard."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .bootstrap import (
    BootstrapPlan,
    BootstrapRequest,
    Environment,
    plan_bootstrap,
    select_deployment,
)
from .config.schema import (
    Config,
    ConfigValidationError,
    NodesSection,
    config_to_dict,
)
from .config.store import ConfigConflictError, ConfigStore, StoredConfig
from .identity import DeploymentKind
from .paths import KnownFolders


def initialize_runtime_config(plan: BootstrapPlan) -> StoredConfig:
    """Create or load the strict local configuration for one startup plan."""

    if not isinstance(plan, BootstrapPlan):
        raise TypeError("plan must be a BootstrapPlan")
    for operation in plan.directories:
        Path(str(operation.path)).mkdir(
            parents=operation.parents,
            exist_ok=operation.exist_ok,
        )
    store = ConfigStore(Path(str(plan.paths.config_file)))
    stored = store.load()
    if stored.generation == 0:
        initial = replace(
            stored.config,
            app=replace(
                stored.config.app,
                environment=plan.identity.deployment.value,
            ),
        )
        config_to_dict(initial)
        try:
            stored = store.save(initial, expected_generation=0)
        except ConfigConflictError:
            stored = store.load()
            if stored.generation == 0:
                raise
    return stored


def host_bootstrap_plan(environment: Environment, *, frozen: bool) -> BootstrapPlan:
    """Resolve the current host into the import-safe bootstrap model."""

    import os
    import sys

    if not isinstance(environment, Environment):
        raise TypeError("environment must be an Environment")
    if type(frozen) is not bool:
        raise TypeError("frozen must be a bool")
    current_binary = Path(sys.executable).resolve()
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if not local_app_data:
        deployment = select_deployment(environment, frozen=frozen)
        if deployment is not DeploymentKind.PORTABLE:
            raise RuntimeError("LOCALAPPDATA is unavailable")
        local_app_data = str(current_binary.parent)
    if frozen:
        application_root = current_binary.parent
        resource_root = Path(
            getattr(sys, "_MEIPASS", application_root)
        ).resolve()
    else:
        application_root = Path(__file__).resolve().parents[2]
        resource_root = Path(__file__).resolve().parent
    return plan_bootstrap(BootstrapRequest(
        environment=environment,
        known_folders=KnownFolders(local_app_data=local_app_data),
        application_root=application_root,
        resource_root=resource_root,
        current_binary=current_binary,
        frozen=frozen,
    ))


def configure_local_node(
    config: Config,
    *,
    node_id: str,
    address: str,
    role: str,
    cpu_count: int,
    monitoring_enabled: bool,
    start_minimized: bool,
) -> Config:
    """Apply the secret-free setup-wizard fields to a typed configuration."""

    from .ui.node_dialog import NodeDraft

    if not isinstance(config, Config):
        raise TypeError("config must be a Config")
    if type(monitoring_enabled) is not bool or type(start_minimized) is not bool:
        raise TypeError("setup flags must be bool values")
    node = NodeDraft(
        node_id=node_id,
        address=address,
        role=role,
        enabled=True,
        cpu_count=cpu_count,
    ).to_node()
    previous_local = config.nodes.local_node_id.casefold()
    items = []
    replaced_local = False
    for existing in config.nodes.items:
        if previous_local and existing.node_id.casefold() == previous_local:
            items.append(node)
            replaced_local = True
        else:
            items.append(existing)
    if not replaced_local:
        items.append(node)
    updated = replace(
        config,
        app=replace(config.app, start_minimized=start_minimized),
        monitoring=replace(config.monitoring, enabled=monitoring_enabled),
        nodes=NodesSection(tuple(items), node.node_id),
    )
    config_to_dict(updated)
    return updated


def _configuration_form_result(
    config: Config,
    *,
    node_id: str,
    address: str,
    role: str,
    cpu_count: str,
    monitoring_enabled: bool,
    start_minimized: bool,
) -> tuple[Config | None, str]:
    """Return a validated form result or one safe user-facing error."""

    try:
        updated = configure_local_node(
            config,
            node_id=node_id.strip(),
            address=address.strip(),
            role=role,
            cpu_count=int(cpu_count, 10),
            monitoring_enabled=monitoring_enabled,
            start_minimized=start_minimized,
        )
    except (ConfigValidationError, TypeError, ValueError) as exc:
        return None, str(exc)
    return updated, ""


def _configuration_dialog(config: Config) -> Config | None:
    """Show the bounded, secret-free local setup form."""

    import tkinter as tk

    if not isinstance(config, Config):
        raise TypeError("config must be a Config")
    current = next(
        (
            item
            for item in config.nodes.items
            if item.node_id.casefold() == config.nodes.local_node_id.casefold()
        ),
        None,
    )
    root = tk.Tk()
    root.title("Ray Cluster Manager - Local setup")
    root.resizable(False, False)
    frame = tk.Frame(root, padx=14, pady=14)
    frame.pack(fill="both", expand=True)
    tk.Label(
        frame,
        text=(
            "Configure this PC only. No password, token, or remote command "
            "setting is accepted here."
        ),
        justify="left",
        wraplength=460,
    ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
    node_id = tk.StringVar(value=current.node_id if current else "local-pc")
    address = tk.StringVar(value=current.address if current else "127.0.0.1")
    role = tk.StringVar(value=current.role if current else "worker")
    cpu_count = tk.StringVar(value=str(current.cpu_count if current else 0))
    monitoring = tk.BooleanVar(value=config.monitoring.enabled)
    minimized = tk.BooleanVar(value=config.app.start_minimized)
    rows = (
        ("Local node ID", node_id),
        ("Address or host name", address),
        ("CPU count (0 = automatic)", cpu_count),
    )
    first_entry = None
    for offset, (label, variable) in enumerate(rows, start=1):
        tk.Label(frame, text=label).grid(
            row=offset, column=0, sticky="w", padx=(0, 10), pady=3
        )
        entry = tk.Entry(frame, textvariable=variable, width=34)
        entry.grid(
            row=offset, column=1, sticky="ew", pady=3
        )
        if first_entry is None:
            first_entry = entry
    tk.Label(frame, text="Role").grid(
        row=4, column=0, sticky="w", padx=(0, 10), pady=3
    )
    tk.OptionMenu(frame, role, "worker", "head", "observer").grid(
        row=4, column=1, sticky="ew", pady=3
    )
    tk.Checkbutton(
        frame,
        text="Enable monitoring when the service is available",
        variable=monitoring,
    ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 2))
    tk.Checkbutton(
        frame, text="Start minimized", variable=minimized
    ).grid(row=6, column=0, columnspan=2, sticky="w", pady=2)
    status = tk.StringVar(value="")
    tk.Label(
        frame, textvariable=status, fg="#800000", justify="left",
        wraplength=460,
    ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
    result: list[Config] = []

    def save() -> None:
        updated, error = _configuration_form_result(
            config,
            node_id=node_id.get(),
            address=address.get(),
            role=role.get(),
            cpu_count=cpu_count.get(),
            monitoring_enabled=monitoring.get(),
            start_minimized=minimized.get(),
        )
        if updated is None:
            status.set(error)
            if first_entry is not None:
                first_entry.focus_set()
            return
        result.append(updated)
        root.destroy()

    buttons = tk.Frame(frame)
    buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(12, 0))
    tk.Button(buttons, text="Save", width=10, command=save).pack(
        side="left", padx=(0, 6)
    )
    tk.Button(buttons, text="Cancel", width=10, command=root.destroy).pack(
        side="left"
    )
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Return>", lambda _event: save())
    root.bind("<Escape>", lambda _event: root.destroy())
    if first_entry is not None:
        first_entry.focus_set()
    root.mainloop()
    return result[0] if result else None


def run_configuration_wizard() -> int:
    """Load, display, validate, and durably save local setup state."""

    import os
    import sys

    environment = Environment(
        {
            key: os.environ[key]
            for key in ("RCM_RUNTIME_MODE", "RCM_PORTABLE")
            if key in os.environ
        }
    )
    plan = host_bootstrap_plan(
        environment,
        frozen=bool(getattr(sys, "frozen", False)),
    )
    stored = initialize_runtime_config(plan)
    updated = _configuration_dialog(stored.config)
    if updated is None or updated == stored.config:
        return 0
    ConfigStore(Path(str(plan.paths.config_file))).save(
        updated,
        expected_generation=stored.generation,
    )
    return 0


def run_internal_configuration_check() -> int:
    """Exercise packaged create/reload against a verifier-owned data root."""

    import os
    import sys

    expectation = os.environ.get("RCM_CONFIGURATION_EXPECT")
    if (
        not getattr(sys, "frozen", False)
        or os.environ.get("RCM_INTERNAL_CONFIGURATION_CHECK") != "1"
        or expectation not in {"create", "reload"}
    ):
        return 2
    environment = Environment(
        {
            key: os.environ[key]
            for key in ("RCM_RUNTIME_MODE", "RCM_PORTABLE")
            if key in os.environ
        }
    )
    plan = host_bootstrap_plan(environment, frozen=True)
    config_path = Path(str(plan.paths.config_file))
    existed = config_path.exists()
    if existed == (expectation == "create"):
        return 3
    from .foundation_check import _deny_network_and_children

    with _deny_network_and_children() as counters:
        stored = initialize_runtime_config(plan)
        first_bytes = config_path.read_bytes()
        reloaded = initialize_runtime_config(plan)
        second_bytes = config_path.read_bytes()
    if (
        any(counters.values())
        or stored.generation != 1
        or reloaded != stored
        or first_bytes != second_bytes
        or config_path.is_symlink()
        or not config_path.is_file()
        or stored.config.app.environment != plan.identity.deployment.value
    ):
        return 4
    return 0


__all__ = (
    "configure_local_node",
    "host_bootstrap_plan",
    "initialize_runtime_config",
    "run_internal_configuration_check",
    "run_configuration_wizard",
)
