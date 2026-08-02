"""Typed settings draft with no secret-bearing controls."""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..config.schema import AppSection, Config, MonitoringSection, UiSection


@dataclass(frozen=True, slots=True)
class SettingsDraft:
    theme: str
    scale_percent: int
    compact_view: bool
    locale: str
    start_minimized: bool
    log_level: str
    monitoring_enabled: bool
    monitoring_interval_ms: int
    autostart: bool = False

    def __post_init__(self) -> None:
        if self.theme not in {"system", "light", "dark"}:
            raise ValueError("theme must be system, light, or dark")
        if type(self.scale_percent) is not int or not 50 <= self.scale_percent <= 300:
            raise ValueError("scale_percent must be between 50 and 300")
        if type(self.compact_view) is not bool:
            raise TypeError("compact_view must be a bool")
        if not isinstance(self.locale, str) or len(self.locale) > 32:
            raise ValueError("locale is invalid")
        if type(self.start_minimized) is not bool:
            raise TypeError("start_minimized must be a bool")
        if self.log_level not in {"debug", "info", "warning", "error"}:
            raise ValueError("log_level is invalid")
        if type(self.monitoring_enabled) is not bool:
            raise TypeError("monitoring_enabled must be a bool")
        if type(self.monitoring_interval_ms) is not int or not (
            100 <= self.monitoring_interval_ms <= 3_600_000
        ):
            raise ValueError("monitoring_interval_ms is outside its supported range")
        if type(self.autostart) is not bool:
            raise TypeError("autostart must be a bool")

    @classmethod
    def from_config(
        cls,
        config: Config,
        *,
        autostart: bool = False,
    ) -> SettingsDraft:
        if not isinstance(config, Config):
            raise TypeError("config must be a Config")
        return cls(
            config.ui.theme,
            config.ui.scale_percent,
            config.ui.compact_view,
            config.ui.locale,
            config.app.start_minimized,
            config.app.log_level,
            config.monitoring.enabled,
            config.monitoring.interval_ms,
            autostart,
        )

    def apply(self, config: Config) -> Config:
        if not isinstance(config, Config):
            raise TypeError("config must be a Config")
        return replace(
            config,
            app=replace(
                config.app,
                start_minimized=self.start_minimized,
                log_level=self.log_level,
            ),
            ui=replace(
                config.ui,
                theme=self.theme,
                scale_percent=self.scale_percent,
                compact_view=self.compact_view,
                locale=self.locale,
            ),
            monitoring=replace(
                config.monitoring,
                enabled=self.monitoring_enabled,
                interval_ms=self.monitoring_interval_ms,
            ),
        )


def settings_sections() -> tuple[str, ...]:
    return ("Appearance", "Monitoring", "Startup")


__all__ = ("SettingsDraft", "settings_sections", "AppSection", "UiSection",
           "MonitoringSection")
