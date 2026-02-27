"""Centralized runtime configuration with layered sources."""

from __future__ import annotations

import json
from typing import Annotated, TypeVar

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    PyprojectTomlConfigSettingsSource,
    SettingsConfigDict,
)

T = TypeVar("T")


class _RuntimeSettings(BaseSettings):
    """Settings resolved from environment and pyproject."""

    settings: Annotated[dict[str, object], NoDecode] = Field(default_factory=dict)

    model_config = SettingsConfigDict(
        env_prefix="MUNINN_",
        pyproject_toml_table_header=("tool", "muninn"),
        pyproject_toml_depth=8,
        extra="ignore",
    )

    @field_validator("settings", mode="before")
    @classmethod
    def _parse_settings(cls, value: object) -> object:
        if value is None:
            return {}
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:
                msg = "MUNINN_SETTINGS must be valid JSON"
                raise ValueError(msg) from exc
            if not isinstance(parsed, dict):
                msg = "MUNINN_SETTINGS JSON must decode to an object"
                raise ValueError(msg)
            return parsed
        return value

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        del dotenv_settings
        return (
            init_settings,
            env_settings,
            PyprojectTomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )


class Configuration:
    """Configuration singleton with API > env > pyproject precedence."""

    def __init__(self) -> None:
        """Initialize API overrides and the resolved settings cache."""
        self._api_overrides: dict[str, object] = {}
        self._settings: dict[str, object] = {}
        self.reload()

    def reload(self) -> None:
        """Reload settings from environment and pyproject, preserving API overrides."""
        loaded = _RuntimeSettings().settings
        merged = {**loaded, **self._api_overrides}
        self._settings = merged

    def set(self, name: str, value: object) -> None:
        """Set an API override value for a named setting."""
        self._api_overrides[name] = value
        self.reload()

    def get(self, name: str, default: T | None = None) -> object | T | None:
        """Get a setting value by name."""
        return self._settings.get(name, default)

    def as_dict(self) -> dict[str, object]:
        """Return a copy of all resolved settings."""
        return dict(self._settings)

    def reset_api_overrides(self) -> None:
        """Clear API overrides and reload source-backed values."""
        self._api_overrides.clear()
        self.reload()


configuration = Configuration()


def load_config() -> None:
    """Reload configuration from API/env/pyproject sources."""
    try:
        configuration.reload()
    except Exception as exc:  # noqa: BLE001
        raise ValueError(str(exc)) from exc


def set_setting(name: str, value: object) -> None:
    """Set a named setting through the global configuration object."""
    configuration.set(name, value)


def get_setting(name: str, default: T | None = None) -> object | T | None:
    """Get a named setting through the global configuration object."""
    return configuration.get(name, default)


def get_settings() -> dict[str, object]:
    """Get all resolved settings through the global configuration object."""
    return configuration.as_dict()


def validate_config() -> None:
    """Validate settings sources and raise ValueError on invalid data."""
    try:
        _RuntimeSettings()
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc
