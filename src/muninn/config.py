"""Runtime configuration for parser execution and local overlays."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

from pydantic import field_validator
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    PyprojectTomlConfigSettingsSource,
    SettingsConfigDict,
)


class ExecutionMode(StrEnum):
    """Parser execution order and fallback behavior."""

    CENTRALIZED_FIRST_FALLBACK = "centralized_first_fallback"
    LOCAL_FIRST_FALLBACK = "local_first_fallback"
    LOCAL_ONLY = "local_only"


class _RuntimeSettings(BaseSettings):
    """Settings resolved from API overrides, environment, and pyproject."""

    parser_paths: Annotated[tuple[Path, ...], NoDecode] = ()
    parser_execution_mode: ExecutionMode = ExecutionMode.LOCAL_FIRST_FALLBACK
    fallback_on_invalid_result: bool = True

    model_config = SettingsConfigDict(
        env_prefix="MUNINN_",
        pyproject_toml_table_header=("tool", "muninn"),
        pyproject_toml_depth=8,
        extra="ignore",
    )

    @field_validator("parser_paths", mode="before")
    @classmethod
    def _split_parser_paths(cls, value: object) -> object:
        if value is None:
            return ()
        if isinstance(value, str):
            return [path for path in value.split(os.pathsep) if path.strip()]
        return value

    @field_validator("parser_paths", mode="after")
    @classmethod
    def _normalize_parser_paths(cls, paths: tuple[Path, ...]) -> tuple[Path, ...]:
        return tuple(Path(path).expanduser().resolve() for path in paths)

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
    """Centralized runtime configuration singleton."""

    def __init__(self) -> None:
        """Initialize configuration state and API override storage."""
        self._api_overrides: dict[str, Any] = {}
        self._settings = _RuntimeSettings()

    def reload(self) -> None:
        """Reload settings from configured sources."""
        self._settings = _RuntimeSettings(**self._api_overrides)

    def set_execution_mode(self, mode: ExecutionMode | str) -> None:
        """Set parser execution mode as an API override."""
        self._api_overrides["parser_execution_mode"] = ExecutionMode(mode)
        self.reload()

    def get_execution_mode(self) -> ExecutionMode:
        """Get current parser execution mode."""
        return self._settings.parser_execution_mode

    def set_fallback_on_invalid_result(self, enabled: bool) -> None:
        """Enable or disable fallback on None/empty dict parser results."""
        self._api_overrides["fallback_on_invalid_result"] = enabled
        self.reload()

    def get_fallback_on_invalid_result(self) -> bool:
        """Return whether fallback on None/empty dict is enabled."""
        return self._settings.fallback_on_invalid_result

    def set_parser_paths(
        self, paths: list[str | Path] | tuple[str | Path, ...]
    ) -> None:
        """Set parser overlay search paths as an API override."""
        normalized = tuple(Path(path).expanduser().resolve() for path in paths)
        self._api_overrides["parser_paths"] = normalized
        self.reload()

    def get_parser_paths(self) -> tuple[Path, ...]:
        """Get configured parser overlay search paths."""
        return self._settings.parser_paths

    def reset_api_overrides(self) -> None:
        """Clear API overrides and reload source-backed settings."""
        self._api_overrides.clear()
        self.reload()


configuration = Configuration()


def load_env_config() -> None:
    """Reload configuration from API/env/pyproject sources."""
    configuration.reload()


def set_execution_mode(mode: ExecutionMode | str) -> None:
    """Set parser execution mode for candidate ordering and fallback."""
    configuration.set_execution_mode(mode)


def get_execution_mode() -> ExecutionMode:
    """Get current parser execution mode."""
    return configuration.get_execution_mode()


def set_fallback_on_invalid_result(enabled: bool) -> None:
    """Enable or disable fallback on None/empty dict parser results."""
    configuration.set_fallback_on_invalid_result(enabled)


def get_fallback_on_invalid_result() -> bool:
    """Return whether fallback on None/empty dict is enabled."""
    return configuration.get_fallback_on_invalid_result()


def set_parser_paths(paths: list[str | Path] | tuple[str | Path, ...]) -> None:
    """Set parser overlay search paths used by load_local_parsers."""
    configuration.set_parser_paths(paths)


def get_parser_paths() -> tuple[Path, ...]:
    """Get configured parser overlay search paths."""
    return configuration.get_parser_paths()
