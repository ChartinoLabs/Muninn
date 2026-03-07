"""Centralized runtime configuration with layered sources."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from typing import TypeAlias, cast

from pydantic import field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    PyprojectTomlConfigSettingsSource,
    SettingsConfigDict,
)


class ExecutionMode(StrEnum):
    """Parser execution order and fallback behavior."""

    # Try the built-in parser first. If it raises or returns an invalid result,
    # attempt a local overlay parser for the same OS/command.
    CENTRALIZED_FIRST_FALLBACK = "centralized_first_fallback"

    # Try a local overlay parser first. If it raises or returns an invalid
    # result, fall back to the built-in parser for the same OS/command.
    LOCAL_FIRST_FALLBACK = "local_first_fallback"

    # Only local overlay parsers are considered. Built-in parsers are ignored,
    # and no fallback to centralized parsers is performed.
    LOCAL_ONLY = "local_only"


class _RuntimeSettings(BaseSettings):
    """Settings resolved from environment and pyproject."""

    model_config = SettingsConfigDict(
        env_prefix="MUNINN_",
        pyproject_toml_table_header=("tool", "muninn"),
        pyproject_toml_depth=8,
        extra="ignore",
    )

    parser_execution_mode: ExecutionMode = ExecutionMode.LOCAL_FIRST_FALLBACK
    fallback_on_invalid_result: bool = True
    parser_paths: tuple[Path, ...] = ()

    @field_validator("parser_paths", mode="before")
    @classmethod
    def _parse_parser_paths(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(
                Path(path).expanduser().resolve()
                for path in value.split(os.pathsep)
                if path.strip()
            )
        if isinstance(value, list):
            parsed_paths: list[Path] = []
            for path in value:
                if not isinstance(path, str | Path):
                    return value
                parsed_paths.append(Path(path).expanduser().resolve())
            return tuple(parsed_paths)
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


ConfigurationOverride: TypeAlias = ExecutionMode | bool | tuple[Path, ...]


class Configuration:
    """Runtime configuration for source loading and validation."""

    def __init__(self) -> None:
        """Initialize and validate configured sources."""
        self._settings = _RuntimeSettings()
        self._overrides: dict[str, ConfigurationOverride] = {}

    def reload(self) -> None:
        """Reload and validate configuration from all sources."""
        self._settings = _RuntimeSettings()

    def get_execution_mode(self) -> ExecutionMode:
        """Get parser execution mode from overrides or loaded sources."""
        override = self._overrides.get("parser_execution_mode")
        if override is None:
            return self._settings.parser_execution_mode
        return cast(ExecutionMode, override)

    def set_execution_mode(self, mode: ExecutionMode | str) -> None:
        """Set parser execution mode as an API override."""
        if isinstance(mode, str):
            normalized_mode = ExecutionMode(mode.strip().lower())
            self._overrides["parser_execution_mode"] = normalized_mode
            return
        self._overrides["parser_execution_mode"] = mode

    def get_fallback_on_invalid_result(self) -> bool:
        """Get fallback-on-invalid-result setting from overrides or sources."""
        override = self._overrides.get("fallback_on_invalid_result")
        if override is None:
            return self._settings.fallback_on_invalid_result
        return cast(bool, override)

    def set_fallback_on_invalid_result(self, enabled: bool) -> None:
        """Set fallback-on-invalid-result as an API override."""
        self._overrides["fallback_on_invalid_result"] = enabled

    def get_parser_paths(self) -> tuple[Path, ...]:
        """Get parser overlay search paths from overrides or sources."""
        override = self._overrides.get("parser_paths")
        if override is None:
            return self._settings.parser_paths
        return cast(tuple[Path, ...], override)

    def set_parser_paths(
        self, paths: list[str | Path] | tuple[str | Path, ...]
    ) -> None:
        """Set parser overlay search paths as an API override."""
        self._overrides["parser_paths"] = tuple(
            Path(path).expanduser().resolve() for path in paths
        )

    def clear_api_overrides(self) -> None:
        """Remove all API overrides and use source-resolved values."""
        self._overrides.clear()
