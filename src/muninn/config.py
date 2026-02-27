"""Centralized runtime configuration with layered sources."""

from __future__ import annotations

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    PyprojectTomlConfigSettingsSource,
    SettingsConfigDict,
)


class _RuntimeSettings(BaseSettings):
    """Settings resolved from environment and pyproject."""

    parser_backend: str = "native"
    retries: int = 0
    feature_enabled: bool = False

    model_config = SettingsConfigDict(
        env_prefix="MUNINN_",
        pyproject_toml_table_header=("tool", "muninn"),
        pyproject_toml_depth=8,
        extra="ignore",
    )

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
        loaded = _RuntimeSettings().model_dump()
        merged = {**loaded, **self._api_overrides}
        self._settings = merged

    def set_parser_backend(self, value: str) -> None:
        """Set parser backend as an API override."""
        self._api_overrides["parser_backend"] = value
        self.reload()

    def get_parser_backend(self) -> str:
        """Get resolved parser backend."""
        return str(self._settings["parser_backend"])

    def set_retries(self, value: int) -> None:
        """Set retry count as an API override."""
        self._api_overrides["retries"] = value
        self.reload()

    def get_retries(self) -> int:
        """Get resolved retry count."""
        return int(self._settings["retries"])

    def set_feature_enabled(self, value: bool) -> None:
        """Set feature toggle as an API override."""
        self._api_overrides["feature_enabled"] = value
        self.reload()

    def get_feature_enabled(self) -> bool:
        """Get resolved feature toggle."""
        return bool(self._settings["feature_enabled"])

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


def set_parser_backend(value: str) -> None:
    """Set parser backend through the global configuration object."""
    configuration.set_parser_backend(value)


def get_parser_backend() -> str:
    """Get parser backend through the global configuration object."""
    return configuration.get_parser_backend()


def set_retries(value: int) -> None:
    """Set retry count through the global configuration object."""
    configuration.set_retries(value)


def get_retries() -> int:
    """Get retry count through the global configuration object."""
    return configuration.get_retries()


def set_feature_enabled(value: bool) -> None:
    """Set feature toggle through the global configuration object."""
    configuration.set_feature_enabled(value)


def get_feature_enabled() -> bool:
    """Get feature toggle through the global configuration object."""
    return configuration.get_feature_enabled()


def get_settings() -> dict[str, object]:
    """Get all resolved settings through the global configuration object."""
    return configuration.as_dict()
