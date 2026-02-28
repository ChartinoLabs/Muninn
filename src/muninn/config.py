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
    """Configuration singleton for source loading and validation."""

    def __init__(self) -> None:
        """Initialize and validate configured sources."""
        self.reload()

    def reload(self) -> None:
        """Reload and validate configuration from all sources."""
        _RuntimeSettings()


configuration = Configuration()


def load_config() -> None:
    """Reload configuration from environment and pyproject."""
    try:
        configuration.reload()
    except Exception as exc:  # noqa: BLE001
        raise ValueError(str(exc)) from exc
