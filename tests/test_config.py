"""Tests for configuration source precedence and parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from muninn.config import (
    configuration,
    get_setting,
    get_settings,
    load_config,
    set_setting,
)


@pytest.fixture(autouse=True)
def reset_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset configuration and relevant environment variables per test."""
    monkeypatch.delenv("MUNINN_SETTINGS", raising=False)
    configuration.reset_api_overrides()


def test_pyproject_settings_are_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Settings are read from [tool.muninn].settings in pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.muninn]\nsettings = { parser_backend = "native", retries = 2 }\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    load_config()

    assert get_setting("parser_backend") == "native"
    assert get_setting("retries") == 2


def test_environment_overrides_pyproject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Environment settings take precedence over pyproject settings."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.muninn]\nsettings = { parser_backend = "native", retries = 2 }\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "MUNINN_SETTINGS",
        '{"parser_backend": "env", "feature_enabled": true}',
    )

    load_config()

    assert get_setting("parser_backend") == "env"
    assert get_setting("feature_enabled") is True


def test_api_overrides_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """API-set values take precedence over environment values."""
    monkeypatch.setenv("MUNINN_SETTINGS", '{"parser_backend": "env"}')
    set_setting("parser_backend", "api")
    load_config()

    assert get_setting("parser_backend") == "api"


def test_get_settings_returns_resolved_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolved settings include loaded and API-overridden values."""
    monkeypatch.setenv("MUNINN_SETTINGS", '{"retries": 1}')
    set_setting("feature_enabled", True)

    values = get_settings()

    assert values["retries"] == 1
    assert values["feature_enabled"] is True


def test_invalid_env_json_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid JSON for MUNINN_SETTINGS raises ValueError."""
    monkeypatch.setenv("MUNINN_SETTINGS", "not-json")

    with pytest.raises(ValueError, match="MUNINN_SETTINGS"):
        load_config()
