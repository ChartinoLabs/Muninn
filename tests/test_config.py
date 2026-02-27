"""Tests for configuration source precedence and parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from muninn.config import (
    configuration,
    get_feature_enabled,
    get_parser_backend,
    get_retries,
    get_settings,
    load_config,
    set_feature_enabled,
    set_parser_backend,
    set_retries,
)


@pytest.fixture(autouse=True)
def reset_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset configuration and relevant environment variables per test."""
    monkeypatch.delenv("MUNINN_PARSER_BACKEND", raising=False)
    monkeypatch.delenv("MUNINN_RETRIES", raising=False)
    monkeypatch.delenv("MUNINN_FEATURE_ENABLED", raising=False)
    configuration.reset_api_overrides()


def test_pyproject_settings_are_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Settings are read from [tool.muninn] in pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.muninn]\n"
        'parser_backend = "native"\n'
        "retries = 2\n"
        "feature_enabled = true\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    load_config()

    assert get_parser_backend() == "native"
    assert get_retries() == 2
    assert get_feature_enabled() is True


def test_environment_overrides_pyproject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Environment values take precedence over pyproject values."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.muninn]\nparser_backend = "native"\nretries = 1\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MUNINN_PARSER_BACKEND", "env")
    monkeypatch.setenv("MUNINN_RETRIES", "4")

    load_config()

    assert get_parser_backend() == "env"
    assert get_retries() == 4


def test_api_overrides_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """API-set values take precedence over environment values."""
    monkeypatch.setenv("MUNINN_PARSER_BACKEND", "env")
    set_parser_backend("api")
    load_config()

    assert get_parser_backend() == "api"


def test_get_settings_returns_resolved_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolved settings include loaded and API-overridden values."""
    monkeypatch.setenv("MUNINN_RETRIES", "1")
    set_feature_enabled(True)

    values = get_settings()

    assert values["retries"] == 1
    assert values["feature_enabled"] is True


def test_invalid_env_value_raises_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invalid type in environment raises ValueError."""
    monkeypatch.setenv("MUNINN_RETRIES", "not-an-int")

    with pytest.raises(ValueError, match="retries"):
        load_config()


def test_api_setters_update_values() -> None:
    """Dedicated API setters update in-process values."""
    set_parser_backend("custom")
    set_retries(9)
    set_feature_enabled(True)

    assert get_parser_backend() == "custom"
    assert get_retries() == 9
    assert get_feature_enabled() is True
