"""Tests for configuration source precedence and parsing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from muninn.config import (
    ExecutionMode,
    configuration,
    get_execution_mode,
    get_fallback_on_invalid_result,
    get_parser_paths,
    load_env_config,
    set_execution_mode,
    set_fallback_on_invalid_result,
    set_parser_paths,
)


@pytest.fixture(autouse=True)
def reset_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset configuration and relevant environment variables per test."""
    monkeypatch.delenv("MUNINN_PARSER_EXECUTION_MODE", raising=False)
    monkeypatch.delenv("MUNINN_FALLBACK_ON_INVALID_RESULT", raising=False)
    monkeypatch.delenv("MUNINN_PARSER_PATHS", raising=False)
    configuration.reset_api_overrides()


def test_pyproject_settings_are_loaded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Settings are read from [tool.muninn] in pyproject.toml."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[tool.muninn]\n"
        'parser_execution_mode = "centralized_first_fallback"\n'
        "fallback_on_invalid_result = false\n"
        'parser_paths = ["./parsers"]\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    load_env_config()

    assert get_execution_mode() is ExecutionMode.CENTRALIZED_FIRST_FALLBACK
    assert get_fallback_on_invalid_result() is False
    assert get_parser_paths() == ((tmp_path / "parsers").resolve(),)


def test_environment_overrides_pyproject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Environment values take precedence over pyproject values."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.muninn]\nparser_execution_mode = "local_only"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MUNINN_PARSER_EXECUTION_MODE", "local_first_fallback")

    load_env_config()

    assert get_execution_mode() is ExecutionMode.LOCAL_FIRST_FALLBACK


def test_api_overrides_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """API overrides take precedence over environment values."""
    monkeypatch.setenv("MUNINN_PARSER_EXECUTION_MODE", "centralized_first_fallback")
    set_execution_mode(ExecutionMode.LOCAL_ONLY)
    load_env_config()

    assert get_execution_mode() is ExecutionMode.LOCAL_ONLY


def test_parser_paths_from_environment_pathsep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parser path env var supports OS path separator syntax."""
    first = Path("/tmp/one")
    second = Path("/tmp/two")
    monkeypatch.setenv(
        "MUNINN_PARSER_PATHS",
        f"{first}{os.pathsep}{second}",
    )

    load_env_config()

    assert get_parser_paths() == (first.resolve(), second.resolve())


def test_api_setters_update_values() -> None:
    """API setters modify in-process configuration values."""
    set_execution_mode("local_only")
    set_fallback_on_invalid_result(False)
    set_parser_paths(["./custom"])

    assert get_execution_mode() is ExecutionMode.LOCAL_ONLY
    assert get_fallback_on_invalid_result() is False
    assert len(get_parser_paths()) == 1
