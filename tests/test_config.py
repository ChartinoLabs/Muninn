"""Tests for configuration source loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from muninn.config import configuration


def test_reload_succeeds_with_no_values() -> None:
    """Configuration loading succeeds when no values are provided."""
    configuration.reload()


def test_reload_accepts_tool_muninn_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Configuration loading accepts a [tool.muninn] section."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.muninn]\nplaceholder = "value"\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    configuration.reload()
