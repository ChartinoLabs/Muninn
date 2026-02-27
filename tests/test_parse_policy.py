"""Tests for parser execution policies and fallback behavior."""

from __future__ import annotations

from typing import Any

import pytest

from muninn import registry
from muninn.config import (
    ExecutionMode,
    set_execution_mode,
    set_fallback_on_invalid_result,
)
from muninn.core import parse
from muninn.exceptions import ParseError, ParserNotFoundError
from muninn.parser import BaseParser


@pytest.fixture(autouse=True)
def reset_registry_and_config() -> None:
    """Reset parser registry and runtime policy before each test."""
    registry._registry.clear()
    set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)
    set_fallback_on_invalid_result(True)


def test_local_first_falls_back_to_built_in_on_exception() -> None:
    """Local-first mode falls back to built-in on local exception."""

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                raise RuntimeError("boom")

    result = parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_centralized_first_uses_built_in_before_local() -> None:
    """Centralized-first mode prioritizes built-in parser."""
    set_execution_mode(ExecutionMode.CENTRALIZED_FIRST_FALLBACK)

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"source": "local"}

    result = parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_local_only_ignores_built_in_parsers() -> None:
    """Local-only mode does not execute centralized parser candidates."""
    set_execution_mode(ExecutionMode.LOCAL_ONLY)

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with pytest.raises(ParserNotFoundError):
        parse("nxos", "show version", "show version output")


def test_fallback_on_none_result() -> None:
    """Parser result of None triggers fallback."""

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any] | None:
                return None

    result = parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_fallback_on_empty_dict_result() -> None:
    """Parser result of empty dict triggers fallback."""

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

    result = parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_parse_error_when_all_candidates_fail() -> None:
    """Raise ParseError when all parser candidates fail."""

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            raise RuntimeError("built-in failure")

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

    with pytest.raises(ParseError):
        parse("nxos", "show version", "show version output")


def test_execution_mode_is_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Execution mode env var is honored without API configuration."""
    monkeypatch.setenv("MUNINN_PARSER_EXECUTION_MODE", "centralized_first_fallback")

    @registry.register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    with registry.registration_source("local"):

        @registry.register("nxos", "show version")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"source": "local"}

    result = parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}
