"""Tests for parser execution policies and fallback behavior."""

from __future__ import annotations

from typing import Any

import pytest

from muninn.config import ExecutionMode
from muninn.exceptions import ParseError, ParserNotFoundError
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.runtime import Muninn


@pytest.fixture
def runtime() -> Muninn:
    """Create an isolated runtime for each test."""
    return Muninn(autoload_builtins=False)


def test_local_first_falls_back_to_built_in_on_exception(
    runtime: Muninn,
) -> None:
    """Local-first mode falls back to built-in on local exception."""
    runtime.configuration.set_execution_mode(ExecutionMode.LOCAL_FIRST_FALLBACK)

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            raise RuntimeError("boom")

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_centralized_first_uses_built_in_before_local(runtime: Muninn) -> None:
    """Centralized-first mode prioritizes built-in parser."""
    runtime.configuration.set_execution_mode(ExecutionMode.CENTRALIZED_FIRST_FALLBACK)

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "local"}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_local_only_ignores_built_in_parsers(runtime: Muninn) -> None:
    """Local-only mode does not execute centralized parser candidates."""
    runtime.configuration.set_execution_mode(ExecutionMode.LOCAL_ONLY)

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")

    with pytest.raises(ParserNotFoundError):
        runtime.parse("nxos", "show version", "show version output")


def test_fallback_on_none_result(runtime: Muninn) -> None:
    """Parser result of None triggers fallback."""

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any] | None:
            return None

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_fallback_on_empty_dict_result(runtime: Muninn) -> None:
    """Parser result of empty dict triggers fallback."""

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}


def test_parse_error_when_all_candidates_fail(runtime: Muninn) -> None:
    """Raise ParseError when all parser candidates fail."""

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            raise RuntimeError("built-in failure")

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    with pytest.raises(ParseError):
        runtime.parse("nxos", "show version", "show version output")


def test_execution_mode_is_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    runtime: Muninn,
) -> None:
    """Execution mode env var is honored without API configuration."""
    runtime.configuration.clear_api_overrides()
    monkeypatch.setenv("MUNINN_PARSER_EXECUTION_MODE", "centralized_first_fallback")

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    @register("nxos", "show version")
    class LocalParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "local"}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")
    runtime.registry.register_parser("nxos", "show version", LocalParser, "local")

    result = runtime.parse("nxos", "show version", "show version output")
    assert result == {"source": "built_in"}
