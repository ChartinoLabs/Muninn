"""Tests for parser execution policies and fallback behavior."""

from __future__ import annotations

from typing import Any

import pytest

from muninn.config import ExecutionMode
from muninn.exceptions import ParseError, ParserAmbiguityError, ParserNotFoundError
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.runtime import Muninn
from muninn.tags import ParserTag


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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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
        tags = frozenset({ParserTag.SYSTEM})

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


def test_instance_parse_accepts_keyword_arguments(runtime: Muninn) -> None:
    """Instance parse supports keyword arguments."""

    @register("nxos", "show version")
    class BuiltInParser(BaseParser):
        tags = frozenset({ParserTag.SYSTEM})

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"source": "built_in"}

    runtime.registry.register_parser("nxos", "show version", BuiltInParser, "built_in")

    result = runtime.parse(
        os="nxos",
        command="show version",
        output="show version output",
    )
    assert result == {"source": "built_in"}


def test_class_parse_accepts_keyword_arguments() -> None:
    """Class parse supports keyword arguments."""
    result = Muninn.parse(
        os="iosxe",
        command="show lldp neighbors",
        output=(
            "Capability codes:\n"
            "R - Router, B - Bridge, T - Telephone, C - DOCSIS Cable Device\n"
            "W - WLAN Access Point, P - Repeater, S - Station, O - Other\n"
            "\n"
            "Device ID    Local Intf     Hold-time  Capability  Port ID\n"
            "switch-1     Gi0/1          120        B,R         Gi1/0/24\n"
            "\n"
            "Total entries displayed: 1\n"
        ),
    )
    assert result["total_entries"] == 1


def test_parse_prefers_literal_over_pattern(runtime: Muninn) -> None:
    """Exact literal registrations win before regex matches."""

    @register("ios", "show ip ospf neighbors")
    class LiteralParser(BaseParser):
        tags = frozenset({ParserTag.SYSTEM})

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"kind": "literal"}

    @register("ios", r"show ip ospf (?P<token>\S+)")
    class PatternParser(BaseParser):
        tags = frozenset({ParserTag.SYSTEM})

        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"kind": "pattern"}

    runtime.registry.register_parser(
        "ios", "show ip ospf neighbors", LiteralParser, "built_in"
    )
    runtime.registry.register_parser(
        "ios", r"show ip ospf (?P<token>\S+)", PatternParser, "built_in"
    )

    result = runtime.parse("ios", "show ip ospf neighbors", "output")
    assert result == {"kind": "literal"}


def test_parse_raises_ambiguity_for_same_source_pattern_overlap(
    runtime: Muninn,
) -> None:
    """Same-source overlapping pattern matches raise ambiguity errors."""

    @register("ios", r"show ip ospf (?P<token>\S+)")
    class GenericParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"kind": "generic"}

    @register("ios", r"show ip ospf (?P<process_id>\d+)")
    class ProcessParser(BaseParser):
        @classmethod
        def parse(cls, output: str) -> dict[str, Any]:
            return {"kind": "process"}

    runtime.registry.register_parser(
        "ios", r"show ip ospf (?P<token>\S+)", GenericParser, "local"
    )
    runtime.registry.register_parser(
        "ios", r"show ip ospf (?P<process_id>\d+)", ProcessParser, "local"
    )

    with pytest.raises(ParserAmbiguityError):
        runtime.parse("ios", "show ip ospf 5", "output")
