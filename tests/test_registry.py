"""Tests for muninn.registry module."""

from typing import Any

import pytest

from muninn import registry
from muninn.exceptions import ParserNotFoundError


@pytest.fixture(autouse=True)
def clear_registry() -> None:
    """Clear the parser registry before each test."""
    registry._registry.clear()


class TestNormalizeCommand:
    """Tests for _normalize_command function."""

    @pytest.mark.parametrize(
        ("input_cmd", "expected"),
        [
            ("SHOW IP OSPF", "show ip ospf"),  # lowercase
            ("  show ip ospf", "show ip ospf"),  # leading whitespace
            ("show ip ospf  ", "show ip ospf"),  # trailing whitespace
            ("show  ip   ospf", "show ip ospf"),  # multiple spaces
            ("show\tip\tospf", "show ip ospf"),  # tabs
            ("", ""),  # empty string
            ("show ip ospf", "show ip ospf"),  # already normalized
            ("  SHOW  IP  OSPF  ", "show ip ospf"),  # combined
        ],
        ids=[
            "lowercase",
            "leading_whitespace",
            "trailing_whitespace",
            "multiple_spaces",
            "tabs",
            "empty_string",
            "already_normalized",
            "combined",
        ],
    )
    def test_normalize_command(self, input_cmd: str, expected: str) -> None:
        """Command normalization handles various input formats."""
        assert registry._normalize_command(input_cmd) == expected


class TestRegister:
    """Tests for register decorator."""

    def test_registers_parser(self) -> None:
        """Decorator registers the parser function."""

        @registry.register("nxos", "show version")
        def parse_show_version(output: str) -> dict[str, Any]:
            return {"version": "1.0"}

        assert ("nxos", "show version") in registry._registry
        assert registry._registry[("nxos", "show version")] is parse_show_version

    def test_returns_original_function(self) -> None:
        """Decorator returns the original function unchanged."""

        def parse_show_version(output: str) -> dict[str, Any]:
            return {"version": "1.0"}

        decorated = registry.register("nxos", "show version")(parse_show_version)
        assert decorated is parse_show_version

    @pytest.mark.parametrize(
        ("register_os", "register_cmd", "expected_key"),
        [
            ("NXOS", "show version", ("nxos", "show version")),
            ("nxos", "  SHOW  VERSION  ", ("nxos", "show version")),
            ("IOSXE", "  SHOW  IP  ROUTE  ", ("iosxe", "show ip route")),
        ],
        ids=["normalizes_os", "normalizes_command", "normalizes_both"],
    )
    def test_normalizes_on_registration(
        self, register_os: str, register_cmd: str, expected_key: tuple[str, str]
    ) -> None:
        """OS and command are normalized during registration."""

        @registry.register(register_os, register_cmd)
        def parser(output: str) -> dict[str, Any]:
            return {}

        assert expected_key in registry._registry


class TestGetParser:
    """Tests for get_parser function."""

    def test_returns_registered_parser(self) -> None:
        """Returns the registered parser function."""

        @registry.register("nxos", "show version")
        def parse_show_version(output: str) -> dict[str, Any]:
            return {"version": "1.0"}

        parser = registry.get_parser("nxos", "show version")
        assert parser is parse_show_version

    @pytest.mark.parametrize(
        ("lookup_os", "lookup_cmd"),
        [
            ("NXOS", "show version"),
            ("nxos", "  SHOW  VERSION  "),
            ("NXOS", "  SHOW  VERSION  "),
        ],
        ids=["normalizes_os", "normalizes_command", "normalizes_both"],
    )
    def test_normalizes_on_lookup(self, lookup_os: str, lookup_cmd: str) -> None:
        """OS and command are normalized during lookup."""

        @registry.register("nxos", "show version")
        def parse_show_version(output: str) -> dict[str, Any]:
            return {}

        parser = registry.get_parser(lookup_os, lookup_cmd)
        assert parser is parse_show_version

    def test_raises_parser_not_found_error(self) -> None:
        """Raises ParserNotFoundError when parser doesn't exist."""
        with pytest.raises(ParserNotFoundError) as exc_info:
            registry.get_parser("nxos", "show version")

        assert exc_info.value.os == "nxos"
        assert exc_info.value.command == "show version"

    def test_raises_for_wrong_os(self) -> None:
        """Raises ParserNotFoundError when OS doesn't match."""

        @registry.register("nxos", "show version")
        def parse_show_version(output: str) -> dict[str, Any]:
            return {}

        with pytest.raises(ParserNotFoundError):
            registry.get_parser("iosxe", "show version")


class TestListParsers:
    """Tests for list_parsers function."""

    def test_empty_registry(self) -> None:
        """Returns empty list when no parsers registered."""
        assert registry.list_parsers() == []

    def test_returns_registered_parsers(self) -> None:
        """Returns list of registered (os, command) tuples."""

        @registry.register("nxos", "show version")
        def parse_nxos_version(output: str) -> dict[str, Any]:
            return {}

        @registry.register("iosxe", "show ip route")
        def parse_iosxe_route(output: str) -> dict[str, Any]:
            return {}

        parsers = registry.list_parsers()
        assert len(parsers) == 2
        assert ("nxos", "show version") in parsers
        assert ("iosxe", "show ip route") in parsers
