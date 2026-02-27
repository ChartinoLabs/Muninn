"""Tests for muninn.registry module."""

from typing import Any

import pytest

from muninn import registry
from muninn.exceptions import ParserNotFoundError
from muninn.os import OS, CiscoIOSXE, CiscoNXOS, OperatingSystem
from muninn.parser import BaseParser


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

    def test_registers_parser_class_with_string(self) -> None:
        """Decorator registers the parser class using string alias."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        assert (OS.CISCO_NXOS, "show version") in registry._registry
        candidates = registry._registry[(OS.CISCO_NXOS, "show version")]
        assert candidates[0].parser_cls is ShowVersionParser
        assert candidates[0].source == "built_in"

    def test_registers_parser_class_with_enum(self) -> None:
        """Decorator registers the parser class using OS enum."""

        @registry.register(OS.CISCO_NXOS, "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        assert (OS.CISCO_NXOS, "show version") in registry._registry

    def test_registers_parser_class_with_os_class(self) -> None:
        """Decorator registers the parser class using OperatingSystem class."""

        @registry.register(CiscoNXOS, "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        assert (OS.CISCO_NXOS, "show version") in registry._registry

    def test_returns_original_class(self) -> None:
        """Decorator returns the original class unchanged."""

        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        decorated = registry.register("nxos", "show version")(ShowVersionParser)
        assert decorated is ShowVersionParser

    def test_sets_os_and_command_attributes(self) -> None:
        """Decorator sets os and command class attributes."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        assert ShowVersionParser.os is OS.CISCO_NXOS
        assert ShowVersionParser.command == "show version"

    @pytest.mark.parametrize(
        ("register_os", "register_cmd", "expected_os"),
        [
            ("NXOS", "show version", OS.CISCO_NXOS),
            ("nx-os", "show version", OS.CISCO_NXOS),
            ("iosxe", "  SHOW  VERSION  ", OS.CISCO_IOSXE),
            (OS.CISCO_NXOS, "show version", OS.CISCO_NXOS),
            (CiscoIOSXE, "show version", OS.CISCO_IOSXE),
        ],
        ids=[
            "string_uppercase",
            "string_hyphen",
            "string_with_command_normalization",
            "enum",
            "class",
        ],
    )
    def test_normalizes_on_registration(
        self, register_os: str | OS, register_cmd: str, expected_os: OS
    ) -> None:
        """OS and command are normalized during registration."""
        normalized_cmd = registry._normalize_command(register_cmd)

        @registry.register(register_os, register_cmd)
        class Parser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        assert (expected_os, normalized_cmd) in registry._registry


class TestGetParser:
    """Tests for get_parser function."""

    def test_returns_registered_parser_class(self) -> None:
        """Returns the registered parser class."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        parser_cls = registry.get_parser("nxos", "show version")
        assert parser_cls is ShowVersionParser

    def test_returned_parser_is_callable(self) -> None:
        """Returned parser class can parse output."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        parser_cls = registry.get_parser("nxos", "show version")
        result = parser_cls.parse("some output")
        assert result == {"version": "1.0"}

    @pytest.mark.parametrize(
        ("lookup_os", "lookup_cmd"),
        [
            ("NXOS", "show version"),
            ("nx-os", "show version"),
            ("nxos", "  SHOW  VERSION  "),
            (OS.CISCO_NXOS, "show version"),
            (CiscoNXOS, "show version"),
        ],
        ids=[
            "string_uppercase",
            "string_hyphen",
            "command_whitespace",
            "enum",
            "class",
        ],
    )
    def test_normalizes_on_lookup(
        self, lookup_os: str | OS | type[OperatingSystem], lookup_cmd: str
    ) -> None:
        """OS and command are normalized during lookup."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        parser_cls = registry.get_parser(lookup_os, lookup_cmd)
        assert parser_cls is ShowVersionParser

    def test_raises_parser_not_found_error(self) -> None:
        """Raises ParserNotFoundError when parser doesn't exist."""
        with pytest.raises(ParserNotFoundError) as exc_info:
            registry.get_parser("nxos", "show version")

        assert exc_info.value.os == "cisco_nxos"
        assert exc_info.value.command == "show version"

    def test_raises_for_wrong_os(self) -> None:
        """Raises ParserNotFoundError when OS doesn't match."""

        @registry.register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        with pytest.raises(ParserNotFoundError):
            registry.get_parser("iosxe", "show version")


class TestListParsers:
    """Tests for list_parsers function."""

    def test_empty_registry(self) -> None:
        """Returns empty list when no parsers registered."""
        assert registry.list_parsers() == []

    def test_returns_registered_parsers(self) -> None:
        """Returns list of registered (OS, command) tuples."""

        @registry.register("nxos", "show version")
        class NxosVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        @registry.register("iosxe", "show ip route")
        class IosxeRouteParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        parsers = registry.list_parsers()
        assert len(parsers) == 2
        assert (OS.CISCO_NXOS, "show version") in parsers
        assert (OS.CISCO_IOSXE, "show ip route") in parsers
