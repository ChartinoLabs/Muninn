"""Tests for muninn.registry module."""

from typing import Any

import pytest

from muninn.exceptions import ParserNotFoundError
from muninn.os import OS, CiscoIOSXE, CiscoNXOS, OperatingSystem
from muninn.parser import BaseParser
from muninn.registry import RuntimeRegistry, _normalize_command, register


class TestNormalizeCommand:
    """Tests for _normalize_command function."""

    @pytest.mark.parametrize(
        ("input_cmd", "expected"),
        [
            ("SHOW IP OSPF", "show ip ospf"),
            ("  show ip ospf", "show ip ospf"),
            ("show ip ospf  ", "show ip ospf"),
            ("show  ip   ospf", "show ip ospf"),
            ("show\tip\tospf", "show ip ospf"),
            ("", ""),
            ("show ip ospf", "show ip ospf"),
            ("  SHOW  IP  OSPF  ", "show ip ospf"),
        ],
    )
    def test_normalize_command(self, input_cmd: str, expected: str) -> None:
        """Command normalization handles various input formats."""
        assert _normalize_command(input_cmd) == expected


class TestRegisterDecorator:
    """Tests for parser class annotation via register decorator."""

    def test_sets_os_command_and_metadata(self) -> None:
        """Decorator annotates parser class metadata."""

        @register("nxos", "  SHOW VERSION  ")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        assert ShowVersionParser.os is OS.CISCO_NXOS
        assert ShowVersionParser.command == "show version"
        assert ShowVersionParser._muninn_registrations == [
            (OS.CISCO_NXOS, "show version")
        ]


class TestRuntimeRegistry:
    """Tests for runtime-owned registry behavior."""

    @pytest.fixture
    def runtime_registry(self) -> RuntimeRegistry:
        """Create an isolated runtime registry."""
        return RuntimeRegistry()

    def test_register_parser_with_string(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Register parser using string OS alias."""

        @register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"version": "1.0"}

        runtime_registry.register_parser(
            "nxos", "show version", ShowVersionParser, source="built_in"
        )

        parsers = runtime_registry.list_parsers()
        assert (OS.CISCO_NXOS, "show version") in parsers

    @pytest.mark.parametrize(
        ("register_os", "register_cmd", "expected_os"),
        [
            ("NXOS", "show version", OS.CISCO_NXOS),
            ("nx-os", "show version", OS.CISCO_NXOS),
            ("iosxe", "  SHOW  VERSION  ", OS.CISCO_IOSXE),
            (OS.CISCO_NXOS, "show version", OS.CISCO_NXOS),
            (CiscoIOSXE, "show version", OS.CISCO_IOSXE),
        ],
    )
    def test_normalizes_on_registration(
        self,
        runtime_registry: RuntimeRegistry,
        register_os: str | OS,
        register_cmd: str,
        expected_os: OS,
    ) -> None:
        """OS and command are normalized during registration."""

        @register(register_os, register_cmd)
        class Parser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            register_os, register_cmd, Parser, source="built_in"
        )
        assert (expected_os, _normalize_command(register_cmd)) in (
            runtime_registry.list_parsers()
        )

    def test_get_candidates_uses_requested_source_order(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Candidate ordering follows explicit source order."""

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

        runtime_registry.register_parser(
            "nxos", "show version", BuiltInParser, source="built_in"
        )
        runtime_registry.register_parser(
            "nxos", "show version", LocalParser, source="local"
        )

        candidates = runtime_registry.get_parser_candidates(
            "nxos", "show version", source_order=("built_in", "local")
        )
        assert [candidate.parser_cls for candidate in candidates] == [
            BuiltInParser,
            LocalParser,
        ]

    def test_raises_parser_not_found_error(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Raises ParserNotFoundError when parser doesn't exist."""
        with pytest.raises(ParserNotFoundError):
            runtime_registry.get_parser_candidates("nxos", "show version")

    def test_returns_empty_when_registry_empty(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Returns empty parser key list for empty registry."""
        assert runtime_registry.list_parsers() == []

    def test_deduplicates_same_parser_source(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Repeated registration of same parser and source is ignored."""

        @register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "nxos", "show version", ShowVersionParser, source="built_in"
        )
        runtime_registry.register_parser(
            "nxos", "show version", ShowVersionParser, source="built_in"
        )

        candidates = runtime_registry.get_parser_candidates("nxos", "show version")
        assert len(candidates) == 1

    def test_supports_operating_system_class_registration(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Registration accepts OperatingSystem class types."""

        @register(CiscoNXOS, "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            CiscoNXOS,
            "show version",
            ShowVersionParser,
            source="built_in",
        )
        assert (OS.CISCO_NXOS, "show version") in runtime_registry.list_parsers()

    def test_lookup_normalizes_os_input_types(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Lookup accepts and normalizes OS aliases, enums, and classes."""

        @register("nxos", "show version")
        class ShowVersionParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "nxos", "show version", ShowVersionParser, source="built_in"
        )

        lookups: list[tuple[str | OS | type[OperatingSystem], str]] = [
            ("NXOS", "show version"),
            ("nx-os", "show version"),
            (OS.CISCO_NXOS, "show version"),
            (CiscoNXOS, "show version"),
        ]
        for os_value, command in lookups:
            candidates = runtime_registry.get_parser_candidates(os_value, command)
            assert candidates[0].parser_cls is ShowVersionParser
