"""Tests for muninn.registry module."""

from typing import Any

import pytest

from muninn.exceptions import ParserAmbiguityError, ParserNotFoundError
from muninn.os import OS, CiscoIOSXE, CiscoNXOS, OperatingSystem
from muninn.parser import BaseParser
from muninn.registry import (
    Registration,
    RuntimeRegistry,
    _generate_doc_template,
    _normalize_command,
    register,
)


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


class TestDocTemplateGeneration:
    """Tests for auto-generated documentation templates."""

    def test_generates_literal_doc_template(self) -> None:
        """Simple named-group patterns generate docs automatically."""
        template = _generate_doc_template(
            "show ip ospf (?P<process_id>\\d+) vrf (?P<vrf_name>\\S+)"
        )

        assert template == "show ip ospf <process-id> vrf <vrf-name>"

    def test_returns_none_for_complex_pattern(self) -> None:
        """Complex regex patterns require explicit doc templates."""
        template = _generate_doc_template(
            "show ip bgp(?: vrf (?P<vrf_name>\\S+))? summary"
        )

        assert template is None


class TestRegisterDecorator:
    """Tests for parser class annotation via register decorator."""

    def test_sets_os_command_and_metadata(self) -> None:
        """Decorator annotates parser class metadata."""

        class _RegistrableParser(BaseParser):
            _muninn_registrations: list[Registration]

        @register("nxos", "  SHOW VERSION  ")
        class ShowVersionParser(_RegistrableParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        assert ShowVersionParser.os is OS.CISCO_NXOS
        assert ShowVersionParser.command == "show version"
        assert len(ShowVersionParser._muninn_registrations) == 1
        registration = ShowVersionParser._muninn_registrations[0]
        assert registration.os is OS.CISCO_NXOS
        assert registration.command == "  SHOW VERSION  "
        assert registration.doc_template is None


class TestRuntimeRegistry:
    """Tests for runtime-owned registry behavior."""

    @pytest.fixture
    def runtime_registry(self) -> RuntimeRegistry:
        """Create an isolated runtime registry."""
        return RuntimeRegistry()

    def test_register_literal_parser_with_string(
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
    def test_normalizes_literal_registration(
        self,
        runtime_registry: RuntimeRegistry,
        register_os: str | OS,
        register_cmd: str,
        expected_os: OS,
    ) -> None:
        """OS and command are normalized during literal registration."""

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

    def test_get_candidates_uses_requested_source_order_for_literals(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Literal candidate ordering follows explicit source order."""

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

    def test_literal_candidates_precede_pattern_candidates(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Exact command matches are returned before regex matches."""

        @register("ios", "show ip ospf neighbors")
        class LiteralParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"kind": "literal"}

        @register("ios", r"show ip ospf (?P<token>\S+)")
        class PatternParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"kind": "pattern"}

        runtime_registry.register_parser(
            "ios", "show ip ospf neighbors", LiteralParser, source="built_in"
        )
        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<token>\S+)",
            PatternParser,
            source="built_in",
        )

        candidates = runtime_registry.get_parser_candidates(
            "ios", "show ip ospf neighbors"
        )
        assert [candidate.parser_cls for candidate in candidates] == [LiteralParser]

    def test_pattern_lookup_uses_first_matching_source(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Regex lookup stops after the first matching source."""

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class BuiltInParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"source": "built_in"}

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {"source": "local"}

        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            BuiltInParser,
            source="built_in",
        )
        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            LocalParser,
            source="local",
        )

        candidates = runtime_registry.get_parser_candidates(
            "ios", "show ip ospf 5", source_order=("local", "built_in")
        )
        assert [candidate.parser_cls for candidate in candidates] == [LocalParser]

    def test_pattern_lookup_raises_ambiguity_within_source(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Overlapping patterns in one source raise ambiguity errors."""

        @register("ios", r"show ip ospf (?P<token>\S+)")
        class GenericParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class ProcessParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "ios", r"show ip ospf (?P<token>\S+)", GenericParser, source="local"
        )
        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            ProcessParser,
            source="local",
        )

        with pytest.raises(ParserAmbiguityError) as exc_info:
            runtime_registry.get_parser_candidates("ios", "show ip ospf 5")

        assert exc_info.value.matches == [
            "show ip ospf <token>",
            "show ip ospf <process-id>",
        ]

    def test_pattern_lookup_skips_ambiguity_in_lower_precedence_source(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """A unique higher-precedence match wins over lower-source ambiguity."""

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class LocalParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        @register("ios", r"show ip ospf (?P<token>\S+)")
        class BuiltInGenericParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class BuiltInProcessParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            LocalParser,
            source="local",
        )
        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<token>\S+)",
            BuiltInGenericParser,
            source="built_in",
        )
        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            BuiltInProcessParser,
            source="built_in",
        )

        candidates = runtime_registry.get_parser_candidates("ios", "show ip ospf 5")
        assert [candidate.parser_cls for candidate in candidates] == [LocalParser]

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

    def test_rejects_duplicate_literal_registration_in_same_source(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Two literal parsers in the same source cannot share one command."""

        @register("nxos", "show version")
        class FirstParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        @register("nxos", "show version")
        class SecondParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "nxos", "show version", FirstParser, source="built_in"
        )
        with pytest.raises(ValueError, match="Duplicate literal registration"):
            runtime_registry.register_parser(
                "nxos", "show version", SecondParser, source="built_in"
            )

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

    def test_pattern_lookup_normalizes_case_and_whitespace(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Pattern lookup evaluates normalized input commands."""

        @register("ios", r"^show ip ospf (?P<process_id>\d+)$")
        class ShowIpOspfParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "ios",
            r"^show ip ospf (?P<process_id>\d+)$",
            ShowIpOspfParser,
            source="built_in",
        )

        candidates = runtime_registry.get_parser_candidates(
            "ios", "  SHOW   IP   OSPF  5  "
        )
        assert candidates[0].parser_cls is ShowIpOspfParser

    def test_rejects_invalid_regex_pattern(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Invalid regex patterns fail registration."""

        @register("ios", r"show ip ospf (?P<process_id>\d+")
        class BadParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        with pytest.raises(ValueError, match="Invalid command pattern"):
            runtime_registry.register_parser(
                "ios",
                r"show ip ospf (?P<process_id>\d+",
                BadParser,
                source="built_in",
            )

    def test_requires_doc_template_for_complex_pattern(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Complex patterns require explicit documentation templates."""

        @register("ios", r"show ip bgp(?: vrf (?P<vrf_name>\S+))? summary")
        class ComplexParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        with pytest.raises(ValueError, match="doc_template is required"):
            runtime_registry.register_parser(
                "ios",
                r"show ip bgp(?: vrf (?P<vrf_name>\S+))? summary",
                ComplexParser,
                source="built_in",
            )

    def test_validates_doc_template_placeholders(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Doc templates must align with named regex groups."""

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class PatternParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        with pytest.raises(ValueError, match="doc_template placeholders"):
            runtime_registry.register_parser(
                "ios",
                r"show ip ospf (?P<process_id>\d+)",
                PatternParser,
                source="built_in",
                doc_template="show ip ospf <vrf-name>",
            )

    def test_list_command_specs_exposes_doc_templates(
        self,
        runtime_registry: RuntimeRegistry,
    ) -> None:
        """Command specs preserve user-facing templates for introspection."""

        @register("ios", r"show ip ospf (?P<process_id>\d+)")
        class PatternParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                return {}

        runtime_registry.register_parser(
            "ios",
            r"show ip ospf (?P<process_id>\d+)",
            PatternParser,
            source="built_in",
        )

        specs = runtime_registry.list_command_specs()
        assert len(specs) == 1
        assert specs[0].doc_template == "show ip ospf <process-id>"
        assert specs[0].command_text == r"show ip ospf (?P<process_id>\d+)"
        assert specs[0].match_text == r"show ip ospf (?P<process_id>\d+)"
        assert specs[0].is_pattern is True
