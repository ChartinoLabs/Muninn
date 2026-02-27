"""Parser registry for discovering and invoking parsers."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from muninn.exceptions import ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os

if TYPE_CHECKING:
    from muninn.parser import BaseParser

ParserSource = Literal["built_in", "local"]


@dataclass(frozen=True)
class ParserCandidate:
    """Registered parser candidate with source metadata."""

    parser_cls: type["BaseParser[object]"]
    source: ParserSource


# Registry: maps (OS enum, normalized_command) -> ordered parser candidates
_registry: dict[tuple[OS, str], list[ParserCandidate]] = {}

# Registration source used by @register (default is built-in parsers)
_active_registration_source: ParserSource = "built_in"


@contextmanager
def registration_source(source: ParserSource) -> Iterator[None]:
    """Temporarily set parser source for decorator-based registration."""
    global _active_registration_source

    previous_source = _active_registration_source
    _active_registration_source = source
    try:
        yield
    finally:
        _active_registration_source = previous_source


def register(
    os: str | OS | type[OperatingSystem], command: str
) -> Callable[[type["BaseParser[object]"]], type["BaseParser[object]"]]:
    """Class decorator to register a parser.

    Args:
        os: Operating system identifier. Can be:
            - A string alias (e.g., "nxos", "ios-xe")
            - An OS enum member (e.g., OS.CISCO_NXOS)
            - An OperatingSystem class (e.g., CiscoNXOS)
        command: The command this parser handles (e.g., "show ip ospf neighbor").

    Returns:
        Decorator function that registers the parser class.

    Example:
        @register("nxos", "show ip ospf neighbor")
        class ShowIpOspfNeighborParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                ...

        # Or with enum:
        @register(OS.CISCO_NXOS, "show ip ospf neighbor")
        class ShowIpOspfNeighborParser(BaseParser):
            ...
    """

    def decorator(cls: type["BaseParser[object]"]) -> type["BaseParser[object]"]:
        register_parser(
            os=os,
            command=command,
            parser_cls=cls,
            source=_active_registration_source,
        )
        return cls

    return decorator


def register_parser(
    os: str | OS | type[OperatingSystem],
    command: str,
    parser_cls: type["BaseParser[object]"],
    source: ParserSource,
) -> None:
    """Register a parser class with explicit source metadata."""
    resolved_os = resolve_os(os)
    normalized_command = _normalize_command(command)
    key = (resolved_os, normalized_command)

    parser_cls.os = resolved_os
    parser_cls.command = normalized_command

    candidates = _registry.setdefault(key, [])
    candidates.append(ParserCandidate(parser_cls=parser_cls, source=source))


def get_parser(
    os: str | OS | type[OperatingSystem], command: str
) -> type["BaseParser[object]"]:
    """Look up a parser class by OS and command.

    Args:
        os: Operating system identifier. Can be:
            - A string alias (e.g., "nxos", "ios-xe")
            - An OS enum member (e.g., OS.CISCO_NXOS)
            - An OperatingSystem class (e.g., CiscoNXOS)
        command: The command to find a parser for.

    Returns:
        The parser class.

    Raises:
        ParserNotFoundError: If no parser is registered for the OS/command.
        ValueError: If the OS input cannot be resolved.
    """
    candidates = get_parser_candidates(os, command)
    return candidates[0].parser_cls


def get_parser_candidates(
    os: str | OS | type[OperatingSystem],
    command: str,
    source_order: tuple[ParserSource, ...] = ("local", "built_in"),
) -> list[ParserCandidate]:
    """Get ordered parser candidates for an OS/command pair."""
    resolved_os = resolve_os(os)
    normalized_command = _normalize_command(command)
    key = (resolved_os, normalized_command)

    if key not in _registry:
        raise ParserNotFoundError(resolved_os.value.name, command)

    candidates = _registry[key]
    grouped: dict[ParserSource, list[ParserCandidate]] = {
        "local": [],
        "built_in": [],
    }
    for candidate in candidates:
        grouped[candidate.source].append(candidate)

    ordered: list[ParserCandidate] = []
    for source in source_order:
        ordered.extend(grouped[source])

    return ordered


def _normalize_command(command: str) -> str:
    """Normalize a command string for consistent registry lookup.

    Args:
        command: The command string to normalize.

    Returns:
        Normalized command string.
    """
    return " ".join(command.lower().split())


def list_parsers() -> list[tuple[OS, str]]:
    """List all registered parsers.

    Returns:
        List of (OS, command) tuples for all registered parsers.
    """
    return list(_registry.keys())
