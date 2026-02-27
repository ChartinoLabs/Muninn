"""Parser registry for discovering and invoking parsers."""

from collections.abc import Callable
from typing import TYPE_CHECKING

from muninn.exceptions import ParserNotFoundError
from muninn.os import OS, OperatingSystem, resolve_os

if TYPE_CHECKING:
    from muninn.parser import BaseParser

# Registry: maps (OS enum, normalized_command) -> parser class
_registry: dict[tuple[OS, str], type["BaseParser[object]"]] = {}


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
    resolved_os = resolve_os(os)
    normalized_command = _normalize_command(command)

    def decorator(cls: type["BaseParser[object]"]) -> type["BaseParser[object]"]:
        cls.os = resolved_os
        cls.command = normalized_command
        _registry[(resolved_os, normalized_command)] = cls
        return cls

    return decorator


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
    resolved_os = resolve_os(os)
    normalized_command = _normalize_command(command)
    key = (resolved_os, normalized_command)

    if key not in _registry:
        raise ParserNotFoundError(resolved_os.value.name, command)

    return _registry[key]


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
