"""Parser registry for discovering and invoking parsers."""

from collections.abc import Callable
from typing import TYPE_CHECKING

from muninn.exceptions import ParserNotFoundError

if TYPE_CHECKING:
    from muninn.parser import BaseParser

# Registry: maps (os, command) -> parser class
_registry: dict[tuple[str, str], type["BaseParser"]] = {}


def register(
    os: str, command: str
) -> Callable[[type["BaseParser"]], type["BaseParser"]]:
    """Class decorator to register a parser.

    Args:
        os: Operating system identifier (e.g., "nxos", "iosxe").
        command: The command this parser handles (e.g., "show ip ospf neighbor").

    Returns:
        Decorator function that registers the parser class.

    Example:
        @register("nxos", "show ip ospf neighbor")
        class ShowIpOspfNeighborParser(BaseParser):
            @classmethod
            def parse(cls, output: str) -> dict[str, Any]:
                ...
    """
    normalized_command = _normalize_command(command)
    normalized_os = os.lower()

    def decorator(cls: type["BaseParser"]) -> type["BaseParser"]:
        cls.os = normalized_os
        cls.command = normalized_command
        _registry[(normalized_os, normalized_command)] = cls
        return cls

    return decorator


def get_parser(os: str, command: str) -> type["BaseParser"]:
    """Look up a parser class by OS and command.

    Args:
        os: Operating system identifier.
        command: The command to find a parser for.

    Returns:
        The parser class.

    Raises:
        ParserNotFoundError: If no parser is registered for the OS/command.
    """
    normalized_command = _normalize_command(command)
    key = (os.lower(), normalized_command)

    if key not in _registry:
        raise ParserNotFoundError(os, command)

    return _registry[key]


def _normalize_command(command: str) -> str:
    """Normalize a command string for consistent registry lookup.

    Args:
        command: The command string to normalize.

    Returns:
        Normalized command string.
    """
    return " ".join(command.lower().split())


def list_parsers() -> list[tuple[str, str]]:
    """List all registered parsers.

    Returns:
        List of (os, command) tuples for all registered parsers.
    """
    return list(_registry.keys())
