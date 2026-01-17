"""Parser registry for discovering and invoking parsers."""

from collections.abc import Callable
from typing import Any

from muninn.exceptions import ParserNotFoundError

# Type alias for parser functions
ParserFunc = Callable[[str], dict[str, Any]]

# Registry: maps (os, command) -> parser function
_registry: dict[tuple[str, str], ParserFunc] = {}


def register(os: str, command: str) -> Callable[[ParserFunc], ParserFunc]:
    """Decorator to register a parser function.

    Args:
        os: Operating system identifier (e.g., "nxos", "iosxe").
        command: The command this parser handles (e.g., "show ip ospf neighbor").

    Returns:
        Decorator function that registers the parser.

    Example:
        @register("nxos", "show ip ospf neighbor")
        def parse_show_ip_ospf_neighbor(output: str) -> dict[str, Any]:
            ...
    """
    # Normalize command (strip whitespace, lowercase for matching)
    normalized_command = _normalize_command(command)

    def decorator(func: ParserFunc) -> ParserFunc:
        _registry[(os.lower(), normalized_command)] = func
        return func

    return decorator


def get_parser(os: str, command: str) -> ParserFunc:
    """Look up a parser by OS and command.

    Args:
        os: Operating system identifier.
        command: The command to find a parser for.

    Returns:
        The parser function.

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
    # Strip whitespace, collapse multiple spaces, lowercase
    return " ".join(command.lower().split())


def list_parsers() -> list[tuple[str, str]]:
    """List all registered parsers.

    Returns:
        List of (os, command) tuples for all registered parsers.
    """
    return list(_registry.keys())
