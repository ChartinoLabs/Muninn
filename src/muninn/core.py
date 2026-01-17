"""Core parsing functionality."""

from typing import Any

from muninn.exceptions import ParseError
from muninn.os import OS, OperatingSystem, resolve_os
from muninn.registry import get_parser


def parse(
    os: str | OS | type[OperatingSystem], command: str, output: str
) -> dict[str, Any]:
    """Parse CLI output into structured data.

    Args:
        os: Operating system identifier. Can be:
            - A string alias (e.g., "nxos", "ios-xe")
            - An OS enum member (e.g., OS.CISCO_NXOS)
            - An OperatingSystem class (e.g., CiscoNXOS)
        command: The command that produced the output (e.g., "show ip ospf neighbor").
        output: Raw CLI output string to parse.

    Returns:
        Parsed structured data as a dictionary.

    Raises:
        ParserNotFoundError: No parser exists for the OS/command combination.
        ParseError: The parser failed to parse the output.
        ValueError: If the OS input cannot be resolved.

    Example:
        >>> import muninn
        >>> result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
        >>> print(result["10.1.1.1"]["state"])
        'FULL/DR'

        # Using enum:
        >>> from muninn import OS
        >>> result = muninn.parse(OS.CISCO_NXOS, "show ip ospf neighbor", raw_output)
    """
    parser_cls = get_parser(os, command)

    try:
        return parser_cls.parse(output)
    except ParseError:
        raise
    except Exception as e:
        resolved_os = resolve_os(os)
        raise ParseError(resolved_os.value.name, command, str(e)) from e
