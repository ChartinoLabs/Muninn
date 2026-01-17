"""Core parsing functionality."""

from typing import Any

from muninn.registry import get_parser


def parse(os: str, command: str, output: str) -> dict[str, Any]:
    """Parse CLI output into structured data.

    Args:
        os: Operating system identifier (e.g., "nxos", "iosxe").
        command: The command that produced the output (e.g., "show ip ospf neighbor").
        output: Raw CLI output string to parse.

    Returns:
        Parsed structured data as a dictionary.

    Raises:
        ParserNotFoundError: No parser exists for the OS/command combination.
        ParseError: The parser failed to parse the output.

    Example:
        >>> import muninn
        >>> result = muninn.parse("nxos", "show ip ospf neighbor", raw_output)
        >>> print(result["10.1.1.1"]["state"])
        'FULL/DR'
    """
    parser_cls = get_parser(os, command)
    return parser_cls.parse(output)
