"""Parser for 'show router isis adjacency' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisAdjacencyEntry(TypedDict):
    """Schema for a single IS-IS adjacency entry."""

    usage: str
    state: str
    hold_time: int
    interface: str
    mt_id: int


# Top-level result is a dict keyed by system ID
ShowRouterIsisAdjacencyResult = dict[str, IsisAdjacencyEntry]


@register(OS.NOKIA_SROS, "show router isis adjacency")
class ShowRouterIsisAdjacencyParser(BaseParser[ShowRouterIsisAdjacencyResult]):
    """Parser for 'show router isis adjacency' command on Nokia SR OS.

    Parses the IS-IS adjacency table output, returning a dict keyed by
    system ID. Each entry contains adjacency type (usage), state, hold
    timer, interface name, and multi-topology ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    # Separator lines (=== or ---)
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Table title line
    _TABLE_TITLE = re.compile(r"^\s*Rtr\s+.*ISIS\s+Instance\s+\d+\s+Adjacency", re.I)

    # Column header line
    _HEADER = re.compile(r"^\s*System\s+ID\s+Usage\s+State", re.I)

    # Footer line showing adjacency count
    _FOOTER = re.compile(r"^\s*Adjacencies\s*:\s*\d+", re.I)

    # Adjacency data row
    _ADJACENCY_ROW = re.compile(
        r"^(?P<system_id>\S+)\s+"
        r"(?P<usage>L[12]|L1L2)\s+"
        r"(?P<state>\S+)\s+"
        r"(?P<hold_time>\d+)\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<mt_id>\d+)\s*$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Return True for lines that are not data rows."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
            return True
        if cls._TABLE_TITLE.match(stripped):
            return True
        if cls._HEADER.match(stripped):
            return True
        if cls._FOOTER.match(stripped):
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowRouterIsisAdjacencyResult:
        """Parse 'show router isis adjacency' output on Nokia SR OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by system ID, each value an IsisAdjacencyEntry dict.

        Raises:
            ValueError: If no adjacency entries can be parsed.
        """
        result: dict[str, IsisAdjacencyEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._ADJACENCY_ROW.match(line.strip())
            if match:
                system_id = match.group("system_id")
                entry: IsisAdjacencyEntry = {
                    "usage": match.group("usage"),
                    "state": match.group("state"),
                    "hold_time": int(match.group("hold_time")),
                    "interface": match.group("interface"),
                    "mt_id": int(match.group("mt_id")),
                }
                result[system_id] = entry

        if not result:
            msg = "No IS-IS adjacency entries found in output"
            raise ValueError(msg)

        return cast(ShowRouterIsisAdjacencyResult, result)
