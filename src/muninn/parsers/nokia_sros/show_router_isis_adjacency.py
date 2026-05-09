"""Parser for 'show router isis adjacency' command on Nokia SR OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisAdjacencyEntry(TypedDict):
    """Schema for a single IS-IS adjacency entry."""

    state: str
    hold_time: int
    interface: str
    mt_id: int


class ShowRouterIsisAdjacencyResult(TypedDict):
    """Schema for 'show router isis adjacency' parsed output on Nokia SR OS.

    Nokia SR OS reports IS-IS adjacencies for a specific router context
    (e.g. "Base") and ISIS instance (an integer). The same system ID may
    appear more than once when both L1 and L2 adjacencies are formed,
    so adjacencies are nested as ``{system_id: {usage: entry}}``.
    """

    router_context: str
    isis_instance: int
    adjacencies: dict[str, dict[str, IsisAdjacencyEntry]]


@register(OS.NOKIA_SROS, "show router isis adjacency")
class ShowRouterIsisAdjacencyParser(BaseParser[ShowRouterIsisAdjacencyResult]):
    """Parser for 'show router isis adjacency' command on Nokia SR OS.

    Parses the IS-IS adjacency table output. Captures the router context
    (e.g. "Base") and ISIS instance number from the table title, plus
    the per-adjacency rows. The same system ID may appear more than once
    when both L1 and L2 adjacencies exist, so adjacencies are keyed first
    by system ID and then by adjacency type (``L1``, ``L2``, ``L1L2``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    # Separator lines (=== or ---)
    _SEPARATOR = re.compile(r"^[=\-]{10,}$")

    # Table title line — captures router context and ISIS instance number.
    _TABLE_TITLE = re.compile(
        r"^\s*Rtr\s+(?P<router_context>\S+)\s+ISIS\s+Instance\s+"
        r"(?P<isis_instance>\d+)\s+Adjacency",
        re.I,
    )

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
        """Return True for lines that are not data rows or table titles."""
        stripped = line.strip()
        if not stripped:
            return True
        if cls._SEPARATOR.match(stripped):
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
            Dict with router_context, isis_instance, and adjacencies keyed
            by system ID then by adjacency usage type.

        Raises:
            ValueError: If the table title or no adjacency entries can be
                parsed from the output.
        """
        router_context: str | None = None
        isis_instance: int | None = None
        adjacencies: dict[str, dict[str, IsisAdjacencyEntry]] = {}

        for line in output.splitlines():
            stripped = line.strip()

            title_match = cls._TABLE_TITLE.match(stripped)
            if title_match:
                router_context = title_match.group("router_context")
                isis_instance = int(title_match.group("isis_instance"))
                continue

            if cls._is_skip_line(line):
                continue

            row_match = cls._ADJACENCY_ROW.match(stripped)
            if row_match is None:
                continue

            system_id = row_match.group("system_id")
            usage = row_match.group("usage")
            entry: IsisAdjacencyEntry = {
                "state": row_match.group("state"),
                "hold_time": int(row_match.group("hold_time")),
                "interface": row_match.group("interface"),
                "mt_id": int(row_match.group("mt_id")),
            }
            adjacencies.setdefault(system_id, {})[usage] = entry

        if router_context is None or isis_instance is None:
            msg = "ISIS adjacency table title not found in output"
            raise ValueError(msg)

        if not adjacencies:
            msg = "No IS-IS adjacency entries found in output"
            raise ValueError(msg)

        return cast(
            ShowRouterIsisAdjacencyResult,
            {
                "router_context": router_context,
                "isis_instance": isis_instance,
                "adjacencies": adjacencies,
            },
        )
