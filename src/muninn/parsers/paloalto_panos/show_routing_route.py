"""Parser for 'show routing route' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RoutingRouteEntry(TypedDict):
    """Schema for a single routing table entry."""

    virtual_router: str
    destination: str
    nexthop: str
    metric: str
    flags: str
    age: str
    interface: NotRequired[str]
    next_as: NotRequired[str]


ShowRoutingRouteResult = dict[str, RoutingRouteEntry]


# Virtual router name line, e.g. "VIRTUAL ROUTER: VR_HANDOFF (id 3)"
_VR_PATTERN = re.compile(r"^VIRTUAL ROUTER:\s+(\S+)")

# "total routes shown:" summary line
_TOTAL_PATTERN = re.compile(r"^total routes shown:", re.IGNORECASE)

# Column names in the header, in order
_HEADER_COLUMNS = (
    "destination",
    "nexthop",
    "metric",
    "flags",
    "age",
    "interface",
    "next-AS",
)


def _find_column_positions(header_line: str) -> list[int]:
    """Extract the start positions of each column from the header line.

    Returns:
        List of column start positions matching _HEADER_COLUMNS order.

    Raises:
        ValueError: If any expected column is not found in the header.
    """
    positions: list[int] = []
    for col_name in _HEADER_COLUMNS:
        idx = header_line.lower().find(col_name.lower())
        if idx < 0:
            msg = f"Column '{col_name}' not found in header"
            raise ValueError(msg)
        positions.append(idx)
    return positions


def _extract_column(line: str, positions: list[int], col_index: int) -> str:
    """Extract a column value from a fixed-width line.

    Args:
        line: The full line of text.
        positions: List of column start positions.
        col_index: Index of the column to extract.

    Returns:
        Stripped column value, or empty string if the line is too short.
    """
    start = positions[col_index]
    if start >= len(line):
        return ""
    # End is the start of the next column, or end of line for the last column
    if col_index + 1 < len(positions):
        end = positions[col_index + 1]
    else:
        end = len(line)
    return line[start:end].strip()


# Column indices (matching _HEADER_COLUMNS order)
_COL_DESTINATION = 0
_COL_NEXTHOP = 1
_COL_METRIC = 2
_COL_FLAGS = 3
_COL_AGE = 4
_COL_INTERFACE = 5
_COL_NEXT_AS = 6


def _parse_route_line(
    line: str,
    positions: list[int],
    virtual_router: str,
    result: dict[str, RoutingRouteEntry],
) -> None:
    """Parse a single route entry line and add it to the result dict."""
    destination = _extract_column(line, positions, _COL_DESTINATION)

    # Route lines must start with a destination that contains a /
    if "/" not in destination:
        return

    nexthop = _extract_column(line, positions, _COL_NEXTHOP)
    metric = _extract_column(line, positions, _COL_METRIC)
    flags = _extract_column(line, positions, _COL_FLAGS)
    age = _extract_column(line, positions, _COL_AGE)
    interface = _extract_column(line, positions, _COL_INTERFACE)
    next_as = _extract_column(line, positions, _COL_NEXT_AS)

    entry: RoutingRouteEntry = {
        "virtual_router": virtual_router,
        "destination": destination,
        "nexthop": nexthop,
        "metric": metric,
        "flags": flags,
        "age": age,
    }

    if interface:
        entry["interface"] = interface
    if next_as:
        entry["next_as"] = next_as

    result[destination] = entry


def _is_skippable(stripped: str) -> bool:
    """Return True if the line should be skipped (decorative/legend/total)."""
    return (
        stripped.startswith("=")
        or stripped.startswith("flags:")
        or bool(_TOTAL_PATTERN.match(stripped))
    )


def _is_header(stripped: str) -> bool:
    """Return True if the line is the column header row."""
    lower = stripped.lower()
    return lower.startswith("destination") and "nexthop" in lower


@register(OS.PALOALTO_PANOS, "show routing route")
class ShowRoutingRouteParser(BaseParser[ShowRoutingRouteResult]):
    """Parser for 'show routing route' command on Palo Alto PAN-OS.

    Parses the routing table output into a dict-of-dicts keyed by
    route destination/prefix (e.g. ``10.0.0.0/8``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRoutingRouteResult:
        """Parse 'show routing route' output on PAN-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of routing entries keyed by destination prefix.

        Raises:
            ValueError: If no routing entries can be parsed.
        """
        result: dict[str, RoutingRouteEntry] = {}
        current_vr = "default"
        positions: list[int] | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or _is_skippable(stripped):
                continue

            vr_match = _VR_PATTERN.match(stripped)
            if vr_match:
                current_vr = vr_match.group(1)
                continue

            if _is_header(stripped):
                positions = _find_column_positions(line)
                continue

            if positions is not None:
                _parse_route_line(line, positions, current_vr, result)

        if not result:
            msg = "No routing entries found in output"
            raise ValueError(msg)

        return cast(ShowRoutingRouteResult, result)
