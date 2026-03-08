"""Parser for 'show route-map' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class RouteMapEntry(TypedDict):
    """Schema for a single route-map sequence entry."""

    name: str
    action: str
    sequence: int
    match_clauses: list[str]
    set_clauses: list[str]
    policy_routing_packets: NotRequired[int]
    policy_routing_bytes: NotRequired[int]


class ShowRouteMapResult(TypedDict):
    """Schema for 'show route-map' parsed output."""

    route_maps: dict[str, RouteMapEntry]


_ROUTE_MAP_HEADER = re.compile(
    r"^route-map\s+(?P<name>\S+),\s+(?P<action>permit|deny),\s+"
    r"sequence\s+(?P<sequence>\d+)\s*$"
)

_POLICY_ROUTING = re.compile(
    r"^\s*Policy\s+routing\s+matches:\s+(?P<packets>\d+)\s+packets?,\s+"
    r"(?P<bytes>\d+)\s+bytes?\s*$"
)

_SECTION_HEADER = re.compile(r"^\s*(?:STATIC|DYNAMIC)\s+routemaps\s*$", re.IGNORECASE)

_DYNAMIC_COUNT = re.compile(
    r"^\s*Current\s+active\s+dynamic\s+routemaps\s*=", re.IGNORECASE
)

_MATCH_HEADER = re.compile(r"^\s*Match\s+clauses:\s*$")
_SET_HEADER = re.compile(r"^\s*Set\s+clauses:\s*$")


def _is_noise_line(line: str) -> bool:
    """Check if a line should be skipped during parsing."""
    stripped = line.strip()
    if not stripped:
        return True
    if _SECTION_HEADER.match(stripped):
        return True
    return bool(_DYNAMIC_COUNT.match(stripped))


def _parse_clause_lines(lines: list[str], start: int) -> tuple[list[str], int]:
    """Parse indented clause lines starting from the given index.

    Returns the list of clause strings and the next line index to process.
    """
    clauses: list[str] = []
    idx = start
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            idx += 1
            continue
        # Stop if we hit a non-indented line or a known section boundary
        if _ROUTE_MAP_HEADER.match(stripped):
            break
        if _MATCH_HEADER.match(line):
            break
        if _SET_HEADER.match(line):
            break
        if _POLICY_ROUTING.match(line):
            break
        if _SECTION_HEADER.match(stripped):
            break
        if _DYNAMIC_COUNT.match(stripped):
            break
        clauses.append(stripped)
        idx += 1
    return clauses, idx


@register(OS.CISCO_IOS, "show route-map")
class ShowRouteMapParser(BaseParser[ShowRouteMapResult]):
    """Parser for 'show route-map' command.

    Example output:
        route-map equal, permit, sequence 10
          Match clauses:
            length 150 200
          Set clauses:
            ip next-hop 10.10.11.254
          Policy routing matches: 0 packets, 0 bytes
    """

    @classmethod
    def parse(cls, output: str) -> ShowRouteMapResult:
        """Parse 'show route-map' output.

        Args:
            output: Raw CLI output from 'show route-map' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        route_maps: dict[str, RouteMapEntry] = {}
        idx = 0

        while idx < len(lines):
            line = lines[idx]
            stripped = line.strip()

            if _is_noise_line(stripped):
                idx += 1
                continue

            header_match = _ROUTE_MAP_HEADER.match(stripped)
            if not header_match:
                idx += 1
                continue

            entry: RouteMapEntry = {
                "name": header_match.group("name"),
                "action": header_match.group("action"),
                "sequence": int(header_match.group("sequence")),
                "match_clauses": [],
                "set_clauses": [],
            }
            idx += 1
            idx = _parse_entry_body(lines, idx, entry)

            key = f"{entry['name']}:{entry['sequence']}"
            route_maps[key] = entry

        if not route_maps:
            msg = "No route-map entries found in output"
            raise ValueError(msg)

        return {"route_maps": route_maps}


def _parse_entry_body(lines: list[str], idx: int, entry: RouteMapEntry) -> int:
    """Parse match clauses, set clauses, and policy routing for one entry."""
    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if not stripped:
            idx += 1
            continue

        if _ROUTE_MAP_HEADER.match(stripped):
            break

        if _SECTION_HEADER.match(stripped) or _DYNAMIC_COUNT.match(stripped):
            break

        if _MATCH_HEADER.match(line):
            idx += 1
            clauses, idx = _parse_clause_lines(lines, idx)
            entry["match_clauses"] = clauses
            continue

        if _SET_HEADER.match(line):
            idx += 1
            clauses, idx = _parse_clause_lines(lines, idx)
            entry["set_clauses"] = clauses
            continue

        policy_match = _POLICY_ROUTING.match(line)
        if policy_match:
            entry["policy_routing_packets"] = int(policy_match.group("packets"))
            entry["policy_routing_bytes"] = int(policy_match.group("bytes"))
            idx += 1
            break

        idx += 1

    return idx
