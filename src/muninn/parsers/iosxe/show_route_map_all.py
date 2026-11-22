"""Parser for 'show route-map all' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteMapClauseEntry(TypedDict):
    """Schema for a single route-map sequence entry."""

    action: str
    sequence: int
    match_clauses: NotRequired[list[str]]
    set_clauses: NotRequired[list[str]]
    policy_routing_packets: NotRequired[int]
    policy_routing_bytes: NotRequired[int]


class ShowRouteMapAllResult(TypedDict):
    """Schema for 'show route-map all' parsed output.

    Keyed by route-map name, each containing a dict of sequence numbers
    mapped to their clause entries.
    """

    route_maps: dict[str, dict[str, RouteMapClauseEntry]]


# Route-map header: route-map NAME, permit/deny, sequence N
_HEADER_PATTERN = re.compile(
    r"^route-map\s+(?P<name>\S+),\s+(?P<action>permit|deny),\s+"
    r"sequence\s+(?P<seq>\d+)"
)

# Section headers within a route-map entry
_MATCH_HEADER = re.compile(r"^Match\s+clauses:$")
_SET_HEADER = re.compile(r"^Set\s+clauses:$")

# Policy routing matches line
_POLICY_ROUTING = re.compile(
    r"^Policy\s+routing\s+matches:\s+(?P<packets>\d+)\s+packets,"
    r"\s+(?P<bytes>\d+)\s+bytes"
)

# Patterns that signal the end of a clause block
_SECTION_BOUNDARIES: tuple[re.Pattern[str], ...] = (
    _MATCH_HEADER,
    _SET_HEADER,
    _POLICY_ROUTING,
    _HEADER_PATTERN,
)


def _is_clause_line(raw: str, stripped: str) -> bool:
    """Return True if the line is an indented clause line, not a boundary."""
    if not raw.startswith("    ") and not raw.startswith("\t"):
        return False
    return not any(p.match(stripped) for p in _SECTION_BOUNDARIES)


def _parse_clauses(lines: list[str], idx: int) -> tuple[list[str], int]:
    """Parse indented clause lines following a Match/Set header.

    Returns a tuple of (clause_list, next_line_index).
    """
    clauses: list[str] = []
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        if not stripped:
            idx += 1
            continue
        if not _is_clause_line(raw, stripped):
            break
        clauses.append(stripped)
        idx += 1
    return clauses, idx


def _apply_policy_routing(entry: RouteMapClauseEntry, match: re.Match[str]) -> None:
    """Apply policy routing match data to an entry."""
    entry["policy_routing_packets"] = int(match.group("packets"))
    entry["policy_routing_bytes"] = int(match.group("bytes"))


def _handle_section(
    stripped: str,
    lines: list[str],
    idx: int,
    entry: RouteMapClauseEntry,
) -> tuple[bool, int]:
    """Handle a section line (Match/Set/Policy). Returns (handled, next_idx)."""
    if _MATCH_HEADER.match(stripped):
        clauses, new_idx = _parse_clauses(lines, idx + 1)
        if clauses:
            entry["match_clauses"] = clauses
        return True, new_idx

    if _SET_HEADER.match(stripped):
        clauses, new_idx = _parse_clauses(lines, idx + 1)
        if clauses:
            entry["set_clauses"] = clauses
        return True, new_idx

    policy_match = _POLICY_ROUTING.match(stripped)
    if policy_match:
        _apply_policy_routing(entry, policy_match)
        return True, idx + 1

    return False, idx


def _parse_entry(
    lines: list[str],
    idx: int,
    header_match: re.Match[str],
) -> tuple[RouteMapClauseEntry, int]:
    """Parse a single route-map entry after the header line.

    Returns (entry, next_line_index).
    """
    entry = RouteMapClauseEntry(
        action=header_match.group("action"),
        sequence=int(header_match.group("seq")),
    )

    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        if _HEADER_PATTERN.match(stripped):
            break

        handled, idx = _handle_section(stripped, lines, idx, entry)
        if not handled:
            idx += 1

    return entry, idx


@register(OS.CISCO_IOSXE, "show route-map all")
class ShowRouteMapAllParser(BaseParser[ShowRouteMapAllResult]):
    """Parser for 'show route-map all' command.

    Example output:
        route-map RM_BGP_IN, permit, sequence 10
          Match clauses:
            ip address (access-lists): AL_BGP_IN
          Set clauses:
            local-preference 200
          Policy routing matches: 0 packets, 0 bytes
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteMapAllResult:
        """Parse 'show route-map all' output.

        Args:
            output: Raw CLI output from 'show route-map all' command.

        Returns:
            Parsed route-map data keyed by route-map name and sequence number.

        Raises:
            ValueError: If no route-map entries found in output.
        """
        route_maps: dict[str, dict[str, RouteMapClauseEntry]] = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            stripped = lines[idx].strip()
            if not stripped:
                idx += 1
                continue

            header_match = _HEADER_PATTERN.match(stripped)
            if not header_match:
                idx += 1
                continue

            name = header_match.group("name")
            seq = header_match.group("seq")
            entry, idx = _parse_entry(lines, idx + 1, header_match)

            if name not in route_maps:
                route_maps[name] = {}
            route_maps[name][seq] = entry

        if not route_maps:
            msg = "No route-map entries found in output"
            raise ValueError(msg)

        return ShowRouteMapAllResult(route_maps=route_maps)
