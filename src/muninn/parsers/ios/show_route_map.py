"""Parser for 'show route-map' command on IOS."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class RouteMapSequenceEntry(TypedDict):
    """Schema for a single route-map sequence entry."""

    action: str
    match_clauses: list[str]
    set_clauses: list[str]
    policy_routing_packets: NotRequired[int]
    policy_routing_bytes: NotRequired[int]


class RouteMapEntry(TypedDict):
    """Schema for a single route-map with all its sequences."""

    sequences: dict[str, RouteMapSequenceEntry]


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


@dataclass
class _ParseState:
    """Mutable parser state for the current route-map sequence."""

    route_maps: dict[str, RouteMapEntry] = field(default_factory=dict)
    name: str | None = None
    sequence: str | None = None
    action: str | None = None
    match_clauses: list[str] = field(default_factory=list)
    set_clauses: list[str] = field(default_factory=list)
    policy_routing_packets: int | None = None
    policy_routing_bytes: int | None = None

    def flush(self) -> None:
        """Save the current route-map sequence into the result."""
        if self.name is None or self.sequence is None or self.action is None:
            return

        if self.name not in self.route_maps:
            self.route_maps[self.name] = RouteMapEntry(sequences={})

        sequence_entry: RouteMapSequenceEntry = {
            "action": self.action,
            "match_clauses": list(self.match_clauses),
            "set_clauses": list(self.set_clauses),
        }
        if self.policy_routing_packets is not None:
            sequence_entry["policy_routing_packets"] = self.policy_routing_packets
        if self.policy_routing_bytes is not None:
            sequence_entry["policy_routing_bytes"] = self.policy_routing_bytes

        self.route_maps[self.name]["sequences"][self.sequence] = sequence_entry

    def start_new(self, name: str, sequence: str, action: str) -> None:
        """Begin a new route-map sequence, flushing any current one."""
        self.flush()
        self.name = name
        self.sequence = sequence
        self.action = action
        self.match_clauses = []
        self.set_clauses = []
        self.policy_routing_packets = None
        self.policy_routing_bytes = None


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

    tags: ClassVar[frozenset[str]] = frozenset({"routing"})

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
        state = _ParseState()
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

            state.start_new(
                name=header_match.group("name"),
                sequence=header_match.group("sequence"),
                action=header_match.group("action"),
            )
            idx += 1
            idx = _parse_entry_body(lines, idx, state)

        state.flush()

        if not state.route_maps:
            msg = "No route-map entries found in output"
            raise ValueError(msg)

        return {"route_maps": state.route_maps}


def _parse_entry_body(lines: list[str], idx: int, state: _ParseState) -> int:
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
            state.match_clauses = clauses
            continue

        if _SET_HEADER.match(line):
            idx += 1
            clauses, idx = _parse_clause_lines(lines, idx)
            state.set_clauses = clauses
            continue

        policy_match = _POLICY_ROUTING.match(line)
        if policy_match:
            state.policy_routing_packets = int(policy_match.group("packets"))
            state.policy_routing_bytes = int(policy_match.group("bytes"))
            idx += 1
            break

        idx += 1

    return idx
