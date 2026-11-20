"""Parser for 'show route-map' command on NX-OS."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteMapSequenceEntry(TypedDict):
    """Schema for a single route-map sequence."""

    action: str
    match_clauses: list[str]
    set_clauses: list[str]
    description: NotRequired[str]


class RouteMapEntry(TypedDict):
    """Schema for a single route-map with all its sequences."""

    sequences: dict[str, RouteMapSequenceEntry]


class ShowRouteMapResult(TypedDict):
    """Schema for 'show route-map' parsed output."""

    route_maps: dict[str, RouteMapEntry]


_HEADER_PATTERN = re.compile(
    r"^route-map\s+(?P<name>\S+),\s+(?P<action>permit|deny),"
    r"\s+sequence\s+(?P<seq>\d+)",
    re.IGNORECASE,
)
_MATCH_HEADER = re.compile(r"^\s*Match clauses:\s*$")
_SET_HEADER = re.compile(r"^\s*Set clauses:\s*$")
_CLAUSE_INDENT = "    "


@dataclass
class _ParseState:
    """Mutable state for the route-map parser."""

    route_maps: dict[str, RouteMapEntry] = field(default_factory=dict)
    name: str | None = None
    seq: str | None = None
    action: str | None = None
    section: str | None = None
    match_clauses: list[str] = field(default_factory=list)
    set_clauses: list[str] = field(default_factory=list)

    def flush(self) -> None:
        """Save current sequence into route_maps and reset."""
        if self.name is None or self.seq is None or self.action is None:
            return
        if self.name not in self.route_maps:
            self.route_maps[self.name] = RouteMapEntry(sequences={})
        self.route_maps[self.name]["sequences"][self.seq] = RouteMapSequenceEntry(
            action=self.action,
            match_clauses=list(self.match_clauses),
            set_clauses=list(self.set_clauses),
        )

    def start_new(self, name: str, seq: str, action: str) -> None:
        """Begin a new route-map sequence, flushing the previous one."""
        self.flush()
        self.name = name
        self.seq = seq
        self.action = action
        self.match_clauses = []
        self.set_clauses = []
        self.section = None


def _is_clause_line(line: str) -> bool:
    """Check if a line is an indented clause value."""
    return line.startswith(_CLAUSE_INDENT) and bool(line.strip())


def _process_line(line: str, state: _ParseState) -> None:
    """Process a single line of route-map output and update state."""
    stripped = line.strip()

    header = _HEADER_PATTERN.match(stripped)
    if header:
        state.start_new(
            header.group("name"),
            header.group("seq"),
            header.group("action"),
        )
        return

    if _MATCH_HEADER.match(line):
        state.section = "match"
        return

    if _SET_HEADER.match(line):
        state.section = "set"
        return

    if _is_clause_line(line) and state.section:
        if state.section == "match":
            state.match_clauses.append(stripped)
        else:
            state.set_clauses.append(stripped)


@register(OS.CISCO_NXOS, "show route-map")
class ShowRouteMapParser(BaseParser[ShowRouteMapResult]):
    """Parser for 'show route-map' command.

    Example output:
        route-map RM-TEST-OUT, permit, sequence 10
          Match clauses:
            as-path (as-path filter): AS-TEST
          Set clauses:
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteMapResult:
        """Parse 'show route-map' output.

        Args:
            output: Raw CLI output from 'show route-map' command.

        Returns:
            Parsed route-map data keyed by route-map name.

        Raises:
            ValueError: If no route-maps found in output.
        """
        state = _ParseState()

        for line in output.splitlines():
            _process_line(line, state)

        state.flush()

        if not state.route_maps:
            msg = "No route-maps found in output"
            raise ValueError(msg)

        return ShowRouteMapResult(route_maps=state.route_maps)
