"""Parser for 'show route' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NextHopEntry(TypedDict):
    """Schema for a single next-hop within a route entry."""

    to: NotRequired[str]
    via: NotRequired[str]
    selected: bool
    local: NotRequired[bool]


class RouteEntry(TypedDict):
    """Schema for a single route entry (one protocol contributing a route)."""

    protocol: str
    preference: int
    preference2: NotRequired[int]
    age: str
    metric: NotRequired[int]
    tag: NotRequired[int]
    med: NotRequired[int]
    local_preference: NotRequired[int]
    from_peer: NotRequired[str]
    as_path: NotRequired[str]
    validation_state: NotRequired[str]
    next_hops: list[NextHopEntry]
    active: bool


class PrefixEntry(TypedDict):
    """Schema for a destination prefix with one or more route entries."""

    routes: list[RouteEntry]


class RoutingTableEntry(TypedDict):
    """Schema for a routing table (RIB)."""

    destinations: int
    total_routes: int
    active_routes: int
    holddown: int
    hidden: int
    prefixes: dict[str, PrefixEntry]


# Top-level result keyed by routing table name (e.g. 'inet.0').
ShowRouteResult = dict[str, RoutingTableEntry]


# --- Compiled patterns ---

_TABLE_HEADER_RE = re.compile(
    r"^(?P<name>\S+):\s+"
    r"(?P<destinations>\d+)\s+destinations,\s+"
    r"(?P<total>\d+)\s+routes\s+"
    r"\((?P<active>\d+)\s+active,\s+"
    r"(?P<holddown>\d+)\s+holddown,\s+"
    r"(?P<hidden>\d+)\s+hidden\)"
)

# Matches a destination prefix line with the first route entry:
# 10.1.0.0/24         *[Direct/0] 29w6d 21:35:55
# 2001:db8:eb18:ca45::1/128  *[Static/5] 3w5d 18:30:36
_PREFIX_ROUTE_RE = re.compile(
    r"^(?P<prefix>\S+/\d+)\s+"
    r"(?P<active>[*\-]?)"
    r"\[(?P<protocol>[^/]+)/(?P<pref>\d+)(?:/(?P<pref2>\d+))?\]\s+"
    r"(?P<age>\S+(?:\s+\S+)?)"
)

# Matches a continuation route entry (second+ protocol for same prefix):
#                     [OSPF/150/10] 3w3d 03:12:45, metric 20, tag 0
_CONTINUATION_ROUTE_RE = re.compile(
    r"^\s+"
    r"(?P<active>[*\-]?)"
    r"\[(?P<protocol>[^/]+)/(?P<pref>\d+)(?:/(?P<pref2>\d+))?\]\s+"
    r"(?P<age>\S+(?:\s+\S+)?)"
)

# Matches a next-hop line with "to <addr> via <intf>":
#                         >  to 10.169.14.121 via ge-0/0/1.0
_NEXTHOP_TO_VIA_RE = re.compile(
    r"^\s+(?P<selected>>)?\s*to\s+(?P<to>\S+)\s+via\s+(?P<via>\S+)"
)

# Matches a next-hop line with just "via <intf>" (Direct routes):
#                         >  via fxp0.0
_NEXTHOP_VIA_RE = re.compile(r"^\s+(?P<selected>>)?\s*via\s+(?P<via>\S+)")

# Matches "Local via <intf>" next-hop (Local routes):
#                         Local via fxp0.0
_NEXTHOP_LOCAL_RE = re.compile(r"^\s+Local\s+via\s+(?P<via>\S+)")

# Matches route attributes after age on the same line or continuation:
# , metric 101, tag 0
_METRIC_RE = re.compile(r"metric\s+(?P<metric>\d+)")
_TAG_RE = re.compile(r"tag\s+(?P<tag>\d+)")
_MED_RE = re.compile(r"MED\s+(?P<med>\d+)")
_LOCALPREF_RE = re.compile(r"localpref\s+(?P<localpref>\d+)")
_FROM_RE = re.compile(r"from\s+(?P<from>\S+)")

# AS path line:
# AS path: (65151 65000) I, validation-state: unverified
_AS_PATH_RE = re.compile(
    r"^\s+AS path:\s+(?P<as_path>.+?)(?:,\s*validation-state:\s*(?P<vs>\S+))?\s*$"
)


def _apply_route_attributes(entry: RouteEntry, text: str) -> None:
    """Extract and apply optional route attributes to a RouteEntry."""
    if m := _METRIC_RE.search(text):
        entry["metric"] = int(m.group("metric"))
    if m := _TAG_RE.search(text):
        entry["tag"] = int(m.group("tag"))
    if m := _MED_RE.search(text):
        entry["med"] = int(m.group("med"))
    if m := _LOCALPREF_RE.search(text):
        entry["local_preference"] = int(m.group("localpref"))
    if m := _FROM_RE.search(text):
        entry["from_peer"] = m.group("from")


def _build_route_entry(
    match: re.Match[str],
    attr_text: str,
) -> RouteEntry:
    """Build a RouteEntry from a regex match and the full attribute text."""
    active_marker = match.group("active")
    entry: RouteEntry = {
        "protocol": match.group("protocol"),
        "preference": int(match.group("pref")),
        "age": match.group("age").rstrip(","),
        "next_hops": [],
        "active": active_marker == "*",
    }

    pref2 = match.group("pref2")
    if pref2 is not None:
        entry["preference2"] = int(pref2)

    _apply_route_attributes(entry, attr_text)

    return entry


def _parse_nexthop(line: str) -> NextHopEntry | None:
    """Try to parse a next-hop line, returning None if not a next-hop."""
    if m := _NEXTHOP_LOCAL_RE.match(line):
        return NextHopEntry(selected=False, local=True, via=m.group("via"))

    if m := _NEXTHOP_TO_VIA_RE.match(line):
        return NextHopEntry(
            selected=m.group("selected") == ">",
            to=m.group("to"),
            via=m.group("via"),
        )

    if m := _NEXTHOP_VIA_RE.match(line):
        return NextHopEntry(
            selected=m.group("selected") == ">",
            via=m.group("via"),
        )

    return None


def _is_noise(stripped: str) -> bool:
    """Return True for lines that should be skipped (prompts, legends, empty)."""
    if not stripped:
        return True
    if stripped.startswith("+ =") or stripped.startswith("- ="):
        return True
    # Skip command echo lines (e.g. "show route protocol ospf")
    if stripped.startswith("show "):
        return True
    return False


def _new_table_entry(m: re.Match[str]) -> RoutingTableEntry:
    """Create a RoutingTableEntry from a table header regex match."""
    return {
        "destinations": int(m.group("destinations")),
        "total_routes": int(m.group("total")),
        "active_routes": int(m.group("active")),
        "holddown": int(m.group("holddown")),
        "hidden": int(m.group("hidden")),
        "prefixes": {},
    }


def _apply_as_path(route: RouteEntry, m: re.Match[str]) -> None:
    """Apply AS path and validation-state from a regex match to a route."""
    route["as_path"] = m.group("as_path").strip()
    vs = m.group("vs")
    if vs:
        route["validation_state"] = vs


def _add_prefix_route(table: RoutingTableEntry, prefix: str, route: RouteEntry) -> None:
    """Append a route entry to the given prefix within a routing table."""
    if prefix not in table["prefixes"]:
        table["prefixes"][prefix] = {"routes": []}
    table["prefixes"][prefix]["routes"].append(route)


class _ParseState:
    """Mutable state container for the routing table line parser."""

    __slots__ = ("result", "table", "prefix", "route")

    def __init__(self) -> None:
        self.result: ShowRouteResult = {}
        self.table: RoutingTableEntry | None = None
        self.prefix: str | None = None
        self.route: RouteEntry | None = None


def _parse_tables(lines: list[str]) -> ShowRouteResult:
    """Parse all routing tables from the output lines."""
    state = _ParseState()

    for line in lines:
        stripped = line.strip()
        if _is_noise(stripped):
            continue
        _process_line(state, line, stripped)

    return state.result


def _process_line(state: _ParseState, line: str, stripped: str) -> None:
    """Dispatch a single non-noise line to the appropriate handler."""
    # Check for routing table header
    if m := _TABLE_HEADER_RE.match(stripped):
        state.table = _new_table_entry(m)
        state.result[m.group("name")] = state.table
        state.prefix = None
        state.route = None
        return

    if state.table is None:
        return

    # AS path line (belongs to current route)
    if m := _AS_PATH_RE.match(line):
        if state.route is not None:
            _apply_as_path(state.route, m)
        return

    # Next-hop line
    nh = _parse_nexthop(line)
    if nh is not None:
        if state.route is not None:
            state.route["next_hops"].append(nh)
        return

    # Prefix + route line
    if m := _PREFIX_ROUTE_RE.match(stripped):
        prefix = m.group("prefix")
        state.prefix = prefix
        state.route = _build_route_entry(m, stripped)
        _add_prefix_route(state.table, prefix, state.route)
        return

    # Continuation route (additional protocol for same prefix)
    if m := _CONTINUATION_ROUTE_RE.match(line):
        if state.prefix is not None:
            state.route = _build_route_entry(m, line)
            _add_prefix_route(state.table, state.prefix, state.route)
        return


@register(OS.JUNIPER_JUNOS, "show route")
class ShowRouteParser(BaseParser["ShowRouteResult"]):
    """Parser for 'show route' command on Juniper Junos.

    Parses routing table headers, destination prefixes, route entries
    with protocol/preference/age, next-hops, AS paths, and metrics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowRouteResult:
        """Parse 'show route' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed routing table information keyed by table name.

        Raises:
            ValueError: If no routing tables are found in output.
        """
        lines = output.splitlines()
        result = _parse_tables(lines)

        if not result:
            msg = "No routing tables found in output"
            raise ValueError(msg)

        return result
