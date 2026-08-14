"""Parser for 'show bgp neighbors <ip> routes' command on Cisco FTD."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteEntry(TypedDict):
    """Schema for a single BGP route entry received from a neighbor."""

    status_codes: str
    next_hop: str
    metric: NotRequired[int]
    local_pref: NotRequired[int]
    weight: int
    path: str


class ShowBgpNeighborsRoutesResult(TypedDict):
    """Schema for 'show bgp neighbors <ip> routes' parsed output."""

    bgp_operational: bool
    table_version: NotRequired[int]
    router_id: NotRequired[str]
    total_prefixes: int
    routes: dict[str, RouteEntry]


# --- Header patterns ---
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*local router ID is (\S+)\s*$"
)

# --- Column header detection ---
_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s*Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)

# --- BGP non-operational detection ---
_BGP_CANNOT_RUN_RE = re.compile(r"^%\s*BGP cannot run")

# --- Total prefixes ---
_TOTAL_PREFIXES_RE = re.compile(r"^Total number of prefixes (\d+)\s*$")

# --- Route line regex ---
# Matches: status_codes network next_hop <remaining fields>
# The remaining fields (metric, locprf, weight, path, origin) are parsed
# separately because metric and locprf may be absent (empty space).
_ROUTE_LEFT_RE = re.compile(
    r"^(?P<status>\S+)\s+"
    r"(?P<network>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
    r"(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<rest>.+)$"
)

# Lines to skip
_SKIP_PREFIXES = (
    "Status codes:",
    "Origin codes:",
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a leading prompt/noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return False


def _should_skip(stripped: str) -> bool:
    """Return True if a line should be skipped (legend, header, etc.)."""
    if not stripped:
        return True
    for prefix in _SKIP_PREFIXES:
        if stripped.startswith(prefix):
            return True
    # Skip continuation lines of the status/origin code legend
    if "RIB-failure" in stripped:
        return True
    return False


def _extract_as_path(path_and_origin: str) -> str | None:
    """Extract the AS path from a combined path+origin string.

    The origin code (i, e, or ?) may be a separate token or attached to the
    last AS number. Returns the AS path without the origin, or None on failure.
    """
    path_tokens = path_and_origin.split()
    if not path_tokens:
        return None

    origin = path_tokens[-1]
    if origin in ("i", "e", "?"):
        return " ".join(path_tokens[:-1])

    # Origin might be attached to last AS number (no space)
    last = path_tokens[-1]
    if last[-1] in ("i", "e", "?"):
        path_tokens[-1] = last[:-1]
        return " ".join(t for t in path_tokens if t)

    return " ".join(path_tokens)


def _parse_numeric_fields(
    numeric_parts: list[str],
) -> tuple[int | None, int | None, int] | None:
    """Parse metric, local_pref, and weight from numeric field groups.

    The rightmost numeric part is weight, then locprf, then metric (right to
    left). Returns (metric, local_pref, weight) or None if weight cannot be
    parsed.
    """
    try:
        weight = int(numeric_parts[-1])
    except ValueError:
        return None

    metric: int | None = None
    local_pref: int | None = None

    if len(numeric_parts) >= 3:
        metric = int(numeric_parts[-3])
        local_pref = int(numeric_parts[-2])
    elif len(numeric_parts) == 2:
        # Ambiguous: could be (metric, weight) or (locprf, weight)
        # In Cisco output, when only one field is present before weight,
        # it's typically metric (appears left of locprf column)
        metric = int(numeric_parts[-2])

    return metric, local_pref, weight


def _parse_rest_fields(rest: str) -> tuple[int | None, int | None, int, str] | None:
    """Parse the metric/locprf/weight/path fields from the right portion of a route.

    In Cisco BGP output, weight and path are always present. Metric and locprf
    may be absent. The weight field is separated from the AS path by 2+ spaces,
    while AS numbers within the path are separated by single spaces.

    Returns (metric, local_pref, weight, path) or None if parsing fails.
    """
    stripped = rest.strip()
    if not stripped:
        return None

    # Split on boundaries of 2+ spaces to identify field groups
    parts = re.split(r"\s{2,}", stripped)
    if not parts:
        return None

    # The last part contains the AS path and origin code: e.g. "65002 i"
    # All preceding parts are numeric fields (metric, locprf, weight)
    numeric_parts = parts[:-1]
    if not numeric_parts:
        return None

    path_str = _extract_as_path(parts[-1])
    if path_str is None:
        return None

    numeric_result = _parse_numeric_fields(numeric_parts)
    if numeric_result is None:
        return None

    metric, local_pref, weight = numeric_result
    return metric, local_pref, weight, path_str


def _parse_route_line(line: str) -> tuple[str, RouteEntry] | None:
    """Parse a single route line.

    Returns (network, entry) or None if the line is not a valid route.
    """
    match = _ROUTE_LEFT_RE.match(line)
    if not match:
        return None

    status = match.group("status")
    network = match.group("network")
    next_hop = match.group("next_hop")
    rest = match.group("rest")

    fields = _parse_rest_fields(rest)
    if fields is None:
        return None

    metric, local_pref, weight, path_str = fields

    entry: RouteEntry = {
        "status_codes": status,
        "next_hop": next_hop,
        "weight": weight,
        "path": path_str,
    }

    if metric is not None:
        entry["metric"] = metric
    if local_pref is not None:
        entry["local_pref"] = local_pref

    return network, entry


class _ParseState:
    """Mutable state container for iterative line parsing."""

    table_version: int | None = None
    router_id: str | None = None
    total_prefixes: int | None = None
    routes: dict[str, RouteEntry]
    in_routes_section: bool = False
    bgp_operational: bool = True

    def __init__(self) -> None:
        self.routes = {}


def _process_line(state: _ParseState, line: str) -> None:
    """Process a single line and update parse state."""
    stripped = line.strip()

    if _is_noise_line(stripped):
        return

    if _BGP_CANNOT_RUN_RE.match(stripped):
        state.bgp_operational = False
        return

    header_match = _TABLE_VERSION_RE.match(stripped)
    if header_match:
        state.table_version = int(header_match.group(1))
        state.router_id = header_match.group(2)
        return

    total_match = _TOTAL_PREFIXES_RE.match(stripped)
    if total_match:
        state.total_prefixes = int(total_match.group(1))
        return

    if _COLUMN_HEADER_RE.match(line):
        state.in_routes_section = True
        return

    if _should_skip(stripped) or not state.in_routes_section:
        return

    result = _parse_route_line(line)
    if result is not None:
        network, entry = result
        state.routes[network] = entry


@register(OS.CISCO_FTD, r"show bgp neighbors (?P<neighbor_ip>\S+) routes")
class ShowBgpNeighborsRoutesParser(BaseParser["ShowBgpNeighborsRoutesResult"]):
    """Parser for 'show bgp neighbors <ip> routes' on Cisco FTD."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsRoutesResult:
        """Parse 'show bgp neighbors <ip> routes' output."""
        state = _ParseState()

        for line in output.splitlines():
            _process_line(state, line)

        if not state.bgp_operational:
            return {
                "bgp_operational": False,
                "total_prefixes": state.total_prefixes
                if state.total_prefixes is not None
                else 0,
                "routes": {},
            }

        if state.table_version is None or state.router_id is None:
            msg = "Could not parse BGP table version or router ID from output"
            raise ValueError(msg)

        if state.total_prefixes is None:
            msg = "Could not parse total number of prefixes from output"
            raise ValueError(msg)

        return {
            "bgp_operational": True,
            "table_version": state.table_version,
            "router_id": state.router_id,
            "total_prefixes": state.total_prefixes,
            "routes": state.routes,
        }
