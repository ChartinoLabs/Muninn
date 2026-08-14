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

    table_version: int
    router_id: str
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
    path_and_origin = parts[-1]
    numeric_parts = parts[:-1]

    # Extract origin code from the path (last single char: i, e, or ?)
    path_tokens = path_and_origin.split()
    if not path_tokens:
        return None

    origin = path_tokens[-1]
    if origin in ("i", "e", "?"):
        as_path = " ".join(path_tokens[:-1])
    else:
        # Origin might be attached to last AS number (no space)
        last = path_tokens[-1]
        if last[-1] in ("i", "e", "?"):
            path_tokens[-1] = last[:-1]
            as_path = " ".join(t for t in path_tokens if t)
        else:
            as_path = " ".join(path_tokens)

    # Combine AS path with the origin code for the path field
    path_str = as_path

    # Parse numeric parts: the rightmost is weight, then locprf, then metric
    if not numeric_parts:
        return None

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


@register(OS.CISCO_FTD, r"show bgp neighbors (?P<neighbor_ip>\S+) routes")
class ShowBgpNeighborsRoutesParser(BaseParser["ShowBgpNeighborsRoutesResult"]):
    """Parser for 'show bgp neighbors <ip> routes' on Cisco FTD."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsRoutesResult:
        """Parse 'show bgp neighbors <ip> routes' output."""
        table_version: int | None = None
        router_id: str | None = None
        total_prefixes: int | None = None
        routes: dict[str, RouteEntry] = {}
        in_routes_section = False

        for line in output.splitlines():
            stripped = line.strip()

            if _is_noise_line(stripped):
                continue

            # Parse header line
            header_match = _TABLE_VERSION_RE.match(stripped)
            if header_match:
                table_version = int(header_match.group(1))
                router_id = header_match.group(2)
                continue

            # Parse total prefixes
            total_match = _TOTAL_PREFIXES_RE.match(stripped)
            if total_match:
                total_prefixes = int(total_match.group(1))
                continue

            # Detect column header to start route parsing
            if _COLUMN_HEADER_RE.match(line):
                in_routes_section = True
                continue

            if _should_skip(stripped) or not in_routes_section:
                continue

            # Parse route entry
            result = _parse_route_line(line)
            if result is not None:
                network, entry = result
                routes[network] = entry

        if table_version is None or router_id is None:
            msg = "Could not parse BGP table version or router ID from output"
            raise ValueError(msg)

        if total_prefixes is None:
            msg = "Could not parse total number of prefixes from output"
            raise ValueError(msg)

        return {
            "table_version": table_version,
            "router_id": router_id,
            "total_prefixes": total_prefixes,
            "routes": routes,
        }
