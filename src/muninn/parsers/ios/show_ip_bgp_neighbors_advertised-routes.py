"""Parser for 'show ip bgp neighbors advertised-routes' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class RouteEntry(TypedDict):
    """Schema for a single advertised BGP route."""

    status_codes: str
    next_hop: str
    metric: NotRequired[int]
    local_pref: NotRequired[int]
    weight: int
    path: str
    origin: str


class ShowIpBgpNeighborsAdvertisedRoutesResult(TypedDict):
    """Schema for 'show ip bgp neighbors advertised-routes' parsed output."""

    local_router_id: str
    table_version: int
    routes: dict[str, RouteEntry]
    total_prefixes: NotRequired[int]


# --- Header patterns ---
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*local router ID is (\S+)\s*$"
)

# --- Column header detection ---
_COLUMN_HEADER_RE = re.compile(
    r"^(?P<pre>\s*)Network\s+Next\s*Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)

# --- Total prefixes ---
_TOTAL_PREFIXES_RE = re.compile(r"^Total number of prefixes (\d+)\s*$")

# Lines to skip
_SKIP_PREFIXES = (
    "Status codes:",
    "Origin codes:",
    "Route Distinguisher:",
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a leading prompt/noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _should_skip(stripped: str) -> bool:
    """Return True if a line should be skipped (legend, header, etc.)."""
    if not stripped:
        return True
    for prefix in _SKIP_PREFIXES:
        if stripped.startswith(prefix):
            return True
    # Skip continuation lines of the status/origin code legend
    if "RIB-failure" in stripped and stripped.lstrip().startswith("r "):
        return True
    if "Stale" in stripped and stripped.lstrip().startswith("S "):
        return True
    return False


def _find_column_positions(line: str) -> dict[str, int]:
    """Extract column start positions from the header line.

    Returns a dict mapping column name to its start position in the line.
    """
    columns = {}
    for col_name in ("Network", "Next", "Metric", "LocPrf", "Weight", "Path"):
        idx = line.find(col_name)
        if idx >= 0:
            columns[col_name] = idx
    return columns


def _parse_route_by_columns(
    line: str,
    columns: dict[str, int],
) -> tuple[str, str, RouteEntry] | None:
    """Parse a single route line using column positions.

    Returns (status_codes, network, entry) or None if the line is not a route.
    """
    network_col = columns.get("Network", 0)
    nexthop_col = columns.get("Next", 0)
    metric_col = columns.get("Metric", 0)
    locprf_col = columns.get("LocPrf", 0)
    weight_col = columns.get("Weight", 0)
    path_col = columns.get("Path", 0)

    # Status codes occupy the space before the Network column
    if len(line) < path_col:
        return None

    status_part = line[:network_col].rstrip()

    # Network field: from network_col to nexthop_col
    network_field = line[network_col:nexthop_col].strip()
    if not network_field:
        return None

    # Validate it looks like an IP prefix
    if not re.match(r"\d+\.\d+\.\d+\.\d+", network_field):
        return None

    # Next hop field: from nexthop_col to metric_col
    nexthop_field = line[nexthop_col:metric_col].strip()
    if not nexthop_field:
        return None

    # Metric field: from metric_col to locprf_col
    metric_field = line[metric_col:locprf_col].strip()

    # LocPrf field: from locprf_col to weight_col
    locprf_field = line[locprf_col:weight_col].strip()

    # Weight field: from weight_col to path_col
    weight_field = line[weight_col:path_col].strip()
    if not weight_field:
        return None

    # Path + origin: everything from path_col onwards
    path_and_origin = line[path_col:].strip()

    # Origin code is the last non-whitespace character (i, e, or ?)
    if not path_and_origin:
        origin = ""
        as_path = ""
    elif path_and_origin[-1] in ("i", "e", "?"):
        origin = path_and_origin[-1]
        as_path = path_and_origin[:-1].strip()
    else:
        origin = ""
        as_path = path_and_origin

    entry: RouteEntry = {
        "status_codes": status_part,
        "next_hop": nexthop_field,
        "weight": int(weight_field),
        "path": as_path,
        "origin": origin,
    }

    if metric_field:
        entry["metric"] = int(metric_field)
    if locprf_field:
        entry["local_pref"] = int(locprf_field)

    return status_part, network_field, entry


def _parse_header_line(
    stripped: str,
) -> tuple[int, str] | None:
    """Extract table version and router ID from the header line.

    Returns:
        Tuple of (table_version, local_router_id) or None.
    """
    m = _TABLE_VERSION_RE.match(stripped)
    if m:
        return int(m.group(1)), m.group(2)
    return None


def _parse_total_prefixes(stripped: str) -> int | None:
    """Extract total prefix count from the summary line."""
    m = _TOTAL_PREFIXES_RE.match(stripped)
    if m:
        return int(m.group(1))
    return None


def _process_lines(
    lines: list[str],
) -> tuple[str | None, int | None, dict[str, RouteEntry], int | None]:
    """Process all output lines and return parsed components.

    Returns:
        Tuple of (local_router_id, table_version, routes, total_prefixes).
    """
    local_router_id: str | None = None
    table_version: int | None = None
    routes: dict[str, RouteEntry] = {}
    total_prefixes: int | None = None
    columns: dict[str, int] | None = None

    for line in lines:
        stripped = line.strip()

        if _is_noise_line(stripped):
            continue

        header = _parse_header_line(stripped)
        if header is not None:
            table_version, local_router_id = header
            continue

        prefix_count = _parse_total_prefixes(stripped)
        if prefix_count is not None:
            total_prefixes = prefix_count
            columns = None
            continue

        if _COLUMN_HEADER_RE.match(line):
            columns = _find_column_positions(line)
            continue

        if _should_skip(stripped) or columns is None:
            continue

        result = _parse_route_by_columns(line, columns)
        if result is not None:
            _status, network, entry = result
            routes[network] = entry

    return local_router_id, table_version, routes, total_prefixes


@register(OS.CISCO_IOS, "show ip bgp neighbors advertised-routes")
class ShowIpBgpNeighborsAdvertisedRoutesParser(
    BaseParser["ShowIpBgpNeighborsAdvertisedRoutesResult"],
):
    """Parser for 'show ip bgp neighbors advertised-routes' on IOS."""

    tags: ClassVar[frozenset[str]] = frozenset({"bgp", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpNeighborsAdvertisedRoutesResult:
        """Parse 'show ip bgp neighbors advertised-routes' output."""
        local_router_id, table_version, routes, total_prefixes = _process_lines(
            output.splitlines()
        )

        if local_router_id is None or table_version is None:
            msg = "Could not parse BGP table version or local router ID from output"
            raise ValueError(msg)

        parsed: ShowIpBgpNeighborsAdvertisedRoutesResult = {
            "local_router_id": local_router_id,
            "table_version": table_version,
            "routes": routes,
        }

        if total_prefixes is not None:
            parsed["total_prefixes"] = total_prefixes

        return parsed
