"""Parser for 'show bgp neighbors <ip> advertised-routes' command on Cisco FTD."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class RouteEntry(TypedDict):
    """Schema for a single advertised BGP route entry."""

    status_codes: str
    next_hop: str
    metric: NotRequired[int]
    local_pref: NotRequired[int]
    weight: int
    path: str


class ShowBgpNeighborsAdvertisedRoutesResult(TypedDict):
    """Schema for 'show bgp neighbors <ip> advertised-routes' parsed output."""

    bgp_operational: bool
    table_version: NotRequired[int]
    router_id: NotRequired[str]
    total_prefixes: int
    routes: dict[str, RouteEntry]


# --- Header pattern ---
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*local router ID is (\S+)\s*$"
)

# --- Column header detection ---
_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s*Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)

# --- Total prefixes ---
_TOTAL_PREFIXES_RE = re.compile(r"^Total number of prefixes (\d+)\s*$")

# --- Route line pattern: extracts status, network, next_hop, and remainder ---
_ROUTE_LINE_RE = re.compile(
    r"^(?P<status>[*>sdhi ]{1,3})\s*"
    r"(?P<network>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
    r"(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<rest>.+)$"
)

# --- Wrapped line: network prefix only (no next-hop on same line) ---
_WRAPPED_NETWORK_RE = re.compile(
    r"^(?P<status>[*>sdhi ]{1,3})\s*"
    r"(?P<network>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s*$"
)

# --- Continuation line: starts with whitespace, has next_hop and fields ---
_CONTINUATION_RE = re.compile(
    r"^\s+(?P<next_hop>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<rest>.+)$"
)

# Lines to skip
_SKIP_PREFIXES = (
    "Status codes:",
    "Origin codes:",
)


def _is_skip_line(stripped: str) -> bool:
    """Return True if a line should be skipped (legend, blank, etc.)."""
    if not stripped:
        return True
    for prefix in _SKIP_PREFIXES:
        if stripped.startswith(prefix):
            return True
    # Skip continuation lines of status/origin code legends (indented)
    if "RIB-failure" in stripped:
        return True
    if "Stale" in stripped and not stripped[0].isdigit():
        return True
    return False


def _parse_rest(rest: str) -> tuple[str | None, str | None, str, str]:
    """Parse the remainder after next_hop into metric, locprf, weight, path.

    The fields after next_hop follow this format:
        [metric] [locprf] weight path_with_origin

    Fields are separated by 2+ spaces. The last group is the path (which
    always contains the origin code). The group before the path is weight.
    Any groups before weight are metric and/or locprf.

    Returns:
        Tuple of (metric_str, locprf_str, weight_str, path_str).
    """
    parts = re.split(r"\s{2,}", rest.strip())

    if len(parts) == 1:
        # Everything in one group; try to extract weight and origin
        tokens = parts[0].split()
        if len(tokens) >= 2:
            return None, None, tokens[0], " ".join(tokens[1:])
        return None, None, parts[0], ""

    # Last part is always path (origin code at minimum)
    path = parts[-1]

    if len(parts) == 2:
        # [weight, path]
        return None, None, parts[0], path

    if len(parts) == 3:
        # [metric, weight, path]
        return parts[0], None, parts[1], path

    # [metric, locprf, weight, path] or more
    return parts[0], parts[1], parts[-2], path


def _build_route_entry(
    status_codes: str,
    next_hop: str,
    rest: str,
) -> RouteEntry:
    """Build a RouteEntry from parsed components."""
    metric_str, locprf_str, weight_str, path_str = _parse_rest(rest)

    entry: RouteEntry = {
        "status_codes": status_codes,
        "next_hop": next_hop,
        "weight": int(weight_str),
        "path": path_str,
    }

    if metric_str is not None:
        entry["metric"] = int(metric_str)
    if locprf_str is not None:
        entry["local_pref"] = int(locprf_str)

    return entry


def _parse_header_fields(
    stripped: str,
) -> tuple[int, str] | None:
    """Extract table version and router ID from header line.

    Returns:
        Tuple of (table_version, router_id) or None.
    """
    m = _TABLE_VERSION_RE.match(stripped)
    if m:
        return int(m.group(1)), m.group(2)
    return None


def _parse_route_section(
    lines: list[str],
    start: int,
) -> tuple[dict[str, RouteEntry], int | None, int]:
    """Parse the route table section starting at `start`.

    Returns:
        Tuple of (routes, total_prefixes, next_index).
    """
    routes: dict[str, RouteEntry] = {}
    total_prefixes: int | None = None
    pending_status: str | None = None
    pending_network: str | None = None

    i = start
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for total prefixes (end of route section)
        m = _TOTAL_PREFIXES_RE.match(stripped)
        if m:
            total_prefixes = int(m.group(1))
            i += 1
            break

        if _is_skip_line(stripped):
            i += 1
            continue

        # Handle continuation of a wrapped line
        if pending_network is not None:
            m = _CONTINUATION_RE.match(line)
            if m:
                entry = _build_route_entry(
                    pending_status or "",
                    m.group("next_hop"),
                    m.group("rest"),
                )
                routes[pending_network] = entry
            pending_network = None
            pending_status = None
            if m:
                i += 1
                continue

        # Try full route line (network + next_hop on same line)
        m = _ROUTE_LINE_RE.match(line)
        if m:
            entry = _build_route_entry(
                m.group("status").strip(),
                m.group("next_hop"),
                m.group("rest"),
            )
            routes[m.group("network")] = entry
            i += 1
            continue

        # Try wrapped line (network only, next_hop on next line)
        m = _WRAPPED_NETWORK_RE.match(line)
        if m:
            pending_status = m.group("status").strip()
            pending_network = m.group("network")
            i += 1
            continue

        i += 1

    return routes, total_prefixes, i


def _process_lines(
    lines: list[str],
) -> tuple[int | None, str | None, int | None, dict[str, RouteEntry]]:
    """Process all output lines and return parsed components.

    Returns:
        Tuple of (table_version, router_id, total_prefixes, routes).
    """
    table_version: int | None = None
    router_id: str | None = None
    total_prefixes: int | None = None
    routes: dict[str, RouteEntry] = {}

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Check for table version header
        header = _parse_header_fields(stripped)
        if header is not None:
            table_version, router_id = header
            i += 1
            continue

        # Check for column header (start of route section)
        if _COLUMN_HEADER_RE.match(line):
            routes, total_prefixes, i = _parse_route_section(lines, i + 1)
            continue

        i += 1

    return table_version, router_id, total_prefixes, routes


@register(
    OS.CISCO_FTD,
    r"show bgp neighbors (?P<neighbor>\S+) advertised-routes",
)
class ShowBgpNeighborsAdvertisedRoutesParser(
    BaseParser["ShowBgpNeighborsAdvertisedRoutesResult"],
):
    """Parser for 'show bgp neighbors <ip> advertised-routes' on Cisco FTD."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsAdvertisedRoutesResult:
        """Parse 'show bgp neighbors <neighbor> advertised-routes' output."""
        # Detect non-operational BGP
        if "% BGP cannot run" in output:
            # Extract total_prefixes if present, default to 0
            total = 0
            for line in output.splitlines():
                m = _TOTAL_PREFIXES_RE.match(line.strip())
                if m:
                    total = int(m.group(1))
                    break
            return {
                "bgp_operational": False,
                "total_prefixes": total,
                "routes": {},
            }

        table_version, router_id, total_prefixes, routes = _process_lines(
            output.splitlines()
        )

        if table_version is None or router_id is None:
            msg = "Could not parse BGP table version or local router ID from output"
            raise ValueError(msg)

        if total_prefixes is None:
            msg = "Could not parse total number of prefixes from output"
            raise ValueError(msg)

        return {
            "bgp_operational": True,
            "table_version": table_version,
            "router_id": router_id,
            "total_prefixes": total_prefixes,
            "routes": routes,
        }
