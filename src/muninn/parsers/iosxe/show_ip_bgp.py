"""Parser for 'show ip bgp' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class PathEntry(TypedDict):
    """Schema for a single BGP path."""

    status_codes: str
    path_type: str
    next_hop: str
    metric: NotRequired[int]
    locprf: NotRequired[int]
    weight: int
    as_path: str
    origin: str


class RouteEntry(TypedDict):
    """Schema for a single BGP route (network prefix)."""

    paths: list[PathEntry]


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family."""

    table_version: int
    router_id: str
    routes: dict[str, RouteEntry]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    address_families: dict[str, AddressFamilyEntry]


class ShowIpBgpResult(TypedDict):
    """Schema for 'show ip bgp' parsed output on IOS-XE."""

    vrfs: dict[str, VrfEntry]


# --- Header and column patterns ---
_TABLE_VERSION_RE = re.compile(
    r"^\s*BGP table version is (\d+),\s*local\s+router\s+ID\s+is\s+(\S+)",
)
_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s+Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)

# Route line pattern: captures status/pathtype prefix, optional network,
# and next hop IP. We use column-based parsing for the data fields after
# the next hop.
_ROUTE_RE = re.compile(
    r"^(?P<prefix>[* >sxSdhmrbi]{2,5})"  # 2-5 char status+pathtype prefix
    r"\s*"  # optional spacing after prefix
    r"(?P<network>\d\S+)?"  # optional network (starts with digit)
    r"\s+"  # whitespace separator
    r"(?P<nexthop>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # next hop IPv4
    r"(?=\s)"  # must be followed by whitespace (not CIDR slash)
)

# Continuation line: only next-hop and data fields, deeply indented.
_CONTINUATION_RE = re.compile(
    r"^\s+"  # leading whitespace
    r"(?P<nexthop>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # next hop IPv4
    r"(?=\s)"  # must be followed by whitespace
)

# Wrapped network line: prefix + optional spacing + network, no data.
_WRAPPED_NET_RE = re.compile(
    r"^(?P<prefix>[* >sxSdhmrbi]{2,5})"
    r"\s*"  # optional spacing
    r"(?P<network>\d\S+)\s*$"  # network fills the rest of line
)


class _ColumnPositions:
    """Column start positions derived from the header line."""

    __slots__ = ("metric", "locprf", "weight", "path")

    def __init__(self, metric: int, locprf: int, weight: int, path: int) -> None:
        self.metric = metric
        self.locprf = locprf
        self.weight = weight
        self.path = path


def _find_column_positions(lines: list[str]) -> _ColumnPositions | None:
    """Find column start positions from the header line."""
    for line in lines:
        if _COLUMN_HEADER_RE.match(line):
            return _ColumnPositions(
                metric=line.index("Metric"),
                locprf=line.index("LocPrf"),
                weight=line.index("Weight"),
                path=line.index("Path"),
            )
    return None


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a prompt/noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _strip_noise(lines: list[str]) -> list[str]:
    """Strip leading and trailing prompt/noise lines."""
    result: list[str] = []
    started = False
    for line in lines:
        if not started:
            if _is_noise_line(line.strip()):
                continue
            started = True
        result.append(line)
    while result and _is_noise_line(result[-1].strip()):
        result.pop()
    return result


def _safe_slice(line: str, start: int, end: int) -> str:
    """Extract a substring from line[start:end], handling short lines."""
    if start >= len(line):
        return ""
    return line[start : min(end, len(line))].strip()


def _parse_origin_and_path(path_field: str) -> tuple[str, str]:
    """Split path field into (as_path, origin).

    Handles AS path sets like {27016} by including them in as_path.
    """
    if not path_field:
        return ("", "")
    tokens = path_field.split()
    if not tokens:
        return ("", "")
    origin = tokens[-1]
    as_path = " ".join(tokens[:-1])
    return (as_path, origin)


def _extract_status_and_path_type(prefix: str) -> tuple[str, str]:
    """Split the prefix area into (status_codes, path_type).

    The prefix contains status codes and optionally a path type indicator
    ``i`` (internal). If present, ``i`` is always the last non-space char.
    """
    stripped = prefix.rstrip()
    if stripped.endswith("i"):
        return (stripped[:-1].strip(), "i")
    return (stripped.strip(), "")


def _parse_data_fields(
    line: str,
    cols: _ColumnPositions,
) -> tuple[str, str, str, str]:
    """Extract (metric, locprf, weight, path) from a line using columns.

    Metric and LocPrf are extracted from fixed column ranges. Weight and
    Path share a boundary that can overlap when AS paths are long, so
    weight is extracted as the first numeric token from the weight column
    onward, and the remaining text is the path.
    """
    metric = _safe_slice(line, cols.metric, cols.locprf)
    locprf = _safe_slice(line, cols.locprf, cols.weight)

    # Weight and path: extract from weight column to end of line,
    # then split into weight (first token) and path (rest).
    tail = line[cols.weight :].strip() if cols.weight < len(line) else ""
    tokens = tail.split(None, 1)
    if tokens:
        weight = tokens[0]
        path = tokens[1] if len(tokens) > 1 else ""
    else:
        weight = ""
        path = ""
    return (metric, locprf, weight, path)


def _build_path_entry(
    status_codes: str,
    path_type: str,
    next_hop: str,
    metric_str: str,
    locprf_str: str,
    weight_str: str,
    path_field: str,
) -> PathEntry | None:
    """Build a PathEntry from raw field strings."""
    if not next_hop:
        return None
    try:
        weight = int(weight_str)
    except (ValueError, TypeError):
        return None

    as_path, origin = _parse_origin_and_path(path_field)
    entry: PathEntry = {
        "status_codes": status_codes,
        "path_type": path_type,
        "next_hop": next_hop,
        "weight": weight,
        "as_path": as_path,
        "origin": origin,
    }
    if metric_str:
        entry["metric"] = int(metric_str)
    if locprf_str:
        entry["locprf"] = int(locprf_str)
    return entry


class _RouteState:
    """Mutable state for route parsing."""

    __slots__ = (
        "current_network",
        "pending_status",
        "pending_path_type",
        "awaiting_data",
    )

    def __init__(self) -> None:
        self.current_network: str | None = None
        self.pending_status: str = ""
        self.pending_path_type: str = ""
        self.awaiting_data: bool = False


def _add_path(
    routes: dict[str, RouteEntry],
    network: str,
    path_entry: PathEntry,
) -> None:
    """Add a path entry to routes under the given network prefix."""
    if network not in routes:
        routes[network] = {"paths": []}
    routes[network]["paths"].append(path_entry)


def _handle_data_line(
    prefix: str,
    network: str,
    nexthop: str,
    line: str,
    cols: _ColumnPositions,
    routes: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Process a route line that has next-hop data."""
    status_codes, path_type = _extract_status_and_path_type(prefix)
    metric, locprf, weight_str, path_field = _parse_data_fields(line, cols)

    if network:
        state.current_network = network
        state.pending_status = status_codes
        state.pending_path_type = path_type
        state.awaiting_data = False

    entry = _build_path_entry(
        status_codes, path_type, nexthop, metric, locprf, weight_str, path_field
    )

    if state.awaiting_data and not network and entry:
        entry["status_codes"] = state.pending_status
        entry["path_type"] = state.pending_path_type
        state.awaiting_data = False

    if state.current_network and entry:
        _add_path(routes, state.current_network, entry)


def _handle_wrapped_network(
    prefix: str,
    network: str,
    state: _RouteState,
) -> None:
    """Process a wrapped network line (network only, no data)."""
    status_codes, path_type = _extract_status_and_path_type(prefix)
    state.current_network = network
    state.pending_status = status_codes
    state.pending_path_type = path_type
    state.awaiting_data = True


def _handle_continuation(
    nexthop: str,
    line: str,
    cols: _ColumnPositions,
    routes: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Process an indented continuation line (no status/network)."""
    metric, locprf, weight_str, path_field = _parse_data_fields(line, cols)
    entry = _build_path_entry(
        state.pending_status,
        state.pending_path_type,
        nexthop,
        metric,
        locprf,
        weight_str,
        path_field,
    )
    if entry and state.current_network:
        _add_path(routes, state.current_network, entry)
        state.awaiting_data = False


def _parse_section_header(lines: list[str]) -> tuple[int, str]:
    """Extract table version and router ID from output lines.

    Raises:
        ValueError: If the header cannot be found.
    """
    for line in lines:
        m = _TABLE_VERSION_RE.match(line)
        if m:
            return (int(m.group(1)), m.group(2))
    msg = "Could not find BGP table version or router ID in output"
    raise ValueError(msg)


def _parse_routes(
    lines: list[str],
    cols: _ColumnPositions,
) -> dict[str, RouteEntry]:
    """Parse all route entries from the data lines below the column header."""
    routes: dict[str, RouteEntry] = {}
    state = _RouteState()
    in_data = False

    for line in lines:
        if not in_data:
            if _COLUMN_HEADER_RE.match(line):
                in_data = True
            continue

        if not line.strip():
            continue

        # Try full route line (prefix + optional network + nexthop)
        m = _ROUTE_RE.match(line)
        if m:
            _handle_data_line(
                m.group("prefix"),
                m.group("network") or "",
                m.group("nexthop"),
                line,
                cols,
                routes,
                state,
            )
            continue

        # Try wrapped network line (prefix + network, no data)
        m = _WRAPPED_NET_RE.match(line)
        if m:
            _handle_wrapped_network(m.group("prefix"), m.group("network"), state)
            continue

        # Try continuation line (indented, nexthop + data only)
        m = _CONTINUATION_RE.match(line)
        if m:
            _handle_continuation(m.group("nexthop"), line, cols, routes, state)
            continue

    return routes


@register(OS.CISCO_IOSXE, "show ip bgp")
@register(OS.CISCO_IOSXE, "show ip bgp regexp ^$")
class ShowIpBgpParser(BaseParser["ShowIpBgpResult"]):
    """Parser for 'show ip bgp' command on IOS-XE.

    Example output:
        BGP table version is 22, local router ID is 10.1.1.1
             Network          Next Hop            Metric LocPrf Weight Path
         *>  10.1.0.0/16      0.0.0.0                  0         32768 i
         *>i 10.2.0.0/16      10.0.0.1                 0    100      0 i
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpResult:
        """Parse 'show ip bgp' output.

        Args:
            output: Raw CLI output from 'show ip bgp' command.

        Returns:
            Parsed data with routes keyed by network prefix.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        raw_lines = output.splitlines()
        lines = _strip_noise(raw_lines)

        table_version, router_id = _parse_section_header(lines)

        cols = _find_column_positions(lines)
        if cols is None:
            msg = "Could not find column header in output"
            raise ValueError(msg)

        routes = _parse_routes(lines, cols)

        af_entry: AddressFamilyEntry = {
            "table_version": table_version,
            "router_id": router_id,
            "routes": routes,
        }

        return {
            "vrfs": {
                "default": {
                    "address_families": {
                        "IPv4 Unicast": af_entry,
                    },
                },
            },
        }
