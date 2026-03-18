"""Parser for 'show bgp all' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
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


class RdEntry(TypedDict):
    """Schema for a route distinguisher section."""

    rd: str
    default_vrf: NotRequired[str]
    vrf_router_id: NotRequired[str]
    af_private_import_to_af: NotRequired[str]
    pfx_count: NotRequired[int]
    pfx_limit: NotRequired[int]
    routes: dict[str, RouteEntry]


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family."""

    table_version: NotRequired[int]
    router_id: NotRequired[str]
    route_distinguishers: NotRequired[dict[str, RdEntry]]
    routes: NotRequired[dict[str, RouteEntry]]


class ShowBgpAllResult(TypedDict):
    """Schema for 'show bgp all' parsed output on IOS-XE."""

    address_families: dict[str, AddressFamilyEntry]


# --- Regex patterns ---

_AF_HEADER_RE = re.compile(r"^\s*For address family:\s+(.+?)\s*$")

_TABLE_VERSION_RE = re.compile(
    r"^\s*BGP table version is (\d+),\s*local\s+router\s+ID\s+is\s+(\S+)",
)

_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s+Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)

_RD_RE = re.compile(
    r"^\s*Route Distinguisher:\s+(?P<rd>\S+)"
    r"(?:\s+\(default for vrf (?P<vrf>\S+)\))?"
    r"(?:\s+VRF Router ID (?P<vrf_rid>\S+))?"
    r"\s*$"
)

_AF_PRIVATE_IMPORT_RE = re.compile(
    r"^\s*AF-Private Import to Address-Family:\s+(?P<af>.+?),"
    r"\s+Pfx Count/Limit:\s+(?P<count>\d+)/(?P<limit>\d+)\s*$"
)

_ROUTE_RE = re.compile(
    r"^(?P<prefix>[* >sxSdhmrbi]{2,5})"
    r"\s*"
    r"(?P<network>\S+)?"
    r"\s+"
    rf"(?P<nexthop>{IPV4_ADDRESS}|[:0-9A-Fa-f]+:[:0-9A-Fa-f]+)"
    r"(?=\s)"
)

_CONTINUATION_RE = re.compile(
    r"^\s+"
    rf"(?P<nexthop>{IPV4_ADDRESS}|[:0-9A-Fa-f]+:[:0-9A-Fa-f]+)"
    r"(?=\s)"
)

_WRAPPED_NET_RE = re.compile(
    r"^(?P<prefix>[* >sxSdhmrbi]{2,5})"
    r"\s*"
    r"(?P<network>\S+)\s*$"
)


class _ColumnPositions:
    """Column start positions derived from the header line."""

    __slots__ = ("metric", "locprf", "weight", "path")

    def __init__(self, metric: int, locprf: int, weight: int, path: int) -> None:
        self.metric = metric
        self.locprf = locprf
        self.weight = weight
        self.path = path


def _find_column_positions(line: str) -> _ColumnPositions:
    """Find column start positions from a header line."""
    return _ColumnPositions(
        metric=line.index("Metric"),
        locprf=line.index("LocPrf"),
        weight=line.index("Weight"),
        path=line.index("Path"),
    )


def _safe_slice(line: str, start: int, end: int) -> str:
    """Extract a substring from line[start:end], handling short lines."""
    if start >= len(line):
        return ""
    return line[start : min(end, len(line))].strip()


def _parse_origin_and_path(path_field: str) -> tuple[str, str]:
    """Split path field into (as_path, origin)."""
    if not path_field:
        return ("", "")
    tokens = path_field.split()
    if not tokens:
        return ("", "")
    origin = tokens[-1]
    as_path = " ".join(tokens[:-1])
    return (as_path, origin)


def _extract_status_and_path_type(prefix: str) -> tuple[str, str]:
    """Split the prefix area into (status_codes, path_type)."""
    stripped = prefix.rstrip()
    if stripped.endswith("i"):
        return (stripped[:-1].strip(), "i")
    return (stripped.strip(), "")


def _parse_data_fields(
    line: str,
    cols: _ColumnPositions,
) -> tuple[str, str, str, str]:
    """Extract (metric, locprf, weight, path) from a line using columns."""
    metric = _safe_slice(line, cols.metric, cols.locprf)
    locprf = _safe_slice(line, cols.locprf, cols.weight)

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


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a prompt/noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _is_status_legend(stripped: str) -> bool:
    """Return True if the line is part of the status/origin code legend."""
    if stripped.startswith("Status codes:"):
        return True
    if stripped.startswith("Origin codes:"):
        return True
    if stripped.startswith("RPKI validation codes:"):
        return True
    # Continuation lines of the legend (indented text with code descriptions)
    legend_tokens = ("r RIB-failure", "x best-external", "t secondary path")
    return any(stripped.startswith(t) for t in legend_tokens)


class _RouteState:
    """Mutable state for route parsing within an address family section."""

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


def _handle_route_line(
    match: re.Match[str],
    line: str,
    cols: _ColumnPositions,
    routes: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Process a route line that has next-hop data."""
    prefix = match.group("prefix")
    network = match.group("network") or ""
    nexthop = match.group("nexthop")

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


def _handle_continuation(
    match: re.Match[str],
    line: str,
    cols: _ColumnPositions,
    routes: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Process an indented continuation line (no status/network)."""
    nexthop = match.group("nexthop")
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


def _handle_wrapped_network(
    match: re.Match[str],
    state: _RouteState,
) -> None:
    """Process a wrapped network line (network only, no data)."""
    prefix = match.group("prefix")
    network = match.group("network")
    status_codes, path_type = _extract_status_and_path_type(prefix)
    state.current_network = network
    state.pending_status = status_codes
    state.pending_path_type = path_type
    state.awaiting_data = True


def _process_route_line(
    line: str,
    cols: _ColumnPositions,
    routes: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Dispatch a single route data line to the appropriate handler."""
    m = _ROUTE_RE.match(line)
    if m:
        _handle_route_line(m, line, cols, routes, state)
        return

    m = _WRAPPED_NET_RE.match(line)
    if m:
        _handle_wrapped_network(m, state)
        return

    m = _CONTINUATION_RE.match(line)
    if m:
        _handle_continuation(m, line, cols, routes, state)


class _AfSectionState:
    """Mutable state for address family section parsing."""

    __slots__ = (
        "af_entry",
        "cols",
        "current_rd",
        "rd_entries",
        "routes",
        "route_state",
        "in_data",
    )

    def __init__(self) -> None:
        self.af_entry: AddressFamilyEntry = {}
        self.cols: _ColumnPositions | None = None
        self.current_rd: str | None = None
        self.rd_entries: dict[str, RdEntry] = {}
        self.routes: dict[str, RouteEntry] = {}
        self.route_state = _RouteState()
        self.in_data: bool = False


def _handle_table_version(stripped: str, sec: _AfSectionState) -> bool:
    """Try to parse a table version line. Returns True if matched."""
    m = _TABLE_VERSION_RE.match(stripped)
    if not m:
        return False
    sec.af_entry["table_version"] = int(m.group(1))
    sec.af_entry["router_id"] = m.group(2)
    return True


def _handle_rd_line(stripped: str, sec: _AfSectionState) -> bool:
    """Try to parse a route distinguisher line. Returns True if matched."""
    m = _RD_RE.match(stripped)
    if not m:
        return False
    _finalize_rd(sec.current_rd, sec.routes, sec.rd_entries)
    sec.current_rd = m.group("rd")
    rd_entry: RdEntry = {"rd": sec.current_rd, "routes": {}}
    if m.group("vrf"):
        rd_entry["default_vrf"] = m.group("vrf")
    if m.group("vrf_rid"):
        rd_entry["vrf_router_id"] = m.group("vrf_rid")
    sec.rd_entries[sec.current_rd] = rd_entry
    sec.routes = rd_entry["routes"]
    sec.route_state = _RouteState()
    return True


def _handle_af_private_import(stripped: str, sec: _AfSectionState) -> bool:
    """Try to parse an AF-Private Import line. Returns True if matched."""
    m = _AF_PRIVATE_IMPORT_RE.match(stripped)
    if not m or not sec.current_rd or sec.current_rd not in sec.rd_entries:
        return False
    sec.rd_entries[sec.current_rd]["af_private_import_to_af"] = m.group("af")
    sec.rd_entries[sec.current_rd]["pfx_count"] = int(m.group("count"))
    sec.rd_entries[sec.current_rd]["pfx_limit"] = int(m.group("limit"))
    return True


def _should_skip_line(stripped: str) -> bool:
    """Return True if the line should be skipped (noise or legend)."""
    return _is_status_legend(stripped) or _is_noise_line(stripped)


def _process_af_line(line: str, stripped: str, sec: _AfSectionState) -> None:
    """Process a single line within an address family section."""
    if _COLUMN_HEADER_RE.match(line):
        sec.cols = _find_column_positions(line)
        sec.in_data = True
        return

    if _should_skip_line(stripped):
        return

    handled = (
        _handle_table_version(stripped, sec)
        or _handle_rd_line(stripped, sec)
        or _handle_af_private_import(stripped, sec)
    )

    if not handled and sec.in_data and sec.cols:
        _process_route_line(line, sec.cols, sec.routes, sec.route_state)


def _build_af_result(sec: _AfSectionState) -> AddressFamilyEntry:
    """Finalize and return the address family entry from accumulated state."""
    _finalize_rd(sec.current_rd, sec.routes, sec.rd_entries)

    if sec.rd_entries:
        sec.af_entry["route_distinguishers"] = sec.rd_entries
    elif sec.routes:
        sec.af_entry["routes"] = sec.routes

    return sec.af_entry


def _parse_af_section(lines: list[str], start: int) -> tuple[AddressFamilyEntry, int]:
    """Parse a single address family section starting at `start`.

    Returns the parsed entry and the index of the next line after this section.
    """
    idx = start
    total = len(lines)
    sec = _AfSectionState()

    while idx < total:
        line = lines[idx]
        stripped = line.strip()

        if _AF_HEADER_RE.match(stripped):
            break

        _process_af_line(line, stripped, sec)
        idx += 1

    return _build_af_result(sec), idx


def _finalize_rd(
    current_rd: str | None,
    routes: dict[str, RouteEntry],
    rd_entries: dict[str, RdEntry],
) -> None:
    """Store the current routes into their RD entry if applicable."""
    if current_rd and current_rd in rd_entries:
        rd_entries[current_rd]["routes"] = routes


@register(OS.CISCO_IOSXE, "show bgp all")
@register(OS.CISCO_IOSXE, "show ip bgp all")
class ShowBgpAllParser(BaseParser["ShowBgpAllResult"]):
    """Parser for 'show bgp all' command on IOS-XE.

    Example output:
        For address family: VPNv4 Unicast
        BGP table version is 5, local router ID is 10.21.33.33
             Network          Next Hop            Metric LocPrf Weight Path
        Route Distinguisher: 65535:1 (default for vrf evpn1)
         *>   10.1.1.0/24     0.0.0.0                  0         32768 ?
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpAllResult:
        """Parse 'show bgp all' output.

        Args:
            output: Raw CLI output from 'show bgp all' command.

        Returns:
            Parsed data with routes grouped by address family and RD.

        Raises:
            ValueError: If no address families are found in the output.
        """
        lines = output.splitlines()
        address_families: dict[str, AddressFamilyEntry] = {}
        idx = 0
        total = len(lines)

        while idx < total:
            line = lines[idx].strip()
            m = _AF_HEADER_RE.match(line)
            if m:
                af_name = m.group(1)
                idx += 1
                af_entry, idx = _parse_af_section(lines, idx)
                # Only include AFs that have actual data
                if _af_has_data(af_entry):
                    address_families[af_name] = af_entry
            else:
                idx += 1

        if not address_families:
            msg = "No address families with data found in output"
            raise ValueError(msg)

        return {"address_families": address_families}


def _af_has_data(af_entry: AddressFamilyEntry) -> bool:
    """Return True if the address family entry contains meaningful data."""
    if af_entry.get("route_distinguishers"):
        return True
    if af_entry.get("routes"):
        return True
    if af_entry.get("table_version") is not None:
        return True
    return False
