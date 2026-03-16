"""Parser for 'show ip bgp' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

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


class RouteDistinguisherEntry(TypedDict):
    """Schema for a Route Distinguisher group."""

    rd_vrf: NotRequired[str]
    routes: dict[str, RouteEntry]


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family."""

    table_version: int
    router_id: str
    routes: NotRequired[dict[str, RouteEntry]]
    route_distinguishers: NotRequired[dict[str, RouteDistinguisherEntry]]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    address_families: dict[str, AddressFamilyEntry]


class ShowIpBgpResult(TypedDict):
    """Schema for 'show ip bgp' parsed output on NX-OS."""

    vrfs: dict[str, VrfEntry]


# --- Section and header patterns ---
_VRF_AF_RE = re.compile(
    r"^BGP routing table information for VRF (\S+),\s*address family (.+?)\s*$"
)
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*[Ll]ocal\s+[Rr]outer\s+ID\s+is\s+(\S+)\s*$",
)
_COLUMN_HEADER_RE = re.compile(
    r"^\s*Network\s+Next\s+Hop\s+Metric\s+LocPrf\s+Weight\s+Path"
)
_RD_RE = re.compile(r"^Route Distinguisher:\s*(\S+)(?:\s+\(VRF\s+(\S+)\))?\s*$")

# Valid characters for route line detection
_STATUS_CHARS = frozenset("*sxSdh ")
_PATH_TYPE_CHARS = frozenset("ieclraI ")


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


def _split_sections(
    lines: list[str],
) -> list[tuple[str, str, list[str]]]:
    """Split output into (vrf, af, lines) sections."""
    sections: list[tuple[str, str, list[str]]] = []
    current_vrf: str | None = None
    current_af: str | None = None
    current_lines: list[str] = []

    for line in lines:
        m = _VRF_AF_RE.match(line)
        if m:
            if current_vrf is not None or current_lines:
                vrf = current_vrf or "default"
                af = current_af or "IPv4 Unicast"
                sections.append((vrf, af, current_lines))
            current_vrf = m.group(1)
            current_af = m.group(2)
            current_lines = []
        else:
            current_lines.append(line)

    # Final section
    if current_lines:
        vrf = current_vrf or "default"
        af = current_af or "IPv4 Unicast"
        sections.append((vrf, af, current_lines))

    return sections


def _find_column_positions(
    lines: list[str],
) -> tuple[int, int, int, int, int] | None:
    """Find column start positions from the header line.

    Returns (nexthop, metric, locprf, weight, path) start positions,
    or None if no header found.
    """
    for line in lines:
        if _COLUMN_HEADER_RE.match(line):
            nh = line.index("Next")
            m = line.index("Metric")
            lp = line.index("LocPrf")
            w = line.index("Weight")
            p = line.index("Path")
            return (nh, m, lp, w, p)
    return None


def _safe_slice(line: str, start: int, end: int) -> str:
    """Extract a substring from line[start:end], handling short lines."""
    if start >= len(line):
        return ""
    return line[start : min(end, len(line))].strip()


def _parse_origin_and_path(path_field: str) -> tuple[str, str]:
    """Split path field into (as_path, origin)."""
    if not path_field:
        return ("", "")
    # Origin code is the last token
    tokens = path_field.split()
    if not tokens:
        return ("", "")
    origin = tokens[-1]
    as_path = " ".join(tokens[:-1])
    return (as_path, origin)


def _is_route_line(line: str) -> bool:
    """Check if a line is a BGP route entry (starts with status chars)."""
    if len(line) < 3:
        return False
    return line[0] in _STATUS_CHARS and line[2] in _PATH_TYPE_CHARS


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


def _parse_data_fields(
    line: str,
    cols: tuple[int, int, int, int, int],
) -> tuple[str, str, str, str, str]:
    """Extract (next_hop, metric, locprf, weight, path) from a line."""
    nh_col, m_col, lp_col, w_col, p_col = cols
    next_hop = _safe_slice(line, nh_col, m_col)
    metric = _safe_slice(line, m_col, lp_col)
    locprf = _safe_slice(line, lp_col, w_col)
    weight = _safe_slice(line, w_col, p_col)
    path = line[p_col:].strip() if p_col < len(line) else ""
    return (next_hop, metric, locprf, weight, path)


def _parse_route_line(
    line: str,
    cols: tuple[int, int, int, int, int],
) -> tuple[str, str, str, PathEntry | None]:
    """Parse a route line into (status_codes, path_type, network, path_entry).

    Returns empty network for continuation routes.
    Returns None path_entry if the line only contains a wrapped network.
    """
    status_codes = line[0:2].rstrip()
    path_type = line[2] if len(line) > 2 else ""
    nh_col = cols[0]

    next_hop, metric, locprf, weight, path = _parse_data_fields(line, cols)

    # A valid next_hop must contain '.' (IPv4) or ':' (IPv6).
    # Long IPv6 prefixes can bleed past the network column, so a stray
    # character in the next_hop column doesn't count.
    has_nexthop = bool(next_hop) and ("." in next_hop or ":" in next_hop)

    # When there's no valid next_hop, this is a wrapped network line.
    # Take the full remaining text as the network prefix.
    if not has_nexthop:
        network = line[3:].strip() if len(line) > 3 else ""
        return (status_codes, path_type, network, None)

    network = line[3:nh_col].strip() if len(line) > 3 else ""
    entry = _build_path_entry(
        status_codes, path_type, next_hop, metric, locprf, weight, path
    )
    return (status_codes, path_type, network, entry)


def _parse_continuation_line(
    line: str,
    cols: tuple[int, int, int, int, int],
    status_codes: str = "",
    path_type: str = "",
) -> PathEntry | None:
    """Parse an indented continuation line (tab or space) as a path entry."""
    next_hop, metric, locprf, weight, path = _parse_data_fields(line, cols)
    if not next_hop:
        return None
    return _build_path_entry(
        status_codes, path_type, next_hop, metric, locprf, weight, path
    )


def _add_path_to_routes(
    routes: dict[str, RouteEntry],
    network: str,
    path_entry: PathEntry,
) -> None:
    """Add a path entry to the routes dict under the given network."""
    if network not in routes:
        routes[network] = {"paths": []}
    routes[network]["paths"].append(path_entry)


def _handle_rd_line(
    m: re.Match[str],
    rd_entries: dict[str, RouteDistinguisherEntry],
) -> str:
    """Process a Route Distinguisher line, return the RD key."""
    rd = m.group(1)
    rd_vrf = m.group(2)
    if rd not in rd_entries:
        entry: RouteDistinguisherEntry = {"routes": {}}
        if rd_vrf:
            entry["rd_vrf"] = rd_vrf
        rd_entries[rd] = entry
    return rd


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


def _handle_route_line(
    line: str,
    cols: tuple[int, int, int, int, int],
    target: dict[str, RouteEntry],
    state: _RouteState,
) -> None:
    """Process a single BGP route line, updating state and target."""
    status, ptype, network, path_entry = _parse_route_line(line, cols)

    if network:
        state.current_network = network
        state.pending_status = status
        state.pending_path_type = ptype
        state.awaiting_data = False

    # Wrapped line (network only, no data yet)
    if path_entry is None:
        if network and "/" in network:
            state.awaiting_data = True
        return

    # Apply pending status/path_type from wrapped network line
    if state.awaiting_data and not network:
        path_entry["status_codes"] = state.pending_status
        path_entry["path_type"] = state.pending_path_type
        state.awaiting_data = False

    if state.current_network and path_entry:
        _add_path_to_routes(target, state.current_network, path_entry)


def _parse_routes(
    lines: list[str],
    cols: tuple[int, int, int, int, int],
) -> tuple[dict[str, RouteEntry], dict[str, RouteDistinguisherEntry]]:
    """Parse all route entries from section lines.

    Returns (routes, route_distinguishers).
    """
    direct_routes: dict[str, RouteEntry] = {}
    rd_entries: dict[str, RouteDistinguisherEntry] = {}
    current_rd: str | None = None
    state = _RouteState()

    for line in lines:
        m = _RD_RE.match(line)
        if m:
            current_rd = _handle_rd_line(m, rd_entries)
            continue

        if current_rd is not None:
            target = rd_entries[current_rd]["routes"]
        else:
            target = direct_routes

        # Tab/space-indented continuation (aggregate extra paths)
        if line and line[0] in ("\t", " ") and not _is_route_line(line):
            path_entry = _parse_continuation_line(line, cols)
            if path_entry and state.current_network:
                _add_path_to_routes(target, state.current_network, path_entry)
            continue

        if _is_route_line(line):
            _handle_route_line(line, cols, target, state)

    return (direct_routes, rd_entries)


def _parse_section_header(
    lines: list[str],
) -> tuple[int, str] | None:
    """Extract table version and router ID from section lines."""
    for line in lines:
        m = _TABLE_VERSION_RE.match(line)
        if m:
            return (int(m.group(1)), m.group(2))
    return None


def _parse_section(lines: list[str]) -> AddressFamilyEntry | None:
    """Parse a single VRF/AF section."""
    header = _parse_section_header(lines)
    cols = _find_column_positions(lines)
    if header is None or cols is None:
        return None

    table_version, router_id = header
    direct_routes, rd_entries = _parse_routes(lines, cols)

    entry: AddressFamilyEntry = {
        "table_version": table_version,
        "router_id": router_id,
    }

    if rd_entries:
        entry["route_distinguishers"] = rd_entries
    if direct_routes:
        entry["routes"] = direct_routes

    return entry


@register(OS.CISCO_NXOS, "show bgp vrf all all")
@register(OS.CISCO_NXOS, "show ip bgp")
class ShowIpBgpParser(BaseParser["ShowIpBgpResult"]):
    """Parser for 'show ip bgp' on NX-OS."""

    tags: ClassVar[frozenset[str]] = frozenset({"bgp", "routing"})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpResult:
        """Parse 'show ip bgp' output."""
        raw_lines = output.splitlines()
        lines = _strip_noise(raw_lines)

        sections = _split_sections(lines)
        vrfs: dict[str, VrfEntry] = {}

        for vrf_name, af_name, section_lines in sections:
            parsed = _parse_section(section_lines)
            if parsed is None:
                continue

            if vrf_name not in vrfs:
                vrfs[vrf_name] = {"address_families": {}}
            vrfs[vrf_name]["address_families"][af_name] = parsed

        return {"vrfs": vrfs}
