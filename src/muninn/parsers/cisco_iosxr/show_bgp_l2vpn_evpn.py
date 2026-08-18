"""Parser for 'show bgp l2vpn evpn' command on Cisco IOS-XR.

IOS-XR ``show bgp l2vpn evpn`` displays the L2VPN EVPN BGP table with route
entries grouped by Route Distinguisher.  Each route entry contains EVPN route
type notation (Type-1 through Type-5), next-hop, metric, local preference,
weight, AS path, and origin code.

The output begins with a header section containing BGP process information,
followed by status/origin code legends, and then the route table organized
by Route Distinguisher sections.  Routes may span multiple lines when the
network (EVPN NLRI) is long, and multiple paths for the same prefix appear
as continuation lines with status codes but no repeated network field.
"""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpL2vpnEvpnParser"]


# ---------------------------------------------------------------------------
# Origin code mapping
# ---------------------------------------------------------------------------

_ORIGIN_MAP = {
    "i": "IGP",
    "e": "EGP",
    "?": "incomplete",
}


# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class RouteEntry(TypedDict):
    """Schema for a single BGP L2VPN EVPN route path entry."""

    status_codes: str
    network: str
    next_hop: str
    label: NotRequired[str]
    metric: NotRequired[int]
    locprf: NotRequired[int]
    weight: int
    as_path: NotRequired[str]
    origin: str


class RouteDistinguisherEntry(TypedDict):
    """Schema for a Route Distinguisher section."""

    rd_version: NotRequired[int]
    default_vrf: NotRequired[str]
    routes: list[RouteEntry]


class ShowBgpL2vpnEvpnResult(TypedDict):
    """Schema for 'show bgp l2vpn evpn' parsed output on IOS-XR."""

    router_id: str
    local_as: str
    generic_scan_interval: NotRequired[int]
    nsr_enabled: NotRequired[bool]
    table_state: NotRequired[str]
    table_id: NotRequired[str]
    main_routing_table_version: int
    nsr_initial_initsync_version: NotRequired[str]
    nsr_issu_sync_group_versions: NotRequired[str]
    scan_interval: NotRequired[int]
    route_distinguishers: dict[str, RouteDistinguisherEntry]
    total_prefixes: NotRequired[int]
    total_paths: NotRequired[int]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Tue Jul  7 22:59:45.436 EDT")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# Router identifier and local AS
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")

# Generic scan interval
_GENERIC_SCAN_INTERVAL_RE = re.compile(r"^BGP generic scan interval (\d+) secs")

# Non-stop routing
_NSR_RE = re.compile(r"^Non-stop routing is (enabled|disabled)", re.I)

# Table state
_TABLE_STATE_RE = re.compile(r"^BGP table state:\s*(\S+)")

# Table ID
_TABLE_ID_RE = re.compile(r"^Table ID:\s*(\S+)")

# Main routing table version
_MAIN_RT_VERSION_RE = re.compile(r"^BGP main routing table version\s+(\d+)")

# NSR Initial initsync version
_NSR_INITSYNC_RE = re.compile(r"^BGP NSR Initial initsync version\s+(.+?)\s*$")

# NSR/ISSU Sync-Group versions
_NSR_ISSU_RE = re.compile(r"^BGP NSR/ISSU Sync-Group versions\s+(.+?)\s*$")

# BGP scan interval
_SCAN_INTERVAL_RE = re.compile(r"^BGP scan interval (\d+) secs")

# Route Distinguisher header
_RD_RE = re.compile(r"^Route Distinguisher:\s*(\S+)(?:\s+\((.+?)\))?\s*$")

# Route Distinguisher Version
_RD_VERSION_RE = re.compile(r"^Route Distinguisher Version:\s*(\d+)")

# Column header line
_COLUMN_HEADER_RE = re.compile(r"^\s*Network\s+Next\s*Hop\s+Metric")

# Status/origin code legend lines
_STATUS_CODES_RE = re.compile(r"^(?:Status codes:|Origin codes:|\s+i\s*-\s*)")

# Processed prefixes line (e.g. "Processed 39 prefixes, 45 paths")
_PROCESSED_RE = re.compile(r"^Processed\s+(\d+)\s+prefixes?,\s*(\d+)\s+paths?")

# Route line: starts with status codes (*, >, i, s, d, h, r, S, N)
# Status occupies columns 0-2, then network or spaces follow
_ROUTE_STATUS_RE = re.compile(r"^([*sdhrSN ][>* ][ieIN ])")

# EVPN network pattern (e.g. [1][...][...]/120)
_EVPN_NETWORK_RE = re.compile(r"(\[\d+\].+/\d+)")

# Label pattern after next-hop (e.g. "C:129")
_LABEL_RE = re.compile(r"^C:\d+$")

# Nexthop route policy line
_NEXTHOP_POLICY_RE = re.compile(r"^BGP table nexthop route policy:")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line should be skipped."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    if _STATUS_CODES_RE.match(stripped):
        return True
    if _COLUMN_HEADER_RE.match(stripped):
        return True
    if _NEXTHOP_POLICY_RE.match(stripped):
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _parse_vrf_from_rd_annotation(annotation: str) -> str | None:
    """Extract VRF name from RD annotation like 'default for vrf 56'."""
    m = re.search(r"default for vrf\s+(\S+)", annotation)
    if m:
        return m.group(1)
    return None


def _parse_data_fields(
    tokens: list[str],
) -> tuple[str, str | None, int | None, int | None, int, str, str]:
    """Parse the data portion of a route line into individual fields.

    Args:
        tokens: List of whitespace-separated tokens from the data portion.
                Expected order: next_hop [label] [metric] [locprf] weight
                [as_numbers...] origin

    Returns:
        Tuple of (next_hop, label, metric, locprf, weight, as_path, origin).
    """
    if not tokens:
        msg = "Empty data tokens for route entry"
        raise ValueError(msg)

    # First token is always the next-hop IP address
    next_hop = tokens[0]
    idx = 1

    # Check for optional label (C:nnn)
    label: str | None = None
    if idx < len(tokens) and _LABEL_RE.match(tokens[idx]):
        label = tokens[idx]
        idx += 1

    # Last token is always the origin code
    if idx >= len(tokens):
        msg = "Insufficient tokens for route data"
        raise ValueError(msg)

    origin_char = tokens[-1]
    origin = _ORIGIN_MAP.get(origin_char, "incomplete")

    # Remaining tokens between (next_hop/label) and origin code
    middle = tokens[idx:-1]

    # Parse middle tokens: [metric] [locprf] weight [as_path_numbers...]
    # For EVPN routes, AS path numbers appear after weight
    # Heuristic: weight is always present; metric/locprf precede it
    # We identify the split point based on count:
    #   1 token  -> weight
    #   2 tokens -> locprf, weight
    #   3 tokens -> metric, locprf, weight
    #   4+ tokens -> metric, locprf, weight, as_path...
    #              OR locprf, weight, as_path... (if no metric)
    metric: int | None = None
    locprf: int | None = None
    weight: int = 0
    as_path_parts: list[str] = []

    if len(middle) == 0:
        weight = 0
    elif len(middle) == 1:
        weight = int(middle[0])
    elif len(middle) == 2:
        locprf = int(middle[0])
        weight = int(middle[1])
    elif len(middle) == 3:
        metric = int(middle[0])
        locprf = int(middle[1])
        weight = int(middle[2])
    else:
        # 4+ tokens: first 3 are metric, locprf, weight; rest is AS path
        # But if metric is absent, first 2 are locprf, weight; rest is AS path
        # Use heuristic: if first token is very large (>= 100) and second is
        # also >= 100, likely metric+locprf; otherwise locprf+weight+as_path
        # For robustness, assume 3-field prefix (metric/locprf/weight)
        metric = int(middle[0])
        locprf = int(middle[1])
        weight = int(middle[2])
        as_path_parts = middle[3:]

    as_path = " ".join(as_path_parts)

    return (next_hop, label, metric, locprf, weight, as_path, origin)


def _is_route_line(line: str) -> bool:
    """Return True if a line starts with BGP status codes (not all spaces)."""
    if len(line) < 3:
        return False
    # A route line has at least one non-space character in the first 3 cols
    # and the first non-space char must be a valid status character
    first_char = line[0]
    return first_char in "*sdhrSN"


def _build_route_entry(
    status: str, network: str, data_tokens: list[str]
) -> RouteEntry | None:
    """Build a RouteEntry from parsed status, network, and data tokens.

    Returns None if the data cannot be parsed into a valid route entry.
    """
    try:
        next_hop, label, metric, locprf, weight, as_path, origin = _parse_data_fields(
            data_tokens
        )
    except (ValueError, IndexError):
        return None

    entry: RouteEntry = {
        "status_codes": status,
        "network": network,
        "next_hop": next_hop,
        "weight": weight,
        "origin": origin,
    }
    if as_path:
        entry["as_path"] = as_path
    if label is not None:
        entry["label"] = label
    if metric is not None:
        entry["metric"] = metric
    if locprf is not None:
        entry["locprf"] = locprf
    return entry


def _process_status_line(
    line: str,
    current_network: str | None,
) -> tuple[str, str | None, list[str] | None]:
    """Process a line that starts with BGP status codes.

    Returns:
        Tuple of (status, network_or_none, data_tokens_or_none).
    """
    status_match = _ROUTE_STATUS_RE.match(line)
    if not status_match:
        return ("", None, None)

    status = status_match.group(1).rstrip()
    after_status = line[3:]

    network_match = _EVPN_NETWORK_RE.search(after_status)
    if network_match:
        network = network_match.group(1)
        after_network = after_status[network_match.end() :].strip()
        tokens = after_network.split() if after_network else None
        return (status, network, tokens)

    # Continuation line: same network, different path
    data_tokens = after_status.strip().split()
    if data_tokens and current_network:
        return (status, None, data_tokens)
    return (status, None, None)


def _try_append_route(
    routes: list[RouteEntry],
    status: str,
    network: str,
    data_tokens: list[str],
) -> None:
    """Build a route entry and append it to routes if valid."""
    entry = _build_route_entry(status, network, data_tokens)
    if entry:
        routes.append(entry)


def _handle_evpn_continuation_line(
    line: str,
    routes: list[RouteEntry],
    current_status: str | None,
    current_network: str | None,
) -> None:
    """Handle an indented data continuation line (next-hop on separate line)."""
    if line[0] != " " or not current_network or not current_status:
        return
    data_tokens = line.strip().split()
    if data_tokens:
        _try_append_route(routes, current_status, current_network, data_tokens)


def _parse_route_lines(lines: list[str]) -> list[RouteEntry]:
    """Parse route entry lines within a Route Distinguisher section.

    Handles multi-line entries where the network wraps to the next line and
    continuation paths where the same network has multiple next-hops.
    """
    routes: list[RouteEntry] = []
    current_network: str | None = None
    current_status: str | None = None

    for line in lines:
        if not line.strip():
            continue

        if not _is_route_line(line):
            _handle_evpn_continuation_line(
                line, routes, current_status, current_network
            )
            continue

        # Route line with status codes
        status, network, data_tokens = _process_status_line(line, current_network)
        if not status:
            continue

        if network is not None:
            current_network = network
        current_status = status

        if data_tokens and current_network:
            _try_append_route(routes, current_status, current_network, data_tokens)

    return routes


def _match_router_id(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store router identifier and local AS from a match."""
    fields["router_id"] = m.group(1)
    fields["local_as"] = m.group(2)


def _match_nsr(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store NSR enabled/disabled flag from a match."""
    fields["nsr_enabled"] = m.group(1).lower() == "enabled"


# Table of (pattern, field_key, group_index, transform) for simple matches
_SIMPLE_HEADER_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_GENERIC_SCAN_INTERVAL_RE, "generic_scan_interval", 1, int),
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_TABLE_ID_RE, "table_id", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
    (_SCAN_INTERVAL_RE, "scan_interval", 1, int),
]

# Custom handlers that extract multiple fields or apply non-trivial transforms
_CUSTOM_HEADER_MATCHERS: list[
    tuple[re.Pattern[str], Callable[[re.Match[str], dict[str, object]], None]]
] = [
    (_ROUTER_ID_RE, _match_router_id),
    (_NSR_RE, _match_nsr),
]


def _try_match_header_line(stripped: str, fields: dict[str, object]) -> None:
    """Attempt to match a single header line and store results in fields."""
    for pattern, handler in _CUSTOM_HEADER_MATCHERS:
        if m := pattern.match(stripped):
            handler(m, fields)
            return

    for pattern, key, group, transform in _SIMPLE_HEADER_MATCHERS:
        if m := pattern.match(stripped):
            fields[key] = transform(m.group(group))
            return


def _parse_header(lines: list[str]) -> dict[str, object]:
    """Parse the BGP header section before route entries."""
    fields: dict[str, object] = {}

    for line in lines:
        stripped = line.strip()
        if not _is_noise_line(stripped):
            _try_match_header_line(stripped, fields)

    return fields


def _split_rd_sections(
    lines: list[str],
) -> tuple[list[str], list[tuple[str, str | None, int | None, list[str]]]]:
    """Split output into header and Route Distinguisher sections.

    Returns:
        Tuple of (header_lines, rd_sections) where each rd_section is
        (rd_value, default_vrf, rd_version, route_lines).
    """
    header_lines: list[str] = []
    rd_sections: list[tuple[str, str | None, int | None, list[str]]] = []

    current_rd: str | None = None
    current_vrf: str | None = None
    current_version: int | None = None
    current_lines: list[str] = []
    in_routes = False

    for line in lines:
        stripped = line.strip()

        rd_match = _RD_RE.match(stripped)
        if rd_match:
            # Flush previous RD section
            if current_rd is not None:
                rd_sections.append(
                    (current_rd, current_vrf, current_version, current_lines)
                )
            current_rd = rd_match.group(1)
            annotation = rd_match.group(2)
            current_vrf = (
                _parse_vrf_from_rd_annotation(annotation) if annotation else None
            )
            current_version = None
            current_lines = []
            in_routes = True
            continue

        if in_routes:
            version_match = _RD_VERSION_RE.match(stripped)
            if version_match:
                current_version = int(version_match.group(1))
                continue
            current_lines.append(line)
        else:
            header_lines.append(line)

    # Flush last RD section
    if current_rd is not None:
        rd_sections.append((current_rd, current_vrf, current_version, current_lines))

    return header_lines, rd_sections


def _extract_totals(raw_lines: list[str]) -> tuple[int | None, int | None]:
    """Extract 'Processed N prefixes, M paths' from the end of output."""
    for line in reversed(raw_lines):
        stripped = line.strip()
        if not stripped:
            continue
        m = _PROCESSED_RE.match(stripped)
        if m:
            return int(m.group(1)), int(m.group(2))
        break
    return None, None


def _build_rd_entries(
    rd_sections: list[tuple[str, str | None, int | None, list[str]]],
) -> dict[str, RouteDistinguisherEntry]:
    """Build RouteDistinguisherEntry dict keyed by RD value."""
    entries: dict[str, RouteDistinguisherEntry] = {}
    for rd_value, default_vrf, rd_version, route_lines in rd_sections:
        routes = _parse_route_lines(route_lines)
        rd_entry: RouteDistinguisherEntry = {"routes": routes}
        if rd_version is not None:
            rd_entry["rd_version"] = rd_version
        if default_vrf is not None:
            rd_entry["default_vrf"] = default_vrf
        entries[rd_value] = rd_entry
    return entries


# Keys to copy from header dict to result, with their type coercion
_OPTIONAL_HEADER_KEYS: list[tuple[str, type]] = [
    ("generic_scan_interval", int),
    ("nsr_enabled", bool),
    ("table_state", str),
    ("table_id", str),
    ("nsr_initial_initsync_version", str),
    ("nsr_issu_sync_group_versions", str),
    ("scan_interval", int),
]


def _apply_optional_fields(
    result: ShowBgpL2vpnEvpnResult,
    header: dict[str, object],
    total_prefixes: int | None,
    total_paths: int | None,
) -> None:
    """Apply optional header fields and totals to the result dict."""
    for key, coerce in _OPTIONAL_HEADER_KEYS:
        if key in header:
            result[key] = coerce(header[key])  # type: ignore[literal-required]  # ty: ignore[invalid-key]
    if total_prefixes is not None:
        result["total_prefixes"] = total_prefixes
    if total_paths is not None:
        result["total_paths"] = total_paths


@register(OS.CISCO_IOSXR, "show bgp l2vpn evpn")
class ShowBgpL2vpnEvpnParser(BaseParser["ShowBgpL2vpnEvpnResult"]):
    """Parser for 'show bgp l2vpn evpn' on Cisco IOS-XR.

    Parses the L2VPN EVPN BGP routing table including BGP process header
    information, Route Distinguisher sections, and individual route entries
    with status codes, EVPN NLRI, next-hop, metric, local preference,
    weight, AS path, and origin code.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpL2vpnEvpnResult:
        """Parse 'show bgp l2vpn evpn' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP L2VPN EVPN table information.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        raw_lines = output.splitlines()

        # Check for processed totals at end of output
        total_prefixes, total_paths = _extract_totals(raw_lines)

        # Split into header and RD sections
        header_lines, rd_sections = _split_rd_sections(raw_lines)

        # Parse header and validate required fields
        header = _parse_header(header_lines)
        router_id = header.get("router_id")
        local_as = header.get("local_as")
        if router_id is None or local_as is None:
            msg = "Missing BGP router identifier or local AS number in output"
            raise ValueError(msg)

        main_rt_version = header.get("main_routing_table_version")
        if main_rt_version is None:
            msg = "Missing BGP main routing table version in output"
            raise ValueError(msg)

        # Parse RD sections
        route_distinguishers = _build_rd_entries(rd_sections)

        # Build result with required and optional fields
        result: ShowBgpL2vpnEvpnResult = {
            "router_id": str(router_id),
            "local_as": str(local_as),
            "main_routing_table_version": int(str(main_rt_version)),
            "route_distinguishers": route_distinguishers,
        }

        _apply_optional_fields(result, header, total_prefixes, total_paths)
        return result
