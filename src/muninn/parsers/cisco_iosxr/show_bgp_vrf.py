"""Parser for 'show bgp vrf <vrf>' command on Cisco IOS-XR.

IOS-XR ``show bgp vrf <vrf>`` displays the full BGP routing table for a
specific VRF.  The output begins with a header section containing BGP process
information (router ID, local AS, NSR state, table state, routing table
version), followed by status/origin code legends, and then a route table
organized by Route Distinguisher.

Routes follow the standard BGP table format with columns for status codes,
network/prefix, next-hop (optionally with a label such as ``C:nnn``), metric,
local preference, weight, AS path, and origin code.  Multiple paths for the
same prefix appear as continuation lines with status codes but no repeated
network field.
"""

import re
from collections.abc import Callable
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpVrfParser"]


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
    """Schema for a single BGP VRF route path entry."""

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


class ShowBgpVrfResult(TypedDict):
    """Schema for 'show bgp vrf <vrf>' parsed output on IOS-XR."""

    vrf: str
    state: str
    router_id: str
    local_as: str
    nsr_enabled: NotRequired[bool]
    table_state: NotRequired[str]
    table_id: NotRequired[str]
    rd_version: NotRequired[int]
    rd: NotRequired[str]
    vrf_id: NotRequired[str]
    main_routing_table_version: int
    nsr_initial_initsync_version: NotRequired[str]
    nsr_issu_sync_group_versions: NotRequired[str]
    route_distinguishers: dict[str, RouteDistinguisherEntry]
    total_prefixes: NotRequired[int]
    total_paths: NotRequired[int]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Tue Jul  7 22:59:50.260 EDT")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# BGP VRF header line (e.g. "BGP VRF DO, state: Active")
_VRF_HEADER_RE = re.compile(r"^BGP VRF (\S+),\s*state:\s*(\S+)")

# Route Distinguisher from header (e.g. "BGP Route Distinguisher: 64512:1001")
_HEADER_RD_RE = re.compile(r"^BGP Route Distinguisher:\s*(\S+)")

# VRF ID from header (e.g. "VRF ID: 0x60000002")
_VRF_ID_RE = re.compile(r"^VRF ID:\s*(\S+)")

# Router identifier and local AS
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")

# Non-stop routing
_NSR_RE = re.compile(r"^Non-stop routing is (enabled|disabled)", re.I)

# Table state
_TABLE_STATE_RE = re.compile(r"^BGP table state:\s*(\S+)")

# Table ID and RD version on same line
_TABLE_ID_RE = re.compile(r"^Table ID:\s*(\S+)(?:\s+RD version:\s*(\d+))?")

# Main routing table version
_MAIN_RT_VERSION_RE = re.compile(r"^BGP main routing table version\s+(\d+)")

# NSR Initial initsync version
_NSR_INITSYNC_RE = re.compile(r"^BGP NSR Initial initsync version\s+(.+?)\s*$")

# NSR/ISSU Sync-Group versions
_NSR_ISSU_RE = re.compile(r"^BGP NSR/ISSU Sync-Group versions\s+(.+?)\s*$")

# Route Distinguisher header in route table section
_RD_RE = re.compile(r"^Route Distinguisher:\s*(\S+)(?:\s+\((.+?)\))?\s*$")

# Route Distinguisher Version
_RD_VERSION_RE = re.compile(r"^Route Distinguisher Version:\s*(\d+)")

# Column header line
_COLUMN_HEADER_RE = re.compile(r"^\s*Network\s+Next\s*Hop\s+Metric")

# Status/origin code legend lines
_STATUS_CODES_RE = re.compile(r"^(?:Status codes:|Origin codes:|\s+i\s*-\s*)")

# Processed prefixes line (e.g. "Processed 5 prefixes, 15 paths")
_PROCESSED_RE = re.compile(r"^Processed\s+(\d+)\s+prefixes?,\s*(\d+)\s+paths?")

# Route line: starts with status codes (*, >, i, s, d, h, r, S, N)
_ROUTE_STATUS_RE = re.compile(r"^([*sdhrSN ][>* ][ieIN ])")

# Label pattern after next-hop (e.g. "C:129")
_LABEL_RE = re.compile(r"^C:\d+$")

# Nexthop route policy line
_NEXTHOP_POLICY_RE = re.compile(r"^BGP table nexthop route policy:")

# IPv4/IPv6 network prefix (e.g. "10.0.0.0/24", "2001:db8::/32")
_NETWORK_PREFIX_RE = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}|[\da-fA-F:]+/\d{1,3})"
)


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
    """Extract VRF name from RD annotation like 'default for vrf DO'."""
    m = re.search(r"default for vrf\s+(\S+)", annotation)
    if m:
        return m.group(1)
    return None


def _split_middle_ebgp(
    middle: list[str],
) -> tuple[int | None, int | None, int, list[str]]:
    """Split middle tokens for eBGP/local routes (no locprf column)."""
    if len(middle) == 0:
        return (None, None, 0, [])
    if len(middle) == 1:
        return (None, None, int(middle[0]), [])
    if len(middle) == 2:
        return (int(middle[0]), None, int(middle[1]), [])
    # 3+: metric, weight, as_path...
    return (int(middle[0]), None, int(middle[1]), middle[2:])


def _split_middle_ibgp(
    middle: list[str],
) -> tuple[int | None, int | None, int, list[str]]:
    """Split middle tokens for iBGP routes (locprf column present)."""
    if len(middle) == 0:
        return (None, None, 0, [])
    if len(middle) == 1:
        return (None, None, int(middle[0]), [])
    if len(middle) == 2:
        return (None, int(middle[0]), int(middle[1]), [])
    if len(middle) == 3:
        return (int(middle[0]), int(middle[1]), int(middle[2]), [])
    # 4+ tokens: metric, locprf, weight, as_path...
    return (int(middle[0]), int(middle[1]), int(middle[2]), middle[3:])


def _parse_data_fields(
    tokens: list[str],
    has_locprf: bool = True,
) -> tuple[str, str | None, int | None, int | None, int, str, str]:
    """Parse the data portion of a route line into individual fields.

    Args:
        tokens: List of whitespace-separated tokens from the data portion.
                Expected order: next_hop [label] [metric] [locprf] weight
                [as_numbers...] origin
        has_locprf: Whether local preference is expected in this route.
                    iBGP routes (status contains 'i') include locprf;
                    eBGP/locally-originated routes typically do not.

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

    # Parse middle tokens based on whether locprf is expected.
    # iBGP routes (has_locprf=True): metric, locprf, weight, [as_path...]
    # eBGP/local routes (has_locprf=False): metric, weight, [as_path...]
    if has_locprf:
        metric, locprf, weight, as_path_parts = _split_middle_ibgp(middle)
    else:
        metric, locprf, weight, as_path_parts = _split_middle_ebgp(middle)

    as_path = " ".join(as_path_parts)

    return (next_hop, label, metric, locprf, weight, as_path, origin)


def _is_route_line(line: str) -> bool:
    """Return True if a line starts with BGP status codes (not all spaces)."""
    if len(line) < 3:
        return False
    first_char = line[0]
    return first_char in "*sdhrSN"


def _build_route_entry(
    status: str, network: str, data_tokens: list[str]
) -> RouteEntry | None:
    """Build a RouteEntry from parsed status, network, and data tokens.

    Returns None if the data cannot be parsed into a valid route entry.
    """
    # Determine if locprf is expected: 'i' in status indicates iBGP
    has_locprf = "i" in status
    try:
        next_hop, label, metric, locprf, weight, as_path, origin = _parse_data_fields(
            data_tokens, has_locprf=has_locprf
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

    # Check for a network prefix after status codes
    network_match = _NETWORK_PREFIX_RE.match(after_status.strip())
    if network_match:
        network = network_match.group(1)
        # Find the position after the network prefix in after_status
        after_network = after_status.strip()[network_match.end() :].strip()
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


def _should_skip_route_line(stripped: str) -> bool:
    """Return True if a stripped line inside a route section should be skipped."""
    if not stripped:
        return True
    if _is_noise_line(stripped):
        return True
    return bool(_PROCESSED_RE.match(stripped))


def _handle_continuation_line(
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

    Handles continuation paths where the same network has multiple next-hops.
    """
    routes: list[RouteEntry] = []
    current_network: str | None = None
    current_status: str | None = None

    for line in lines:
        if _should_skip_route_line(line.strip()):
            continue

        if not _is_route_line(line):
            _handle_continuation_line(line, routes, current_status, current_network)
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


def _match_vrf_header(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store VRF name and state from header."""
    fields["vrf"] = m.group(1)
    fields["state"] = m.group(2)


def _match_header_rd(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store Route Distinguisher from header."""
    fields["rd"] = m.group(1)


def _match_vrf_id(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store VRF ID from header."""
    fields["vrf_id"] = m.group(1)


def _match_table_id(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store Table ID and optional RD version from header."""
    fields["table_id"] = m.group(1)
    if m.group(2) is not None:
        fields["rd_version"] = int(m.group(2))


# Table of (pattern, field_key, group_index, transform) for simple matches
_SIMPLE_HEADER_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
]

# Custom handlers that extract multiple fields or apply non-trivial transforms
_CUSTOM_HEADER_MATCHERS: list[
    tuple[re.Pattern[str], Callable[[re.Match[str], dict[str, object]], None]]
] = [
    (_ROUTER_ID_RE, _match_router_id),
    (_NSR_RE, _match_nsr),
    (_VRF_HEADER_RE, _match_vrf_header),
    (_HEADER_RD_RE, _match_header_rd),
    (_VRF_ID_RE, _match_vrf_id),
    (_TABLE_ID_RE, _match_table_id),
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
    ("nsr_enabled", bool),
    ("table_state", str),
    ("table_id", str),
    ("rd_version", int),
    ("rd", str),
    ("vrf_id", str),
    ("nsr_initial_initsync_version", str),
    ("nsr_issu_sync_group_versions", str),
]


def _apply_optional_fields(
    result: ShowBgpVrfResult,
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


@register(OS.CISCO_IOSXR, r"show bgp vrf (?P<vrf>\S+)")
class ShowBgpVrfParser(BaseParser["ShowBgpVrfResult"]):
    """Parser for 'show bgp vrf <vrf>' on Cisco IOS-XR.

    Parses the full BGP routing table for a specific VRF including BGP process
    header information, Route Distinguisher sections, and individual route
    entries with status codes, network/prefix, next-hop, metric, local
    preference, weight, AS path, and origin code.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.BGP, ParserTag.ROUTING, ParserTag.VRF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfResult:
        """Parse 'show bgp vrf <vrf>' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP VRF table information.

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

        vrf = header.get("vrf")
        if vrf is None:
            msg = "Missing VRF name in BGP VRF header"
            raise ValueError(msg)

        # Parse RD sections
        route_distinguishers = _build_rd_entries(rd_sections)

        state = header.get("state")
        if state is None:
            msg = "Missing VRF state in BGP VRF header"
            raise ValueError(msg)

        # Build result with required and optional fields
        result: ShowBgpVrfResult = {
            "vrf": str(vrf),
            "state": str(state),
            "router_id": str(router_id),
            "local_as": str(local_as),
            "main_routing_table_version": int(str(main_rt_version)),
            "route_distinguishers": route_distinguishers,
        }

        _apply_optional_fields(result, header, total_prefixes, total_paths)
        return result
