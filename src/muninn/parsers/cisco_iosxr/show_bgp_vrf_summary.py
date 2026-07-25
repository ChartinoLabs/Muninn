"""Parser for 'show bgp vrf <vrf> summary' commands on Cisco IOS-XR.

IOS-XR ``show bgp vrf <vrf> summary`` (and the address-family-specific
variants ``show bgp vrf <vrf> ipv4 unicast summary`` and
``show bgp vrf <vrf> ipv6 unicast summary``) display BGP summary
information for a single named VRF.  The output includes VRF state,
route distinguisher, router identifier, local AS number, table metadata,
the speaker process row, and an optional neighbor table.

The output format is identical across all three command variants.

The per-VRF output structure mirrors the sibling parser
``show_bgp_vrf_all_ipv4_unicast_summary``; parsing logic follows
the same pattern (regex matchers, speaker/neighbor table extraction).
"""

import re
from collections.abc import Callable
from typing import Any, ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the VRF summary table."""

    spk: int
    remote_as: str
    msg_rcvd: int
    msg_sent: int
    tbl_ver: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfxrcd: str


class ProcessEntry(TypedDict):
    """Schema for a BGP speaker process row."""

    rcv_tbl_ver: int
    brib_rib: int
    label_ver: int
    import_ver: int
    send_tbl_ver: int
    standby_ver: int


class ShowBgpVrfSummaryResult(TypedDict):
    """Schema for 'show bgp vrf <vrf> summary' parsed output on IOS-XR."""

    vrf: str
    router_id: str
    local_as: str
    state: NotRequired[str]
    route_distinguisher: NotRequired[str]
    vrf_id: NotRequired[str]
    nsr_enabled: NotRequired[bool]
    table_state: NotRequired[str]
    table_id: NotRequired[str]
    rd_version: NotRequired[int]
    main_routing_table_version: NotRequired[int]
    nsr_initial_initsync_version: NotRequired[str]
    nsr_issu_sync_group_versions: NotRequired[str]
    operation_mode: NotRequired[str]
    process: NotRequired[ProcessEntry]
    neighbors: dict[str, NeighborEntry]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Tue Jul  7 22:59:47.881 EDT")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# Per-VRF state line: "BGP VRF CUSTOMER_A, state: Active"
_VRF_STATE_RE = re.compile(r"^BGP VRF (\S+),\s*state:\s*(\S+)")

# Route distinguisher: "BGP Route Distinguisher: 64512:1001"
_ROUTE_DISTINGUISHER_RE = re.compile(r"^BGP Route Distinguisher:\s*(\S+)")

# VRF ID: "VRF ID: 0x60000002"
_VRF_ID_RE = re.compile(r"^VRF ID:\s*(\S+)")

# Router identifier and local AS
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")

# Non-stop routing
_NSR_RE = re.compile(r"^Non-stop routing is (enabled|disabled)", re.I)

# Table state
_TABLE_STATE_RE = re.compile(r"^BGP table state:\s*(\S+)")

# Table ID and optional RD version
_TABLE_ID_RE = re.compile(r"^Table ID:\s*(\S+)(?:\s+RD version:\s*(\d+))?")

# Main routing table version
_MAIN_RT_VERSION_RE = re.compile(r"^BGP main routing table version\s+(\d+)")

# NSR Initial initsync version
_NSR_INITSYNC_RE = re.compile(r"^BGP NSR Initial initsync version\s+(.+?)\s*$")

# NSR/ISSU Sync-Group versions
_NSR_ISSU_RE = re.compile(r"^BGP NSR/ISSU Sync-Group versions\s+(.+?)\s*$")

# Operation mode
_OPERATION_MODE_RE = re.compile(r"^BGP is operating in (\S+) mode", re.I)

# Process/Speaker header line
_PROCESS_HEADER_RE = re.compile(r"^Process\s+RcvTblVer")

# Speaker data line
_SPEAKER_RE = re.compile(r"^Speaker\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")

# Neighbor table header line
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+Spk\s+AS\s+MsgRcvd")

# Error line for unconfigured address family
_AF_NOT_CONFIGURED_RE = re.compile(
    r"^%\s*None of the requested address families are configured"
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if the line is noise (timestamp, separator, prompt)."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if SEPARATOR_DASH_RE.match(stripped):
        return True
    return stripped.endswith("#") or "#show " in stripped.lower()


def _parse_neighbor_line(
    line: str,
    neighbors: dict[str, NeighborEntry],
) -> None:
    """Parse a single neighbor data line and add to the neighbors dict."""
    tokens = line.split()
    min_tokens = 10
    if len(tokens) < min_tokens:
        return
    address = tokens[0]
    neighbors[address] = {
        "spk": int(tokens[1]),
        "remote_as": tokens[2],
        "msg_rcvd": int(tokens[3]),
        "msg_sent": int(tokens[4]),
        "tbl_ver": int(tokens[5]),
        "in_queue": int(tokens[6]),
        "out_queue": int(tokens[7]),
        "up_down": tokens[8],
        "state_pfxrcd": " ".join(tokens[9:]),
    }


def _parse_process_line(line: str) -> ProcessEntry | None:
    """Parse a Speaker process data line."""
    m = _SPEAKER_RE.match(line)
    if not m:
        return None
    return {
        "rcv_tbl_ver": int(m.group(1)),
        "brib_rib": int(m.group(2)),
        "label_ver": int(m.group(3)),
        "import_ver": int(m.group(4)),
        "send_tbl_ver": int(m.group(5)),
        "standby_ver": int(m.group(6)),
    }


def _match_router_id(m: re.Match[str], fields: dict[str, Any]) -> None:
    """Store router identifier and local AS from a match."""
    fields["router_id"] = m.group(1)
    fields["local_as"] = m.group(2)


def _match_table_id(m: re.Match[str], fields: dict[str, Any]) -> None:
    """Store table ID and optional RD version from a match."""
    fields["table_id"] = m.group(1)
    if m.group(2) is not None:
        fields["rd_version"] = int(m.group(2))


def _match_nsr(m: re.Match[str], fields: dict[str, Any]) -> None:
    """Store NSR enabled/disabled flag from a match."""
    fields["nsr_enabled"] = m.group(1).lower() == "enabled"


def _match_vrf_state(m: re.Match[str], fields: dict[str, Any]) -> None:
    """Store VRF name and state from a match."""
    fields["vrf"] = m.group(1)
    fields["state"] = m.group(2)


_CustomHandler = Callable[[re.Match[str], dict[str, Any]], None]

_SIMPLE_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_ROUTE_DISTINGUISHER_RE, "route_distinguisher", 1, str),
    (_VRF_ID_RE, "vrf_id", 1, str),
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
    (_OPERATION_MODE_RE, "operation_mode", 1, str),
]

_CUSTOM_MATCHERS: list[tuple[re.Pattern[str], _CustomHandler]] = [
    (_VRF_STATE_RE, _match_vrf_state),
    (_ROUTER_ID_RE, _match_router_id),
    (_TABLE_ID_RE, _match_table_id),
    (_NSR_RE, _match_nsr),
]


def _match_header_line(stripped: str, fields: dict[str, Any]) -> bool:
    """Try to match a header/metadata line and store results in *fields*."""
    for pattern, handler in _CUSTOM_MATCHERS:
        if m := pattern.match(stripped):
            handler(m, fields)
            return True

    for pattern, key, group, transform in _SIMPLE_MATCHERS:
        if m := pattern.match(stripped):
            fields[key] = transform(m.group(group))
            return True

    if _SPEAKER_RE.match(stripped):
        process = _parse_process_line(stripped)
        if process is not None:
            fields["process"] = process
        return True

    return False


def _parse_vrf_output(
    output: str,
) -> tuple[dict[str, Any], dict[str, NeighborEntry]]:
    """Parse all lines from a single-VRF BGP summary output.

    Returns:
        Tuple of (header fields dict, neighbors dict).

    Raises:
        ValueError: If the output contains an address-family-not-configured
            error message.
    """
    fields: dict[str, Any] = {}
    neighbors: dict[str, NeighborEntry] = {}
    in_neighbor_table = False

    for raw_line in output.splitlines():
        stripped = raw_line.strip()

        if _AF_NOT_CONFIGURED_RE.match(stripped):
            msg = "Address family not configured for this VRF"
            raise ValueError(msg)

        if _is_noise_line(stripped):
            continue

        if _NEIGHBOR_HEADER_RE.match(stripped):
            in_neighbor_table = True
            continue

        if in_neighbor_table:
            _parse_neighbor_line(stripped, neighbors)
            continue

        if _PROCESS_HEADER_RE.match(stripped):
            continue

        _match_header_line(stripped, fields)

    return fields, neighbors


def _build_result(
    fields: dict[str, Any],
    neighbors: dict[str, NeighborEntry],
) -> ShowBgpVrfSummaryResult:
    """Build the typed result dict from parsed fields and neighbors.

    Raises:
        ValueError: If required fields (router_id, local_as, vrf) are missing.
    """
    router_id = fields.get("router_id")
    local_as = fields.get("local_as")
    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number"
        raise ValueError(msg)

    vrf_name = fields.get("vrf")
    if vrf_name is None:
        msg = "Missing VRF name in output (expected 'BGP VRF <name>, state:' line)"
        raise ValueError(msg)

    result: ShowBgpVrfSummaryResult = {
        "vrf": str(vrf_name),
        "router_id": str(router_id),
        "local_as": str(local_as),
        "neighbors": neighbors,
    }

    optional_keys = (
        "state",
        "route_distinguisher",
        "vrf_id",
        "nsr_enabled",
        "table_state",
        "table_id",
        "rd_version",
        "main_routing_table_version",
        "nsr_initial_initsync_version",
        "nsr_issu_sync_group_versions",
        "operation_mode",
        "process",
    )
    for key in optional_keys:
        if key in fields:
            result[key] = fields[key]

    return result


@register(OS.CISCO_IOSXR, r"show bgp vrf (?P<vrf>\S+) summary")
@register(OS.CISCO_IOSXR, r"show bgp vrf (?P<vrf>\S+) ipv4 unicast summary")
@register(OS.CISCO_IOSXR, r"show bgp vrf (?P<vrf>\S+) ipv6 unicast summary")
class ShowBgpVrfSummaryParser(BaseParser["ShowBgpVrfSummaryResult"]):
    """Parser for 'show bgp vrf <vrf> [ipv4|ipv6 unicast] summary' on IOS-XR.

    Parses single-VRF BGP summary information including VRF state, route
    distinguisher, router ID, local AS, table metadata, the speaker
    process row, and neighbor table entries.

    Handles all three command variants:
    - show bgp vrf <vrf> summary
    - show bgp vrf <vrf> ipv4 unicast summary
    - show bgp vrf <vrf> ipv6 unicast summary
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.BGP, ParserTag.ROUTING, ParserTag.VRF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfSummaryResult:
        """Parse 'show bgp vrf <vrf> summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict containing vrf name, router_id, local_as,
            optional per-VRF metadata, and a neighbors dict.

        Raises:
            ValueError: If required fields are missing or address family
                is not configured.
        """
        fields, neighbors = _parse_vrf_output(output)
        return _build_result(fields, neighbors)
