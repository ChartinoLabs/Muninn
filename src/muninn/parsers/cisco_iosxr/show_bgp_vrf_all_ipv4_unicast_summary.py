"""Parser for 'show bgp vrf all ipv4 unicast summary' on Cisco IOS-XR.

IOS-XR ``show bgp vrf all ipv4 unicast summary`` displays BGP summary
information for every VRF configured on the router.  Each VRF section
includes the VRF state, route distinguisher, router identifier, local AS
number, table metadata, the speaker process row, and an optional neighbor
table.

The parser produces a dict keyed by VRF name, with each entry containing
per-VRF metadata and a nested dict of neighbors keyed by address.
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
    """Schema for a single BGP neighbor in a VRF summary table."""

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


class VrfEntry(TypedDict):
    """Schema for a single VRF section."""

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


ShowBgpVrfAllIpv4UnicastSummaryResult = dict[str, VrfEntry]

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Timestamp line (e.g. "Tue Mar 21 09:08:19.039 EDT")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# VRF header: "VRF: PROD"
_VRF_HEADER_RE = re.compile(r"^VRF:\s*(\S+)")

# Per-VRF state line: "BGP VRF PROD, state: Active"
_VRF_STATE_RE = re.compile(r"^BGP VRF \S+,\s*state:\s*(\S+)")

# Route distinguisher: "BGP Route Distinguisher: 10.1.1.1:5"
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


_SIMPLE_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_VRF_STATE_RE, "state", 1, str),
    (_ROUTE_DISTINGUISHER_RE, "route_distinguisher", 1, str),
    (_VRF_ID_RE, "vrf_id", 1, str),
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
    (_OPERATION_MODE_RE, "operation_mode", 1, str),
]

_CustomHandler = Callable[[re.Match[str], dict[str, Any]], None]

_CUSTOM_MATCHERS: list[tuple[re.Pattern[str], _CustomHandler]] = [
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


def _parse_vrf_block(lines: list[str]) -> VrfEntry:
    """Parse lines belonging to a single VRF section.

    Raises:
        ValueError: If router identifier or local AS cannot be found.
    """
    fields: dict[str, Any] = {}
    neighbors: dict[str, NeighborEntry] = {}
    in_neighbor_table = False

    for raw_line in lines:
        stripped = raw_line.strip()
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

    router_id = fields.get("router_id")
    local_as = fields.get("local_as")
    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number in VRF block"
        raise ValueError(msg)

    result: VrfEntry = {
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


@register(OS.CISCO_IOSXR, "show bgp vrf all ipv4 unicast summary")
class ShowBgpVrfAllIpv4UnicastSummaryParser(
    BaseParser["ShowBgpVrfAllIpv4UnicastSummaryResult"],
):
    """Parser for 'show bgp vrf all ipv4 unicast summary' on Cisco IOS-XR.

    Parses per-VRF BGP summary information including VRF state, route
    distinguisher, router ID, local AS, table metadata, the speaker
    process row, and neighbor table entries.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.BGP, ParserTag.ROUTING, ParserTag.VRF}
    )

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllIpv4UnicastSummaryResult:
        """Parse 'show bgp vrf all ipv4 unicast summary' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by VRF name, each containing router_id, local_as,
            optional per-VRF metadata, and a neighbors dict.

        Raises:
            ValueError: If no VRF sections are found or required fields
                are missing.
        """
        vrf_sections: list[tuple[str, list[str]]] = []
        current_vrf: str | None = None
        current_lines: list[str] = []

        for line in output.splitlines():
            stripped = line.strip()
            m = _VRF_HEADER_RE.match(stripped)
            if m:
                if current_vrf is not None:
                    vrf_sections.append((current_vrf, current_lines))
                current_vrf = m.group(1)
                current_lines = []
            else:
                current_lines.append(line)

        if current_vrf is not None:
            vrf_sections.append((current_vrf, current_lines))

        if not vrf_sections:
            msg = "No VRF sections found in output"
            raise ValueError(msg)

        result: ShowBgpVrfAllIpv4UnicastSummaryResult = {}
        for vrf_name, lines in vrf_sections:
            result[vrf_name] = _parse_vrf_block(lines)

        return result
