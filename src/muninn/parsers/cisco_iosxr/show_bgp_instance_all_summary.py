"""Parser for 'show bgp instance all summary' command on Cisco IOS-XR.

IOS-XR ``show bgp instance all summary`` displays BGP process information
for every configured BGP instance, each containing one or more address-family
sections with a neighbor summary table.

The output is structured hierarchically:
  Instance -> Address Family -> VRF -> Neighbors

Each instance block begins with ``BGP instance N: '<name>'`` and may contain
multiple ``Address Family:`` sections.  Within each AF section, an optional
``VRF:`` header introduces per-VRF neighbor tables.
"""

import re
from collections.abc import Callable
from typing import Any, ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the summary table."""

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
    """Schema for a VRF section within an address family."""

    router_id: str
    local_as: str
    generic_scan_interval: NotRequired[int]
    nsr_enabled: NotRequired[bool]
    table_state: NotRequired[str]
    table_id: NotRequired[str]
    rd_version: NotRequired[int]
    main_routing_table_version: int
    nsr_initial_initsync_version: NotRequired[str]
    nsr_issu_sync_group_versions: NotRequired[str]
    scan_interval: NotRequired[int]
    operation_mode: NotRequired[str]
    process: NotRequired[ProcessEntry]
    neighbors: dict[str, NeighborEntry]


class AddressFamilyEntry(TypedDict):
    """Schema for an address-family section, containing one or more VRFs."""

    vrfs: dict[str, VrfEntry]


class InstanceEntry(TypedDict):
    """Schema for a single BGP instance."""

    address_families: dict[str, AddressFamilyEntry]


class ShowBgpInstanceAllSummaryResult(TypedDict):
    """Schema for 'show bgp instance all summary' parsed output on IOS-XR."""

    instances: dict[str, InstanceEntry]


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)
_INSTANCE_HEADER_RE = re.compile(r"^BGP instance \d+:\s*'(\S+)'")
_ADDRESS_FAMILY_RE = re.compile(r"^Address Family:\s*(.+?)\s*$")
_VRF_HEADER_RE = re.compile(r"^VRF:\s*(\S+)")
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")
_GENERIC_SCAN_INTERVAL_RE = re.compile(r"^BGP generic scan interval (\d+) secs")
_NSR_RE = re.compile(r"^Non-stop routing is (enabled|disabled)", re.I)
_TABLE_STATE_RE = re.compile(r"^BGP table state:\s*(\S+)")
_TABLE_ID_RE = re.compile(r"^Table ID:\s*(\S+)(?:\s+RD version:\s*(\d+))?")
_MAIN_RT_VERSION_RE = re.compile(r"^BGP main routing table version\s+(\d+)")
_NSR_INITSYNC_RE = re.compile(r"^BGP NSR Initial initsync version\s+(.+?)\s*$")
_NSR_ISSU_RE = re.compile(r"^BGP NSR/ISSU Sync-Group versions\s+(.+?)\s*$")
_SCAN_INTERVAL_RE = re.compile(r"^BGP scan interval (\d+) secs")
_OPERATION_MODE_RE = re.compile(r"^BGP is operating in (\S+) mode", re.I)
_PROCESS_HEADER_RE = re.compile(r"^Process\s+RcvTblVer")
_SPEAKER_RE = re.compile(r"^Speaker\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+Spk\s+AS\s+MsgRcvd")
_SEPARATOR_RE = re.compile(r"^=+$")

_WARNING_PREFIX = "Some configured"
_WARNING_CONTINUATION_PREFIXES = (
    "do not have",
    "address family",
    "receiving no routes",
    "Use the ",
)


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is noise (timestamp, prompt, etc.)."""
    if not stripped:
        return True
    if _TIMESTAMP_RE.match(stripped):
        return True
    if SEPARATOR_DASH_RE.match(stripped):
        return True
    if _SEPARATOR_RE.match(stripped):
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _is_warning_line(stripped: str) -> bool:
    """Return True if a line is part of the eBGP warning banner."""
    if stripped.startswith(_WARNING_PREFIX):
        return True
    return any(stripped.startswith(p) for p in _WARNING_CONTINUATION_PREFIXES)


# ---------------------------------------------------------------------------
# Header field extraction
# ---------------------------------------------------------------------------

_SIMPLE_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_GENERIC_SCAN_INTERVAL_RE, "generic_scan_interval", 1, int),
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
    (_SCAN_INTERVAL_RE, "scan_interval", 1, int),
    (_OPERATION_MODE_RE, "operation_mode", 1, str),
]

_CustomHandler = Callable[[re.Match[str], dict[str, Any]], None]


def _match_router_id(m: re.Match[str], fields: dict[str, Any]) -> None:
    fields["router_id"] = m.group(1)
    fields["local_as"] = m.group(2)


def _match_table_id(m: re.Match[str], fields: dict[str, Any]) -> None:
    fields["table_id"] = m.group(1)
    if m.group(2) is not None:
        fields["rd_version"] = int(m.group(2))


def _match_nsr(m: re.Match[str], fields: dict[str, Any]) -> None:
    fields["nsr_enabled"] = m.group(1).lower() == "enabled"


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
        m = _SPEAKER_RE.match(stripped)
        if m:
            fields["process"] = {
                "rcv_tbl_ver": int(m.group(1)),
                "brib_rib": int(m.group(2)),
                "label_ver": int(m.group(3)),
                "import_ver": int(m.group(4)),
                "send_tbl_ver": int(m.group(5)),
                "standby_ver": int(m.group(6)),
            }
        return True

    return False


# ---------------------------------------------------------------------------
# Neighbor parsing
# ---------------------------------------------------------------------------


def _complete_neighbor(
    neighbors: dict[str, NeighborEntry],
    address: str,
    tokens: list[str],
) -> None:
    """Build a NeighborEntry from tokens and add to neighbors dict."""
    min_tokens = 9
    if len(tokens) < min_tokens:
        return
    neighbors[address] = {
        "spk": int(tokens[0]),
        "remote_as": tokens[1],
        "msg_rcvd": int(tokens[2]),
        "msg_sent": int(tokens[3]),
        "tbl_ver": int(tokens[4]),
        "in_queue": int(tokens[5]),
        "out_queue": int(tokens[6]),
        "up_down": tokens[7],
        "state_pfxrcd": " ".join(tokens[8:]),
    }


def _flush_neighbor(
    neighbors: dict[str, NeighborEntry],
    addr: str | None,
    tokens: list[str],
) -> None:
    """Flush a pending neighbor entry if complete."""
    if addr and tokens:
        _complete_neighbor(neighbors, addr, tokens)


def _is_section_boundary(stripped: str) -> bool:
    """Return True if a line marks a non-neighbor section start."""
    return bool(
        _ADDRESS_FAMILY_RE.match(stripped)
        or _INSTANCE_HEADER_RE.match(stripped)
        or _VRF_HEADER_RE.match(stripped)
        or _PROCESS_HEADER_RE.match(stripped)
    )


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse neighbor table lines from a block."""
    neighbors: dict[str, NeighborEntry] = {}
    current_addr: str | None = None
    current_tokens: list[str] = []
    in_section = False

    for line in lines:
        stripped = line.strip()
        if _NEIGHBOR_HEADER_RE.match(stripped):
            in_section = True
            continue
        if not in_section:
            continue
        if _is_section_boundary(stripped):
            break
        if not stripped:
            _flush_neighbor(neighbors, current_addr, current_tokens)
            current_addr = None
            current_tokens = []
            continue

        if line[0] not in (" ", "\t"):
            _flush_neighbor(neighbors, current_addr, current_tokens)
            tokens = stripped.split()
            current_addr = tokens[0]
            current_tokens = tokens[1:]
        else:
            current_tokens.extend(stripped.split())

    _flush_neighbor(neighbors, current_addr, current_tokens)
    return neighbors


# ---------------------------------------------------------------------------
# VRF / AF block parsing
# ---------------------------------------------------------------------------

_VRF_DEFAULT = "default"

_OPTIONAL_KEYS = (
    "generic_scan_interval",
    "nsr_enabled",
    "table_state",
    "table_id",
    "rd_version",
    "nsr_initial_initsync_version",
    "nsr_issu_sync_group_versions",
    "scan_interval",
    "operation_mode",
    "process",
)


def _build_vrf_entry(
    fields: dict[str, Any],
    neighbors: dict[str, NeighborEntry],
) -> VrfEntry:
    """Construct a VrfEntry from extracted header fields and neighbors."""
    router_id = fields.get("router_id")
    local_as = fields.get("local_as")
    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number"
        raise ValueError(msg)

    main_rt_version = fields.get("main_routing_table_version")
    if main_rt_version is None:
        msg = "Missing BGP main routing table version"
        raise ValueError(msg)

    result: VrfEntry = {
        "router_id": str(router_id),
        "local_as": str(local_as),
        "main_routing_table_version": int(str(main_rt_version)),
        "neighbors": neighbors,
    }

    for key in _OPTIONAL_KEYS:
        if key in fields:
            result[key] = fields[key]  # type: ignore[literal-required]

    return result


def _extract_header_fields(lines: list[str]) -> dict[str, Any]:
    """Extract all header/metadata fields from a block of lines."""
    fields: dict[str, Any] = {}
    for line_raw in lines:
        stripped = line_raw.strip()
        if not stripped or _is_noise_line(stripped) or _is_warning_line(stripped):
            continue
        _match_header_line(stripped, fields)
    return fields


def _parse_vrf_block(lines: list[str]) -> VrfEntry:
    """Parse a block of lines belonging to a single VRF section."""
    fields = _extract_header_fields(lines)
    neighbors = _parse_neighbors(lines)
    return _build_vrf_entry(fields, neighbors)


def _split_instance_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split raw lines into per-instance sections.

    Returns a list of (instance_name, lines) tuples.
    """
    sections: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        m = _INSTANCE_HEADER_RE.match(stripped)
        if m:
            if current_name is not None:
                sections.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if current_name is not None:
        sections.append((current_name, current_lines))

    return sections


def _split_af_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split lines into address-family sections within an instance.

    Returns a list of (af_name, lines) tuples.  If no explicit
    ``Address Family:`` headers exist, treats everything as ``default``.
    """
    sections: list[tuple[str, list[str]]] = []
    current_af: str | None = None
    current_lines: list[str] = []
    has_af_header = False

    for line in lines:
        stripped = line.strip()
        m = _ADDRESS_FAMILY_RE.match(stripped)
        if m:
            has_af_header = True
            if current_af is not None:
                sections.append((current_af, current_lines))
            current_af = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if has_af_header and current_af is not None:
        sections.append((current_af, current_lines))
    elif not has_af_header:
        sections.append(("default", lines))

    return sections


def _split_vrf_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split lines into VRF sections within an address family.

    Returns a list of (vrf_name, lines) tuples.  If no explicit
    ``VRF:`` headers exist, treats everything as ``default``.
    """
    sections: list[tuple[str, list[str]]] = []
    current_vrf: str | None = None
    current_lines: list[str] = []
    has_vrf_header = False

    for line in lines:
        stripped = line.strip()
        m = _VRF_HEADER_RE.match(stripped)
        if m:
            has_vrf_header = True
            if current_vrf is not None:
                sections.append((current_vrf, current_lines))
            current_vrf = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if has_vrf_header and current_vrf is not None:
        sections.append((current_vrf, current_lines))
    elif not has_vrf_header:
        sections.append((_VRF_DEFAULT, lines))

    return sections


def _parse_instance_block(lines: list[str]) -> InstanceEntry:
    """Parse all AF/VRF sections within a single BGP instance."""
    af_sections = _split_af_sections(lines)
    address_families: dict[str, AddressFamilyEntry] = {}

    for af_name, af_lines in af_sections:
        vrf_sections = _split_vrf_sections(af_lines)
        vrfs: dict[str, VrfEntry] = {}
        for vrf_name, vrf_lines in vrf_sections:
            vrfs[vrf_name] = _parse_vrf_block(vrf_lines)
        address_families[af_name] = {"vrfs": vrfs}

    return {"address_families": address_families}


@register(OS.CISCO_IOSXR, "show bgp instance all summary")
class ShowBgpInstanceAllSummaryParser(
    BaseParser["ShowBgpInstanceAllSummaryResult"],
):
    """Parser for 'show bgp instance all summary' on Cisco IOS-XR.

    Parses BGP process information, speaker table, and neighbor summary
    across all configured BGP instances and address families.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpInstanceAllSummaryResult:
        """Parse 'show bgp instance all summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP instance summary information.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        raw_lines = output.splitlines()

        # Filter noise lines but preserve blank lines as separators
        cleaned: list[str] = []
        for line in raw_lines:
            stripped = line.strip()
            if _is_noise_line(stripped):
                if not stripped:
                    cleaned.append(line)
                continue
            cleaned.append(line)

        instance_sections = _split_instance_sections(cleaned)

        if not instance_sections:
            msg = "No BGP instance data found in output"
            raise ValueError(msg)

        instances: dict[str, InstanceEntry] = {}
        for inst_name, inst_lines in instance_sections:
            instances[inst_name] = _parse_instance_block(inst_lines)

        return cast(ShowBgpInstanceAllSummaryResult, {"instances": instances})
