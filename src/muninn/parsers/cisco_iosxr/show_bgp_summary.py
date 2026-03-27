"""Parser for 'show bgp summary' command on Cisco IOS-XR.

IOS-XR ``show bgp summary`` displays BGP process information followed by a
neighbor table.  The output may be preceded by an optional timestamp line and
may contain one or more Address Family sections within a BGP instance.

This parser produces a flat structure when no address-family sections are
present (the common ``show bgp summary`` case) or a per-address-family
structure when multiple AF blocks appear.
"""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
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


class AddressFamilyEntry(TypedDict):
    """Schema for a single address-family section."""

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


class ShowBgpSummaryResult(TypedDict):
    """Schema for 'show bgp summary' parsed output on IOS-XR."""

    address_families: dict[str, AddressFamilyEntry]


# ---------------------------------------------------------------------------
# Regex patterns as class attributes (convention: _UPPER_SNAKE)
# ---------------------------------------------------------------------------

# Timestamp line at the top of the output (e.g. "Wed Jul 27 17:18:35.642 CST")
_TIMESTAMP_RE = re.compile(
    r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d+:\d+:\d+", re.I
)

# BGP instance header: "BGP instance 0: 'default'"
_INSTANCE_HEADER_RE = re.compile(r"^BGP instance \d+:\s*'(\S+)'")

# Address Family section header: "Address Family: VPNv4 Unicast"
_ADDRESS_FAMILY_RE = re.compile(r"^Address Family:\s*(.+?)\s*$")

# Router identifier and local AS
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)")

# Generic scan interval
_GENERIC_SCAN_INTERVAL_RE = re.compile(r"^BGP generic scan interval (\d+) secs")

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

# BGP scan interval
_SCAN_INTERVAL_RE = re.compile(r"^BGP scan interval (\d+) secs")

# Operation mode
_OPERATION_MODE_RE = re.compile(r"^BGP is operating in (\S+) mode", re.I)

# Process/Speaker header line
_PROCESS_HEADER_RE = re.compile(r"^Process\s+RcvTblVer")

# Speaker data line
_SPEAKER_RE = re.compile(r"^Speaker\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)")

# Neighbor table header
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+Spk\s+AS\s+MsgRcvd")

# VRF header (for VRF-specific output)
_VRF_HEADER_RE = re.compile(r"^VRF:\s*(\S+)")

# Separator lines (dashes)
_SEPARATOR_RE = re.compile(r"^-+$")

# Warning banner lines we want to skip
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


def _complete_neighbor(
    neighbors: dict[str, NeighborEntry],
    address: str,
    tokens: list[str],
) -> None:
    """Build a NeighborEntry from collected tokens and add to neighbors dict.

    Expected token order (after address):
        Spk, AS, MsgRcvd, MsgSent, TblVer, InQ, OutQ, Up/Down, St/PfxRcd...
    """
    # Minimum 9 tokens: Spk AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down St/PfxRcd
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
    """Return True if a stripped line marks the start of a non-neighbor section."""
    return bool(
        _ADDRESS_FAMILY_RE.match(stripped)
        or _INSTANCE_HEADER_RE.match(stripped)
        or _VRF_HEADER_RE.match(stripped)
        or _PROCESS_HEADER_RE.match(stripped)
    )


def _extract_neighbor_lines(lines: list[str]) -> list[str]:
    """Extract only the raw lines belonging to the neighbor table."""
    result: list[str] = []
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
        result.append(line)
    return result


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse neighbor table lines.

    Handles IOS-XR wrapping patterns:
    - Full line: all fields on one line
    - Address wrap: long IPv6 address alone on one line, data on next line(s)
    """
    neighbors: dict[str, NeighborEntry] = {}
    current_addr: str | None = None
    current_tokens: list[str] = []

    for line in _extract_neighbor_lines(lines):
        stripped = line.strip()
        if not stripped:
            _flush_neighbor(neighbors, current_addr, current_tokens)
            current_addr = None
            current_tokens = []
            continue

        # Detect if this is a non-indented line (new neighbor) or continuation
        if line[0] not in (" ", "\t"):
            _flush_neighbor(neighbors, current_addr, current_tokens)
            tokens = stripped.split()
            current_addr = tokens[0]
            current_tokens = tokens[1:]
        else:
            current_tokens.extend(stripped.split())

    _flush_neighbor(neighbors, current_addr, current_tokens)
    return neighbors


def _match_router_id(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store router identifier and local AS from a match."""
    fields["router_id"] = m.group(1)
    fields["local_as"] = m.group(2)


def _match_table_id(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store table ID and optional RD version from a match."""
    fields["table_id"] = m.group(1)
    if m.group(2) is not None:
        fields["rd_version"] = int(m.group(2))


def _match_nsr(m: re.Match[str], fields: dict[str, object]) -> None:
    """Store NSR enabled/disabled flag from a match."""
    fields["nsr_enabled"] = m.group(1).lower() == "enabled"


# Table mapping regex patterns to (field_key, value_transform) or a custom handler.
# Each entry is (pattern, handler_or_key, group_index, transform).
# When handler_or_key is callable, it is called with (match, fields).
# Otherwise it is a field name; the captured group is optionally transformed.
_SIMPLE_MATCHERS: list[tuple[re.Pattern[str], str, int, type]] = [
    (_GENERIC_SCAN_INTERVAL_RE, "generic_scan_interval", 1, int),
    (_TABLE_STATE_RE, "table_state", 1, str),
    (_MAIN_RT_VERSION_RE, "main_routing_table_version", 1, int),
    (_NSR_INITSYNC_RE, "nsr_initial_initsync_version", 1, str),
    (_NSR_ISSU_RE, "nsr_issu_sync_group_versions", 1, str),
    (_SCAN_INTERVAL_RE, "scan_interval", 1, int),
    (_OPERATION_MODE_RE, "operation_mode", 1, str),
]

_CUSTOM_MATCHERS: list[tuple[re.Pattern[str], object]] = [
    (_ROUTER_ID_RE, _match_router_id),
    (_TABLE_ID_RE, _match_table_id),
    (_NSR_RE, _match_nsr),
]


def _match_header_line(stripped: str, fields: dict[str, object]) -> bool:
    """Try to match a single header/metadata line and store results in *fields*.

    Returns True if the line was consumed by a pattern.
    """
    for pattern, handler in _CUSTOM_MATCHERS:
        if m := pattern.match(stripped):
            handler(m, fields)
            return True

    for pattern, key, group, transform in _SIMPLE_MATCHERS:
        if m := pattern.match(stripped):
            fields[key] = transform(m.group(group))
            return True

    if _SPEAKER_RE.match(stripped):
        fields["process"] = _parse_process_line(stripped)
        return True

    return False


def _extract_header_fields(lines: list[str]) -> dict[str, object]:
    """Extract all header/metadata fields from a block of lines."""
    fields: dict[str, object] = {}
    for line_raw in lines:
        stripped = line_raw.strip()
        if not stripped or _is_noise_line(stripped) or _is_warning_line(stripped):
            continue
        _match_header_line(stripped, fields)
    return fields


def _parse_af_block(lines: list[str]) -> AddressFamilyEntry:
    """Parse a block of lines belonging to a single address-family section.

    Returns a populated AddressFamilyEntry.  Raises ValueError if the
    required router-id / local-AS line is missing.
    """
    fields = _extract_header_fields(lines)

    router_id = fields.get("router_id")
    local_as = fields.get("local_as")
    if router_id is None or local_as is None:
        msg = "Missing BGP router identifier or local AS number"
        raise ValueError(msg)

    main_rt_version = fields.get("main_routing_table_version")
    if main_rt_version is None:
        msg = "Missing BGP main routing table version"
        raise ValueError(msg)

    neighbors = _parse_neighbors(lines)

    result: AddressFamilyEntry = {
        "router_id": str(router_id),
        "local_as": str(local_as),
        "main_routing_table_version": int(str(main_rt_version)),
        "neighbors": neighbors,
    }

    # Add optional fields
    optional_keys = (
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
    for key in optional_keys:
        if key in fields:
            result[key] = fields[key]  # type — handled by TypedDict NotRequired

    return result


def _split_af_sections(
    lines: list[str],
) -> list[tuple[str, list[str]]]:
    """Split lines into address-family sections.

    Returns a list of (af_name, lines) tuples.  If no explicit
    ``Address Family:`` headers exist, the entire block is treated as
    a single section named ``default``.
    """
    # Default AF name used when there is no explicit Address Family header
    default_af_name = "default"

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
        # No AF headers found — treat everything as default
        sections.append((default_af_name, lines))

    return sections


@register(OS.CISCO_IOSXR, "show bgp summary")
class ShowBgpSummaryParser(BaseParser["ShowBgpSummaryResult"]):
    """Parser for 'show bgp summary' on Cisco IOS-XR.

    Parses BGP process information, speaker table, and neighbor summary
    table.  Supports both single-AF and multi-AF output formats, as well
    as IPv6 neighbor address wrapping.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    # Compiled regex patterns as class attributes
    _ROUTER_ID_RE = _ROUTER_ID_RE
    _NEIGHBOR_HEADER_RE = _NEIGHBOR_HEADER_RE
    _ADDRESS_FAMILY_RE = _ADDRESS_FAMILY_RE
    _INSTANCE_HEADER_RE = _INSTANCE_HEADER_RE

    @classmethod
    def parse(cls, output: str) -> ShowBgpSummaryResult:
        """Parse 'show bgp summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP summary information.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        raw_lines = output.splitlines()

        # Strip leading noise (timestamp, prompt, instance header, separators)
        cleaned: list[str] = []
        for line in raw_lines:
            stripped = line.strip()
            if _is_noise_line(stripped):
                # Keep blank lines as section separators
                if not stripped:
                    cleaned.append(line)
                continue
            if _INSTANCE_HEADER_RE.match(stripped):
                continue
            cleaned.append(line)

        af_sections = _split_af_sections(cleaned)

        if not af_sections:
            msg = "No BGP summary data found in output"
            raise ValueError(msg)

        address_families: dict[str, AddressFamilyEntry] = {}
        for af_name, section_lines in af_sections:
            af_entry = _parse_af_block(section_lines)
            address_families[af_name] = af_entry

        return cast(ShowBgpSummaryResult, {"address_families": address_families})
