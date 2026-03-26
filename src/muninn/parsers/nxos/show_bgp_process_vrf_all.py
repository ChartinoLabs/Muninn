"""Parser for 'show bgp process vrf all' command on NX-OS."""

from __future__ import annotations

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class AttributesInfo(TypedDict):
    """Schema for BGP attribute statistics."""

    num_attribute_entries: int
    hwm_attribute_entries: int
    bytes_used: int
    entries_pending_delete: int
    hwm_entries_pending_delete: int
    paths_per_attribute_hwm: int
    as_path_entries: int
    bytes_used_by_as_path_entries: int


class AddressFamilyCounters(TypedDict):
    """Schema for the per-AF peers/routes/paths/networks/aggregates table."""

    peers: int
    active_peers: int
    routes: int
    paths: int
    networks: int
    aggregates: int


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family within a VRF."""

    table_id: str
    table_state: str
    counters: AddressFamilyCounters
    redistribution: NotRequired[list[str]]
    export_rt_list: NotRequired[list[str]]
    import_rt_list: NotRequired[list[str]]
    evpn_export_rt_list: NotRequired[list[str]]
    evpn_import_rt_list: NotRequired[list[str]]
    label_mode: NotRequired[str]
    aggregate_label: NotRequired[int]
    is_route_reflector: NotRequired[bool]
    retain_rt: NotRequired[str]
    import_default_limit: NotRequired[int]
    import_default_prefix_count: NotRequired[int]
    import_default_map: NotRequired[str]
    export_default_limit: NotRequired[int]
    export_default_prefix_count: NotRequired[int]
    export_default_map: NotRequired[str]
    import_route_map: NotRequired[str]
    export_route_map: NotRequired[str]
    advertise_to_evpn: NotRequired[bool]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    vrf_id: int
    vrf_state: str
    router_id: str
    configured_router_id: str
    confed_id: int
    cluster_id: str
    configured_peers: int
    pending_config_peers: int
    established_peers: int
    vrf_rd: str
    vrf_evpn_rd: NotRequired[str]
    address_families: dict[str, AddressFamilyEntry]


class ProcessInfo(TypedDict):
    """Schema for the top-level BGP process information."""

    process_id: int
    protocol_started_reason: str
    protocol_tag: int
    protocol_state: str
    isolate_mode: bool
    mmode: str
    memory_state: str
    as_format: str
    performance_mode: NotRequired[bool]
    segment_routing_global_block: NotRequired[str]


class ShowBgpProcessVrfAllResult(TypedDict):
    """Schema for 'show bgp process vrf all' parsed output on NX-OS."""

    process: ProcessInfo
    attributes: AttributesInfo
    vrfs: dict[str, VrfEntry]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Process information patterns
_PROCESS_ID_RE = re.compile(r"^BGP Process ID\s+:\s+(\d+)\s*$")
_PROTOCOL_STARTED_RE = re.compile(r"^BGP Protocol Started, reason:\s+:\s+(.+?)\s*$")
_PROTOCOL_TAG_RE = re.compile(r"^BGP Protocol Tag\s+:\s+(\d+)\s*$")
_PROTOCOL_STATE_RE = re.compile(r"^BGP Protocol State\s+:\s+(.+?)\s*$")
_ISOLATE_MODE_RE = re.compile(r"^BGP Isolate Mode\s+:\s+(\S+)\s*$")
_MMODE_RE = re.compile(r"^BGP MMODE\s+:\s+(.+?)\s*$")
_MEMORY_STATE_RE = re.compile(r"^BGP Memory State\s+:\s+(\S+)\s*$")
_AS_FORMAT_RE = re.compile(r"^BGP asformat\s+:\s+(\S+)\s*$")
_PERFORMANCE_MODE_RE = re.compile(r"^BGP Performance Mode:\s+:\s+(\S+)\s*$")
_SR_GLOBAL_BLOCK_RE = re.compile(r"^Segment Routing Global Block\s+:\s+(.+?)\s*$")

# Attribute information patterns
_NUM_ATTR_ENTRIES_RE = re.compile(r"^Number of attribute entries\s+:\s+(\d+)\s*$")
_HWM_ATTR_ENTRIES_RE = re.compile(r"^HWM of attribute entries\s+:\s+(\d+)\s*$")
_BYTES_USED_RE = re.compile(r"^Bytes used by entries\s+:\s+(\d+)\s*$")
_ENTRIES_PENDING_DELETE_RE = re.compile(r"^Entries pending delete\s+:\s+(\d+)\s*$")
_HWM_PENDING_DELETE_RE = re.compile(r"^HWM of entries pending delete\s+:\s+(\d+)\s*$")
_PATHS_PER_ATTR_HWM_RE = re.compile(r"^BGP paths per attribute HWM\s+:\s+(\d+)\s*$")
_AS_PATH_ENTRIES_RE = re.compile(r"^BGP AS path entries\s+:\s+(\d+)\s*$")
_BYTES_AS_PATH_RE = re.compile(r"^Bytes used by AS path entries\s+:\s+(\d+)\s*$")

# VRF header and field patterns
_VRF_HEADER_RE = re.compile(r"^BGP Information for VRF (\S+)\s*$")
_VRF_ID_RE = re.compile(r"^VRF Id\s+:\s+(\d+)\s*$")
_VRF_STATE_RE = re.compile(r"^VRF state\s+:\s+(\S+)\s*$")
_ROUTER_ID_RE = re.compile(r"^Router-ID\s+:\s+(\S+)\s*$")
_CONFIGURED_ROUTER_ID_RE = re.compile(r"^Configured Router-ID\s+:\s+(\S+)\s*$")
_CONFED_ID_RE = re.compile(r"^Confed-ID\s+:\s+(\d+)\s*$")
_CLUSTER_ID_RE = re.compile(r"^Cluster-ID\s+:\s+(\S+)\s*$")
_CONFIGURED_PEERS_RE = re.compile(r"^No\. of configured peers\s+:\s+(\d+)\s*$")
_PENDING_CONFIG_PEERS_RE = re.compile(r"^No\. of pending config peers\s+:\s+(\d+)\s*$")
_ESTABLISHED_PEERS_RE = re.compile(r"^No\. of established peers\s+:\s+(\d+)\s*$")
_VRF_RD_RE = re.compile(r"^VRF RD\s+:\s+(.+?)\s*$")
_VRF_EVPN_RD_RE = re.compile(r"^VRF EVPN RD\s+:\s+(.+?)\s*$")

# Address family patterns
_AF_HEADER_RE = re.compile(r"^\s+Information for address family (.+?) in VRF (\S+)\s*$")
_TABLE_ID_RE = re.compile(r"^\s+Table Id\s+:\s+(\S+)\s*$")
_TABLE_STATE_RE = re.compile(r"^\s+Table state\s+:\s+(\S+)\s*$")
_AF_COUNTERS_HEADER_RE = re.compile(
    r"^\s+Peers\s+Active-peers\s+Routes\s+Paths\s+Networks\s+Aggregates\s*$"
)
_AF_COUNTERS_RE = re.compile(r"^\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")

# AF detail patterns
_LABEL_MODE_RE = re.compile(r"^\s+Label mode:\s+(.+?)\s*$")
_AGGREGATE_LABEL_RE = re.compile(r"^\s+Aggregate label:\s+(\d+)\s*$")
_IS_ROUTE_REFLECTOR_RE = re.compile(r"^\s+Is a Route-reflector\s*$")
_RETAIN_RT_RE = re.compile(r"^\s+Retain RT:\s+(.+?)\s*$")
_IMPORT_DEFAULT_LIMIT_RE = re.compile(r"^\s+Import default limit\s+:\s+(\d+)\s*$")
_IMPORT_DEFAULT_PREFIX_COUNT_RE = re.compile(
    r"^\s+Import default prefix count\s+:\s+(\d+)\s*$"
)
_IMPORT_DEFAULT_MAP_RE = re.compile(r"^\s+Import default map\s+:\s+(\S+)\s*$")
_EXPORT_DEFAULT_LIMIT_RE = re.compile(r"^\s+Export default limit\s+:\s+(\d+)\s*$")
_EXPORT_DEFAULT_PREFIX_COUNT_RE = re.compile(
    r"^\s+Export default prefix count\s+:\s+(\d+)\s*$"
)
_EXPORT_DEFAULT_MAP_RE = re.compile(r"^\s+Export default map\s+:\s+(\S+)\s*$")
_IMPORT_ROUTE_MAP_RE = re.compile(r"^\s+Import route-map\s+(\S+)\s*$")
_EXPORT_ROUTE_MAP_RE = re.compile(r"^\s+Export route-map\s+(\S+)\s*$")
_ADVERTISE_TO_EVPN_RE = re.compile(r"^\s+Advertise to EVPN\s*$")

# RT list header patterns
_EXPORT_RT_LIST_RE = re.compile(r"^\s+Export RT list:\s*(.+)?\s*$")
_IMPORT_RT_LIST_RE = re.compile(r"^\s+Import RT list:\s*(.+)?\s*$")
_EVPN_EXPORT_RT_LIST_RE = re.compile(r"^\s+EVPN Export RT list:\s*(.+)?\s*$")
_EVPN_IMPORT_RT_LIST_RE = re.compile(r"^\s+EVPN Import RT list:\s*(.+)?\s*$")

# Redistribution
_REDISTRIBUTION_HEADER_RE = re.compile(r"^\s+Redistribution\s*$")
_REDISTRIBUTION_ENTRY_RE = re.compile(r"^\t(.+?)\s*$")

# Process info dispatch table: (pattern, key, converter)
_PROCESS_DISPATCH: list[tuple[re.Pattern[str], str, type]] = [
    (_PROCESS_ID_RE, "process_id", int),
    (_PROTOCOL_STARTED_RE, "protocol_started_reason", str),
    (_PROTOCOL_TAG_RE, "protocol_tag", int),
    (_PROTOCOL_STATE_RE, "protocol_state", str),
    (_MMODE_RE, "mmode", str),
    (_MEMORY_STATE_RE, "memory_state", str),
    (_AS_FORMAT_RE, "as_format", str),
]

# Attribute info dispatch table: (pattern, key)
_ATTR_DISPATCH: list[tuple[re.Pattern[str], str]] = [
    (_NUM_ATTR_ENTRIES_RE, "num_attribute_entries"),
    (_HWM_ATTR_ENTRIES_RE, "hwm_attribute_entries"),
    (_BYTES_USED_RE, "bytes_used"),
    (_ENTRIES_PENDING_DELETE_RE, "entries_pending_delete"),
    (_HWM_PENDING_DELETE_RE, "hwm_entries_pending_delete"),
    (_PATHS_PER_ATTR_HWM_RE, "paths_per_attribute_hwm"),
    (_AS_PATH_ENTRIES_RE, "as_path_entries"),
    (_BYTES_AS_PATH_RE, "bytes_used_by_as_path_entries"),
]

# VRF field dispatch: (pattern, key, converter)
_VRF_FIELD_DISPATCH: list[tuple[re.Pattern[str], str, type]] = [
    (_VRF_ID_RE, "vrf_id", int),
    (_VRF_STATE_RE, "vrf_state", str),
    (_ROUTER_ID_RE, "router_id", str),
    (_CONFIGURED_ROUTER_ID_RE, "configured_router_id", str),
    (_CONFED_ID_RE, "confed_id", int),
    (_CLUSTER_ID_RE, "cluster_id", str),
    (_CONFIGURED_PEERS_RE, "configured_peers", int),
    (_PENDING_CONFIG_PEERS_RE, "pending_config_peers", int),
    (_ESTABLISHED_PEERS_RE, "established_peers", int),
    (_VRF_RD_RE, "vrf_rd", str),
    (_VRF_EVPN_RD_RE, "vrf_evpn_rd", str),
]

# AF detail dispatch tables
_AF_DETAIL_STR_DISPATCH: list[tuple[re.Pattern[str], str]] = [
    (_LABEL_MODE_RE, "label_mode"),
    (_RETAIN_RT_RE, "retain_rt"),
    (_IMPORT_DEFAULT_MAP_RE, "import_default_map"),
    (_EXPORT_DEFAULT_MAP_RE, "export_default_map"),
    (_IMPORT_ROUTE_MAP_RE, "import_route_map"),
    (_EXPORT_ROUTE_MAP_RE, "export_route_map"),
]

_AF_DETAIL_INT_DISPATCH: list[tuple[re.Pattern[str], str]] = [
    (_AGGREGATE_LABEL_RE, "aggregate_label"),
    (_IMPORT_DEFAULT_LIMIT_RE, "import_default_limit"),
    (_IMPORT_DEFAULT_PREFIX_COUNT_RE, "import_default_prefix_count"),
    (_EXPORT_DEFAULT_LIMIT_RE, "export_default_limit"),
    (_EXPORT_DEFAULT_PREFIX_COUNT_RE, "export_default_prefix_count"),
]

_AF_DETAIL_BOOL_DISPATCH: list[tuple[re.Pattern[str], str]] = [
    (_IS_ROUTE_REFLECTOR_RE, "is_route_reflector"),
    (_ADVERTISE_TO_EVPN_RE, "advertise_to_evpn"),
]

# RT list dispatch: (pattern, key)
_RT_LIST_DISPATCH: list[tuple[re.Pattern[str], str]] = [
    (_EXPORT_RT_LIST_RE, "export_rt_list"),
    (_IMPORT_RT_LIST_RE, "import_rt_list"),
    (_EVPN_EXPORT_RT_LIST_RE, "evpn_export_rt_list"),
    (_EVPN_IMPORT_RT_LIST_RE, "evpn_import_rt_list"),
]


# ---------------------------------------------------------------------------
# Helper parsers
# ---------------------------------------------------------------------------


def _try_dispatch(
    stripped: str,
    dispatch: list[tuple[re.Pattern[str], str, type]],
    fields: dict[str, object],
) -> bool:
    """Try each pattern in dispatch table; set field on first match."""
    for pattern, key, converter in dispatch:
        if m := pattern.match(stripped):
            fields[key] = converter(m.group(1))
            return True
    return False


def _parse_process_info(lines: list[str]) -> ProcessInfo:
    """Parse the BGP Process Information block."""
    fields: dict[str, object] = {
        "process_id": 0,
        "protocol_started_reason": "",
        "protocol_tag": 0,
        "protocol_state": "",
        "isolate_mode": False,
        "mmode": "",
        "memory_state": "",
        "as_format": "",
    }

    for line in lines:
        stripped = line.strip()
        if _try_dispatch(stripped, _PROCESS_DISPATCH, fields):
            continue
        if m := _ISOLATE_MODE_RE.match(stripped):
            fields["isolate_mode"] = m.group(1).lower() == "yes"
        elif m := _PERFORMANCE_MODE_RE.match(stripped):
            fields["performance_mode"] = m.group(1).lower() != "no"
        elif m := _SR_GLOBAL_BLOCK_RE.match(stripped):
            fields["segment_routing_global_block"] = m.group(1)

    return cast(ProcessInfo, fields)


def _parse_attributes_info(lines: list[str]) -> AttributesInfo:
    """Parse the BGP attributes information block."""
    fields: dict[str, int] = {key: 0 for _, key in _ATTR_DISPATCH}

    for line in lines:
        stripped = line.strip()
        for pattern, key in _ATTR_DISPATCH:
            if m := pattern.match(stripped):
                fields[key] = int(m.group(1))
                break

    return cast(AttributesInfo, fields)


def _parse_vrf_fields(lines: list[str]) -> VrfEntry:
    """Parse VRF-level fields from lines between VRF header and first AF."""
    fields: dict[str, object] = {
        "vrf_id": 0,
        "vrf_state": "",
        "router_id": "",
        "configured_router_id": "",
        "confed_id": 0,
        "cluster_id": "",
        "configured_peers": 0,
        "pending_config_peers": 0,
        "established_peers": 0,
        "vrf_rd": "",
        "address_families": {},
    }

    for line in lines:
        stripped = line.strip()
        _try_dispatch(stripped, _VRF_FIELD_DISPATCH, fields)

    return cast(VrfEntry, fields)


def _collect_rt_values(lines: list[str], start_idx: int) -> tuple[list[str], int]:
    """Collect RT values from tab-indented lines following an RT list header.

    Returns tuple of (values, next_index).
    """
    values: list[str] = []
    idx = start_idx
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("\t") and line.strip():
            values.append(line.strip())
            idx += 1
        else:
            break
    return values, idx


def _parse_redistribution(lines: list[str], start_idx: int) -> tuple[list[str], int]:
    """Parse redistribution entries from tab-indented lines.

    Returns tuple of (redistribution_list, next_index).
    """
    entries: list[str] = []
    idx = start_idx
    while idx < len(lines):
        line = lines[idx]
        m = _REDISTRIBUTION_ENTRY_RE.match(line)
        if m:
            value = m.group(1)
            if value.lower() != "none":
                entries.append(value)
            idx += 1
        else:
            break
    return entries, idx


def _parse_af_detail_line(
    line: str,
    af_entry: AddressFamilyEntry,
) -> bool:
    """Try to parse a single AF detail line. Returns True if consumed."""
    for pattern, key in _AF_DETAIL_STR_DISPATCH:
        if m := pattern.match(line):
            af_entry[key] = m.group(1)  # type: ignore[literal-required]
            return True
    for pattern, key in _AF_DETAIL_INT_DISPATCH:
        if m := pattern.match(line):
            af_entry[key] = int(m.group(1))  # type: ignore[literal-required]
            return True
    for pattern, key in _AF_DETAIL_BOOL_DISPATCH:
        if pattern.match(line):
            af_entry[key] = True  # type: ignore[literal-required]
            return True
    return False


def _parse_af_table_fields(
    lines: list[str],
    af_entry: AddressFamilyEntry,
) -> None:
    """Parse table_id, table_state, and counter fields from AF lines."""
    expect_counters = False
    for line in lines:
        if m := _TABLE_ID_RE.match(line):
            af_entry["table_id"] = m.group(1)
        elif m := _TABLE_STATE_RE.match(line):
            af_entry["table_state"] = m.group(1)
        elif _AF_COUNTERS_HEADER_RE.match(line):
            expect_counters = True
        elif expect_counters:
            _try_parse_counters(line, af_entry)
            expect_counters = False


def _try_parse_counters(line: str, af_entry: AddressFamilyEntry) -> None:
    """Parse the counters data line if it matches."""
    m_c = _AF_COUNTERS_RE.match(line)
    if m_c:
        af_entry["counters"] = {
            "peers": int(m_c.group(1)),
            "active_peers": int(m_c.group(2)),
            "routes": int(m_c.group(3)),
            "paths": int(m_c.group(4)),
            "networks": int(m_c.group(5)),
            "aggregates": int(m_c.group(6)),
        }


def _try_parse_rt_list(
    line: str,
    lines: list[str],
    idx: int,
    af_entry: AddressFamilyEntry,
) -> tuple[bool, int]:
    """Try to parse an RT list header and its values. Returns (matched, new_idx)."""
    for pattern, key in _RT_LIST_DISPATCH:
        m = pattern.match(line)
        if m:
            inline = m.group(1)
            idx += 1
            if inline and inline.strip():
                af_entry[key] = [inline.strip()]  # type: ignore[literal-required]
            else:
                values, idx = _collect_rt_values(lines, idx)
                if values:
                    af_entry[key] = values  # type: ignore[literal-required]
            return True, idx
    return False, idx


def _parse_address_family(lines: list[str]) -> AddressFamilyEntry:
    """Parse a single address family block from its lines."""
    af_entry: AddressFamilyEntry = {
        "table_id": "",
        "table_state": "",
        "counters": {
            "peers": 0,
            "active_peers": 0,
            "routes": 0,
            "paths": 0,
            "networks": 0,
            "aggregates": 0,
        },
    }

    _parse_af_table_fields(lines, af_entry)

    idx = 0
    while idx < len(lines):
        line = lines[idx]

        if _REDISTRIBUTION_HEADER_RE.match(line):
            idx += 1
            redist, idx = _parse_redistribution(lines, idx)
            if redist:
                af_entry["redistribution"] = redist
            continue

        matched, idx = _try_parse_rt_list(line, lines, idx, af_entry)
        if matched:
            continue

        _parse_af_detail_line(line, af_entry)
        idx += 1

    return af_entry


# ---------------------------------------------------------------------------
# Section splitting
# ---------------------------------------------------------------------------


def _flush_af(
    current_af: str | None,
    current_af_lines: list[str],
    af_sections: list[tuple[str, list[str]]],
) -> None:
    """Flush the current AF section if present."""
    if current_af is not None:
        af_sections.append((current_af, current_af_lines))


def _flush_vrf(
    current_vrf: str | None,
    current_vrf_lines: list[str],
    af_sections: list[tuple[str, list[str]]],
    vrf_sections: list[tuple[str, list[str], list[tuple[str, list[str]]]]],
) -> None:
    """Flush the current VRF section if present."""
    if current_vrf is not None:
        vrf_sections.append((current_vrf, current_vrf_lines, af_sections))


def _split_into_sections(
    lines: list[str],
) -> tuple[list[str], list[tuple[str, list[str], list[tuple[str, list[str]]]]]]:
    """Split the output into the global header and per-VRF sections.

    Returns:
        (header_lines, vrf_sections) where each vrf_section is
        (vrf_name, vrf_field_lines, [(af_name, af_lines), ...])
    """
    header_lines: list[str] = []
    vrf_sections: list[tuple[str, list[str], list[tuple[str, list[str]]]]] = []

    current_vrf: str | None = None
    current_vrf_lines: list[str] = []
    current_af: str | None = None
    current_af_lines: list[str] = []
    af_sections: list[tuple[str, list[str]]] = []

    for line in lines:
        m_vrf = _VRF_HEADER_RE.match(line.strip())
        if m_vrf:
            _flush_af(current_af, current_af_lines, af_sections)
            _flush_vrf(current_vrf, current_vrf_lines, af_sections, vrf_sections)
            current_vrf = m_vrf.group(1)
            current_vrf_lines = []
            current_af = None
            current_af_lines = []
            af_sections = []
            continue

        m_af = _AF_HEADER_RE.match(line)
        if m_af and current_vrf is not None:
            _flush_af(current_af, current_af_lines, af_sections)
            current_af = m_af.group(1)
            current_af_lines = []
            continue

        if current_vrf is None:
            header_lines.append(line)
        elif current_af is not None:
            current_af_lines.append(line)
        else:
            current_vrf_lines.append(line)

    _flush_af(current_af, current_af_lines, af_sections)
    _flush_vrf(current_vrf, current_vrf_lines, af_sections, vrf_sections)

    return header_lines, vrf_sections


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_NXOS, "show bgp process vrf all")
class ShowBgpProcessVrfAllParser(BaseParser["ShowBgpProcessVrfAllResult"]):
    """Parser for 'show bgp process vrf all' on NX-OS.

    Parses BGP process information, attribute statistics, and per-VRF
    details including address family configuration.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpProcessVrfAllResult:
        """Parse 'show bgp process vrf all' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP process information keyed by VRF name.
        """
        lines = output.splitlines()
        header_lines, vrf_sections = _split_into_sections(lines)

        process_info = _parse_process_info(header_lines)
        attributes_info = _parse_attributes_info(header_lines)

        vrfs: dict[str, VrfEntry] = {}
        for vrf_name, vrf_lines, af_sections in vrf_sections:
            vrf_entry = _parse_vrf_fields(vrf_lines)
            for af_name, af_lines in af_sections:
                vrf_entry["address_families"][af_name] = _parse_address_family(af_lines)
            vrfs[vrf_name] = vrf_entry

        return {
            "process": process_info,
            "attributes": attributes_info,
            "vrfs": vrfs,
        }
