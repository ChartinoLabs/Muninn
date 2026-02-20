"""Parser for 'show ip bgp summary' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class MemoryNetworkEntries(TypedDict):
    """Schema for network entries memory usage."""

    count: int
    bytes: int


class MemoryPathEntries(TypedDict):
    """Schema for path entries memory usage."""

    count: int
    bytes: int


class MemoryPathAttributeEntries(TypedDict):
    """Schema for path/bestpath attribute entries memory usage."""

    count: int
    bestpath_count: int
    bytes: int


class MemoryGenericEntries(TypedDict):
    """Schema for generic memory entries (rrinfo, AS-PATH, community, etc.)."""

    count: int
    bytes: int


class MemoryInfo(TypedDict):
    """Schema for BGP memory statistics."""

    network_entries: NotRequired[MemoryNetworkEntries]
    path_entries: NotRequired[MemoryPathEntries]
    path_attribute_entries: NotRequired[MemoryPathAttributeEntries]
    rrinfo_entries: NotRequired[MemoryGenericEntries]
    as_path_entries: NotRequired[MemoryGenericEntries]
    community_entries: NotRequired[MemoryGenericEntries]
    extended_community_entries: NotRequired[MemoryGenericEntries]
    route_map_cache_entries: NotRequired[MemoryGenericEntries]
    filter_list_cache_entries: NotRequired[MemoryGenericEntries]
    total_bytes: int


class ActivityInfo(TypedDict):
    """Schema for BGP activity statistics."""

    prefixes_current: int
    prefixes_total: int
    paths_current: int
    paths_total: int
    scan_interval_secs: int


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor."""

    version: int
    remote_as: str
    msg_rcvd: int
    msg_sent: int
    tbl_ver: int
    in_queue: int
    out_queue: int
    up_down: str
    state_pfxrcd: str


class AddressFamilyEntry(TypedDict):
    """Schema for a single address family section."""

    router_id: str
    local_as: str
    table_version: int
    main_routing_table_version: int
    memory: MemoryInfo
    activity: ActivityInfo
    neighbors: dict[str, NeighborEntry]


class ShowIpBgpSummaryResult(TypedDict):
    """Schema for 'show ip bgp summary' parsed output."""

    address_families: dict[str, AddressFamilyEntry]


# --- Header patterns ---
_AF_HEADER_RE = re.compile(r"^For address family:\s*(.+?)\s*$")
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)\s*$")
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*main routing table version (\d+)\s*$"
)

# --- Memory patterns ---
_NETWORK_ENTRIES_RE = re.compile(
    r"^(\d+) network entries? using (\d+) bytes of memory\s*$"
)
_PATH_ENTRIES_RE = re.compile(r"^(\d+) path entries? using (\d+) bytes of memory\s*$")
_PATH_ATTR_RE = re.compile(
    r"^(\d+)/(\d+) BGP path/bestpath attribute entries? using (\d+) bytes of memory\s*$"
)
_GENERIC_ENTRIES_RE = re.compile(
    r"^(\d+) BGP (\S+(?:\s+\S+)*?) entries? using (\d+) bytes of memory\s*$"
)
_TOTAL_MEMORY_RE = re.compile(r"^BGP using (\d+) total bytes of memory\s*$")

# --- Activity pattern ---
_ACTIVITY_RE = re.compile(
    r"^BGP activity (\d+)/(\d+) prefixes,\s*(\d+)/(\d+) paths,\s*"
    r"scan interval (\d+) secs\s*$"
)

# --- Neighbor table header ---
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+V\s+AS\s+MsgRcvd")

# --- Neighbor line: starts with an IP address ---
_NEIGHBOR_LINE_RE = re.compile(
    r"^(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
    r"(\S+)\s+(.+?)\s*$"
)

# --- Continuation line for IPv6 neighbors that wrap ---
_NEIGHBOR_CONTINUATION_RE = re.compile(
    r"^\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+"
    r"(\S+)\s+(.+?)\s*$"
)

# Map from the entry type string to our field name
_GENERIC_ENTRY_FIELDS: dict[str, str] = {
    "rrinfo": "rrinfo_entries",
    "AS-PATH": "as_path_entries",
    "community": "community_entries",
    "extended community": "extended_community_entries",
    "route-map cache": "route_map_cache_entries",
    "filter-list cache": "filter_list_cache_entries",
}

# Default address family when no header is present
_DEFAULT_ADDRESS_FAMILY = "IPv4 Unicast"


def _parse_memory(lines: list[str]) -> MemoryInfo:
    """Parse memory statistics from the header section."""
    memory: dict = {}

    for line in lines:
        m = _NETWORK_ENTRIES_RE.match(line)
        if m:
            memory["network_entries"] = {
                "count": int(m.group(1)),
                "bytes": int(m.group(2)),
            }
            continue

        m = _PATH_ENTRIES_RE.match(line)
        if m:
            memory["path_entries"] = {
                "count": int(m.group(1)),
                "bytes": int(m.group(2)),
            }
            continue

        m = _PATH_ATTR_RE.match(line)
        if m:
            memory["path_attribute_entries"] = {
                "count": int(m.group(1)),
                "bestpath_count": int(m.group(2)),
                "bytes": int(m.group(3)),
            }
            continue

        m = _GENERIC_ENTRIES_RE.match(line)
        if m:
            entry_type = m.group(2)
            field_name = _GENERIC_ENTRY_FIELDS.get(entry_type)
            if field_name:
                memory[field_name] = {
                    "count": int(m.group(1)),
                    "bytes": int(m.group(3)),
                }
            continue

        m = _TOTAL_MEMORY_RE.match(line)
        if m:
            memory["total_bytes"] = int(m.group(1))
            continue

    return memory  # type: ignore[return-value]


def _parse_activity(lines: list[str]) -> ActivityInfo | None:
    """Parse the BGP activity line."""
    for line in lines:
        m = _ACTIVITY_RE.match(line)
        if m:
            return {
                "prefixes_current": int(m.group(1)),
                "prefixes_total": int(m.group(2)),
                "paths_current": int(m.group(3)),
                "paths_total": int(m.group(4)),
                "scan_interval_secs": int(m.group(5)),
            }
    return None


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse the neighbor table from lines after the header."""
    neighbors: dict[str, NeighborEntry] = {}
    pending_address: str | None = None

    for line in lines:
        # Skip the header line
        if _NEIGHBOR_HEADER_RE.match(line):
            pending_address = None
            continue

        # Try full neighbor line (address + data on same line)
        m = _NEIGHBOR_LINE_RE.match(line)
        if m:
            pending_address = None
            address = m.group(1)
            neighbors[address] = {
                "version": int(m.group(2)),
                "remote_as": m.group(3),
                "msg_rcvd": int(m.group(4)),
                "msg_sent": int(m.group(5)),
                "tbl_ver": int(m.group(6)),
                "in_queue": int(m.group(7)),
                "out_queue": int(m.group(8)),
                "up_down": m.group(9),
                "state_pfxrcd": m.group(10),
            }
            continue

        # Check for an address alone on a line (IPv6 or IPv4 that wraps)
        stripped = line.strip()
        if stripped and ":" in stripped and " " not in stripped:
            pending_address = stripped
            continue

        # Try continuation line (data columns only, for wrapped IPv6 addresses)
        if pending_address:
            m = _NEIGHBOR_CONTINUATION_RE.match(line)
            if m:
                neighbors[pending_address] = {
                    "version": int(m.group(1)),
                    "remote_as": m.group(2),
                    "msg_rcvd": int(m.group(3)),
                    "msg_sent": int(m.group(4)),
                    "tbl_ver": int(m.group(5)),
                    "in_queue": int(m.group(6)),
                    "out_queue": int(m.group(7)),
                    "up_down": m.group(8),
                    "state_pfxrcd": m.group(9),
                }
                pending_address = None
                continue

    return neighbors


def _parse_address_family(lines: list[str], af_name: str) -> AddressFamilyEntry | None:
    """Parse a single address family block."""
    router_id: str | None = None
    local_as: str | None = None
    table_version: int | None = None
    main_version: int | None = None

    for line in lines:
        m = _ROUTER_ID_RE.match(line)
        if m:
            router_id = m.group(1)
            local_as = m.group(2)
            continue

        m = _TABLE_VERSION_RE.match(line)
        if m:
            table_version = int(m.group(1))
            main_version = int(m.group(2))
            continue

    # Must have at minimum router ID and table version
    if router_id is None or local_as is None:
        return None
    if table_version is None or main_version is None:
        return None

    memory = _parse_memory(lines)
    activity = _parse_activity(lines)
    neighbors = _parse_neighbors(lines)

    entry: AddressFamilyEntry = {
        "router_id": router_id,
        "local_as": local_as,
        "table_version": table_version,
        "main_routing_table_version": main_version,
        "memory": memory,
        "activity": activity,  # type: ignore[typeddict-item]
        "neighbors": neighbors,
    }

    # Omit activity if not present
    if activity is None:
        del entry["activity"]  # type: ignore[misc]

    return entry


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a leading prompt/noise line."""
    if not stripped:
        return True
    if stripped.endswith("#") or "#show " in stripped.lower():
        return True
    return stripped.startswith("Load for ") or stripped.startswith("Time source ")


def _dedent_lines(lines: list[str]) -> list[str]:
    """Remove common leading whitespace from non-empty lines."""
    indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
    min_indent = min(indents, default=0)
    if min_indent > 0:
        return [
            line[min_indent:] if len(line) >= min_indent else line for line in lines
        ]
    return lines


def _strip_prompt_lines(lines: list[str]) -> list[str]:
    """Strip leading prompt/noise lines, preserving relative indentation."""
    content: list[str] = []
    started = False
    for line in lines:
        if not started:
            if _is_noise_line(line.strip()):
                continue
            started = True
        content.append(line)

    return _dedent_lines(content)


def _split_address_families(lines: list[str]) -> list[tuple[str, list[str]]]:
    """Split output into address family sections."""
    sections: list[tuple[str, list[str]]] = []
    current_af: str | None = None
    current_lines: list[str] = []

    for line in lines:
        m = _AF_HEADER_RE.match(line)
        if m:
            if current_af is not None or current_lines:
                af_name = current_af if current_af else _DEFAULT_ADDRESS_FAMILY
                sections.append((af_name, current_lines))
            current_af = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    # Final section
    if current_lines:
        af_name = current_af if current_af else _DEFAULT_ADDRESS_FAMILY
        sections.append((af_name, current_lines))

    return sections


@register(OS.CISCO_IOS, "show ip bgp summary")
@register(OS.CISCO_IOSXE, "show ip bgp summary")
class ShowIpBgpSummaryParser(BaseParser["ShowIpBgpSummaryResult"]):
    """Parser for 'show ip bgp summary' on IOS/IOS-XE."""

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryResult:
        """Parse 'show ip bgp summary' output."""
        raw_lines = output.splitlines()
        lines = _strip_prompt_lines(raw_lines)

        sections = _split_address_families(lines)
        address_families: dict[str, AddressFamilyEntry] = {}

        for af_name, af_lines in sections:
            parsed = _parse_address_family(af_lines, af_name)
            if parsed is not None:
                address_families[af_name] = parsed

        return {"address_families": address_families}
