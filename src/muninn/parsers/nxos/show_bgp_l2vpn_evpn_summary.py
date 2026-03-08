"""Parser for 'show bgp l2vpn evpn summary' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class BracketEntries(TypedDict):
    """Schema for bracket-notation memory entries [count/bytes]."""

    count: int
    bytes: int


class MemoryInfo(TypedDict):
    """Schema for NX-OS BGP memory statistics."""

    network_entries: int
    paths: int
    bytes_used: int
    attribute_entries: BracketEntries
    as_path_entries: BracketEntries
    community_entries: BracketEntries
    clusterlist_entries: BracketEntries


class DampeningInfo(TypedDict):
    """Schema for BGP dampening statistics."""

    history_paths: int
    dampened_paths: int


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor in the L2VPN EVPN summary."""

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
    """Schema for a single address family section within a VRF."""

    router_id: str
    local_as: str
    table_version: int
    config_peers: int
    capable_peers: int
    memory: MemoryInfo
    dampening: NotRequired[DampeningInfo]
    received_paths: NotRequired[int]
    neighbors: dict[str, NeighborEntry]


class VrfEntry(TypedDict):
    """Schema for a single VRF."""

    address_families: dict[str, AddressFamilyEntry]


class ShowBgpL2vpnEvpnSummaryResult(TypedDict):
    """Schema for 'show bgp l2vpn evpn summary' parsed output on NX-OS."""

    vrfs: dict[str, VrfEntry]


# --- Section header ---
_VRF_AF_HEADER_RE = re.compile(
    r"^BGP summary information for VRF (\S+),\s*address family (.+?)\s*$"
)

# --- Header patterns ---
_ROUTER_ID_RE = re.compile(r"^BGP router identifier (\S+),\s*local AS number (\S+)\s*$")
_TABLE_VERSION_RE = re.compile(
    r"^BGP table version is (\d+),\s*.+?config peers (\d+),\s*capable peers (\d+)\s*$"
)

# --- Memory patterns ---
_COMPACT_MEMORY_RE = re.compile(
    r"^(\d+) network entries? and (\d+) paths? using (\d+) bytes of memory\s*$"
)
_BRACKET_LINE1_RE = re.compile(
    r"^BGP attribute entries \[(\d+)/(\d+)\],\s*"
    r"BGP AS path entries \[(\d+)/(\d+)\]\s*$"
)
_BRACKET_LINE2_RE = re.compile(
    r"^BGP community entries \[(\d+)/(\d+)\],\s*"
    r"BGP clusterlist entries \[(\d+)/(\d+)\]\s*$"
)

# --- Optional lines ---
_DAMPENING_RE = re.compile(
    r"^Dampening configured,\s*(\d+) history paths?,\s*(\d+) dampened paths?\s*$"
)
_RECEIVED_PATHS_RE = re.compile(
    r"^(\d+) received paths for inbound soft reconfiguration\s*$"
)

# --- Neighbor table ---
_NEIGHBOR_HEADER_RE = re.compile(r"^Neighbor\s+V\s+AS\s+MsgRcvd")


def _is_noise_line(stripped: str) -> bool:
    """Return True if a stripped line is a leading prompt/noise line."""
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
    """Split output into (vrf, af, lines) sections based on VRF/AF headers."""
    sections: list[tuple[str, str, list[str]]] = []
    current_vrf: str | None = None
    current_af: str | None = None
    current_lines: list[str] = []

    for line in lines:
        m = _VRF_AF_HEADER_RE.match(line)
        if m:
            if current_vrf is not None:
                sections.append((current_vrf, current_af or "", current_lines))
            current_vrf = m.group(1)
            current_af = m.group(2)
            current_lines = []
        else:
            current_lines.append(line)

    if current_vrf is not None:
        sections.append((current_vrf, current_af or "", current_lines))

    return sections


def _parse_memory(lines: list[str]) -> MemoryInfo:
    """Parse memory statistics from section lines."""
    network_entries = 0
    paths = 0
    bytes_used = 0
    attribute_entries: BracketEntries = {"count": 0, "bytes": 0}
    as_path_entries: BracketEntries = {"count": 0, "bytes": 0}
    community_entries: BracketEntries = {"count": 0, "bytes": 0}
    clusterlist_entries: BracketEntries = {"count": 0, "bytes": 0}

    for line in lines:
        if m := _COMPACT_MEMORY_RE.match(line):
            network_entries = int(m.group(1))
            paths = int(m.group(2))
            bytes_used = int(m.group(3))
            continue

        if m := _BRACKET_LINE1_RE.match(line):
            attribute_entries = {"count": int(m.group(1)), "bytes": int(m.group(2))}
            as_path_entries = {"count": int(m.group(3)), "bytes": int(m.group(4))}
            continue

        if m := _BRACKET_LINE2_RE.match(line):
            community_entries = {"count": int(m.group(1)), "bytes": int(m.group(2))}
            clusterlist_entries = {"count": int(m.group(3)), "bytes": int(m.group(4))}
            continue

    return {
        "network_entries": network_entries,
        "paths": paths,
        "bytes_used": bytes_used,
        "attribute_entries": attribute_entries,
        "as_path_entries": as_path_entries,
        "community_entries": community_entries,
        "clusterlist_entries": clusterlist_entries,
    }


def _parse_dampening(lines: list[str]) -> DampeningInfo | None:
    """Parse optional dampening line."""
    for line in lines:
        if m := _DAMPENING_RE.match(line):
            return {
                "history_paths": int(m.group(1)),
                "dampened_paths": int(m.group(2)),
            }
    return None


def _parse_received_paths(lines: list[str]) -> int | None:
    """Parse optional received paths count."""
    for line in lines:
        if m := _RECEIVED_PATHS_RE.match(line):
            return int(m.group(1))
    return None


def _complete_neighbor(
    neighbors: dict[str, NeighborEntry],
    address: str,
    tokens: list[str],
) -> None:
    """Build a NeighborEntry from collected tokens and add to neighbors dict."""
    min_neighbor_fields = 9
    if len(tokens) < min_neighbor_fields:
        return
    neighbors[address] = {
        "version": int(tokens[0]),
        "remote_as": tokens[1],
        "msg_rcvd": int(tokens[2]),
        "msg_sent": int(tokens[3]),
        "tbl_ver": int(tokens[4]),
        "in_queue": int(tokens[5]),
        "out_queue": int(tokens[6]),
        "up_down": tokens[7],
        "state_pfxrcd": " ".join(tokens[8:]),
    }


def _extract_neighbor_lines(lines: list[str]) -> list[str]:
    """Extract only the neighbor table lines (after the header)."""
    result: list[str] = []
    in_section = False
    for line in lines:
        if _NEIGHBOR_HEADER_RE.match(line):
            in_section = True
            continue
        if in_section:
            result.append(line)
    return result


def _flush_neighbor(
    neighbors: dict[str, NeighborEntry],
    addr: str | None,
    tokens: list[str],
) -> None:
    """Flush a pending neighbor entry if complete."""
    if addr and tokens:
        _complete_neighbor(neighbors, addr, tokens)


def _parse_neighbors(lines: list[str]) -> dict[str, NeighborEntry]:
    """Parse the neighbor table from lines after the header.

    Handles NX-OS wrapping patterns:
    - Full line: all fields on one line
    - Address wrap: address alone, data on next line(s)
    - AS wrap: address + V + AS on one line, remaining fields on next line
    - Triple wrap: address alone, then V + AS, then remaining fields
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

        if line[0] not in (" ", "\t"):
            _flush_neighbor(neighbors, current_addr, current_tokens)
            tokens = stripped.split()
            current_addr = tokens[0]
            current_tokens = tokens[1:]
        else:
            current_tokens.extend(stripped.split())

    _flush_neighbor(neighbors, current_addr, current_tokens)
    return neighbors


class _SectionHeader:
    """Parsed header fields from a VRF/AF section."""

    __slots__ = (
        "router_id",
        "local_as",
        "table_version",
        "config_peers",
        "capable_peers",
    )

    def __init__(
        self,
        router_id: str,
        local_as: str,
        table_version: int,
        config_peers: int,
        capable_peers: int,
    ) -> None:
        self.router_id = router_id
        self.local_as = local_as
        self.table_version = table_version
        self.config_peers = config_peers
        self.capable_peers = capable_peers


def _parse_section_header(lines: list[str]) -> _SectionHeader | None:
    """Extract router ID, local AS, and table version from section lines."""
    router_id: str | None = None
    local_as: str | None = None
    table_version: int | None = None
    config_peers: int | None = None
    capable_peers: int | None = None

    for line in lines:
        if m := _ROUTER_ID_RE.match(line):
            router_id = m.group(1)
            local_as = m.group(2)
        elif m := _TABLE_VERSION_RE.match(line):
            table_version = int(m.group(1))
            config_peers = int(m.group(2))
            capable_peers = int(m.group(3))

    if router_id is None or local_as is None:
        return None
    if table_version is None or config_peers is None or capable_peers is None:
        return None

    return _SectionHeader(
        router_id, local_as, table_version, config_peers, capable_peers
    )


def _parse_section(lines: list[str]) -> AddressFamilyEntry | None:
    """Parse a single VRF/AF section."""
    header = _parse_section_header(lines)
    if header is None:
        return None

    entry: AddressFamilyEntry = {
        "router_id": header.router_id,
        "local_as": header.local_as,
        "table_version": header.table_version,
        "config_peers": header.config_peers,
        "capable_peers": header.capable_peers,
        "memory": _parse_memory(lines),
        "neighbors": _parse_neighbors(lines),
    }

    if (dampening := _parse_dampening(lines)) is not None:
        entry["dampening"] = dampening
    if (received_paths := _parse_received_paths(lines)) is not None:
        entry["received_paths"] = received_paths

    return entry


@register(OS.CISCO_NXOS, "show bgp l2vpn evpn summary")
class ShowBgpL2vpnEvpnSummaryParser(BaseParser["ShowBgpL2vpnEvpnSummaryResult"]):
    """Parser for 'show bgp l2vpn evpn summary' on NX-OS."""

    @classmethod
    def parse(cls, output: str) -> ShowBgpL2vpnEvpnSummaryResult:
        """Parse 'show bgp l2vpn evpn summary' output."""
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
