"""Parser for 'show bgp vrf all all neighbors' command on NX-OS."""

from __future__ import annotations

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class MessageStats(TypedDict):
    """Schema for BGP message statistics."""

    opens_sent: int
    opens_rcvd: int
    notifications_sent: int
    notifications_rcvd: int
    updates_sent: int
    updates_rcvd: int
    keepalives_sent: int
    keepalives_rcvd: int
    route_refresh_sent: int
    route_refresh_rcvd: int
    capability_sent: int
    capability_rcvd: int
    total_sent: int
    total_rcvd: int
    total_bytes_sent: int
    total_bytes_rcvd: int
    bytes_in_queue_sent: int
    bytes_in_queue_rcvd: int


class AddressFamilyInfo(TypedDict):
    """Schema for per-address-family information."""

    table_version: int
    neighbor_version: int
    accepted_paths: int
    accepted_paths_memory: int
    sent_paths: int
    inbound_route_map: NotRequired[str]
    outbound_route_map: NotRequired[str]
    inbound_soft_reconfig: NotRequired[bool]
    community_attr_sent: NotRequired[bool]
    extended_community_attr_sent: NotRequired[bool]
    max_prefixes: NotRequired[int]
    max_prefix_warning_threshold: NotRequired[int]
    route_reflector_client: NotRequired[bool]


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor."""

    remote_as: int
    link_type: str
    peer_index: int
    description: NotRequired[str]
    peer_template: NotRequired[str]
    bgp_version: int
    router_id: str
    bgp_state: str
    state_reason: NotRequired[str]
    state_duration: NotRequired[str]
    update_source: NotRequired[str]
    attached_interface: NotRequired[str]
    local_as: NotRequired[int]
    bfd_enabled: NotRequired[bool]
    bfd_state: NotRequired[str]
    hold_time: int
    keepalive_interval: int
    last_read: str
    last_written: str
    msgs_sent: int
    msgs_rcvd: int
    notifications_sent: int
    notifications_rcvd: int
    bytes_in_queue_sent: int
    bytes_in_queue_rcvd: int
    connections_established: int
    connections_dropped: int
    connection_attempts: NotRequired[int]
    last_reset_by_us: NotRequired[str]
    last_reset_by_us_reason: NotRequired[str]
    last_reset_by_peer: NotRequired[str]
    last_reset_by_peer_reason: NotRequired[str]
    message_stats: MessageStats
    address_families: dict[str, AddressFamilyInfo]
    local_host: NotRequired[str]
    local_port: NotRequired[int]
    foreign_host: NotRequired[str]
    foreign_port: NotRequired[int]
    fd: NotRequired[int]


class ShowBgpVrfAllAllNeighborsResult(TypedDict):
    """Schema for 'show bgp vrf all all neighbors' parsed output on NX-OS."""

    vrfs: dict[str, dict[str, NeighborEntry]]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

_VRF_HEADER_RE = re.compile(
    r"^\s*show bgp vrf (?P<vrf>\S+) all neighbors\s*$", re.IGNORECASE
)

_NEIGHBOR_HEADER_RE = re.compile(
    r"^BGP neighbor is (?P<neighbor>\S+),\s+"
    r"remote AS (?P<remote_as>\d+)"
    r"(?:,\s+local AS (?P<local_as>\d+))?"
    r",\s+(?P<link_type>\S+(?: \S+)*?)\s+link"
    r"(?:,\s+(?P<extra>[^,]+?))*"
    r",\s+Peer index (?P<peer_index>\d+)"
)

_PEER_TEMPLATE_RE = re.compile(
    r"^\s+Inherits (?:session|peer) configuration from "
    r"(?:session-template |peer-template )?(?P<template>\S+)"
)

_DESCRIPTION_RE = re.compile(r"^\s+Description:\s+(?P<desc>.+)$")

_BGP_VERSION_RE = re.compile(
    r"^\s+BGP version (?P<version>\d+),\s+"
    r"remote router ID (?P<router_id>\S+)"
)

_BGP_STATE_UP_RE = re.compile(
    r"^\s+BGP state = (?P<state>\S+),\s+up for (?P<duration>\S+)"
)

_BGP_STATE_DOWN_RE = re.compile(
    r"^\s+BGP state = (?P<state>\S+)"
    r"(?: \((?P<reason>[^)]+)\))?"
    r",\s+down for (?P<duration>[^,\s]+)"
)

_BGP_STATE_SIMPLE_RE = re.compile(
    r"^\s+BGP state = (?P<state>\S+)"
    r"(?: \((?P<reason>[^)]+)\))?"
)

_UPDATE_SOURCE_RE = re.compile(r"^\s+Using (?P<source>\S+) as update source")

_ATTACHED_INTF_RE = re.compile(
    r"^\s+Peer is directly attached, interface (?P<intf>\S+)"
)

_BFD_CONFIGURED_RE = re.compile(r"^\s+BFD live-detection is configured\s*$")

_BFD_CONFIGURED_STATE_RE = re.compile(
    r"^\s+BFD live-detection is configured and "
    r"(?P<admin>\w+),\s+state is (?P<state>\S+)"
)

_LAST_READ_RE = re.compile(
    r"^\s+Last read (?P<last_read>\S+),\s+"
    r"hold time = (?P<hold_time>\d+),\s+"
    r"keepalive interval is (?P<keepalive>\d+) seconds"
)

_LAST_WRITTEN_RE = re.compile(r"^\s+Last written (?P<last_written>\S+),")

_RECEIVED_RE = re.compile(
    r"^\s+Received (?P<count>\d+) messages,\s+"
    r"(?P<notif>\d+) notifications,\s+"
    r"(?P<bytes>\d+)"
    r"(?:\(\d+\))?"  # handle optional "(0)" format
    r" bytes in queue"
)

_SENT_RE = re.compile(
    r"^\s+Sent (?P<count>\d+) messages,\s+"
    r"(?P<notif>\d+) notifications,\s+"
    r"(?P<bytes>\d+)"
    r"(?:\(\d+\))?"
    r" bytes in queue"
)

_CONNECTIONS_RE = re.compile(
    r"^\s+Connections established (?P<established>\d+),\s+"
    r"dropped (?P<dropped>\d+)"
)

_CONN_ATTEMPTS_RE = re.compile(r"^\s+Connection attempts (?P<attempts>\d+)")

_LAST_RESET_US_RE = re.compile(
    r"^\s+Last reset by us (?P<time>\S+),\s+"
    r"due to (?P<reason>.+)$"
)

_LAST_RESET_PEER_RE = re.compile(
    r"^\s+Last reset by peer (?P<time>\S+),\s+"
    r"due to (?P<reason>.+)$"
)

# Message statistics table row
_MSG_STAT_RE = re.compile(r"^\s+(?P<label>[\w ]+?):\s+(?P<sent>\d+)\s+(?P<rcvd>\d+)")

# Address family patterns
_AF_HEADER_RE = re.compile(r"^\s+For address family:\s+(?P<af>.+?)\s*$")

_AF_TABLE_VERSION_RE = re.compile(
    r"^\s+BGP table version (?P<table_ver>\d+),\s+"
    r"neighbor version (?P<nbr_ver>\d+)"
)

_AF_ACCEPTED_PATHS_RE = re.compile(
    r"^\s+(?P<count>\d+) accepted (?:paths|prefixes)"
    r"(?: \(\d+ paths\))?"
    r" consume (?P<memory>\d+) bytes"
)

_AF_SENT_PATHS_RE = re.compile(r"^\s+(?P<count>\d+) sent (?:paths|prefixes)")

_AF_INBOUND_RM_RE = re.compile(r"^\s+Inbound route-map configured is (?P<name>\S+),")

_AF_OUTBOUND_RM_RE = re.compile(r"^\s+Outbound route-map configured is (?P<name>\S+),")

_AF_INBOUND_SOFT_RE = re.compile(r"^\s+Inbound soft reconfiguration allowed")

_AF_COMMUNITY_RE = re.compile(r"^\s+Community attribute sent to this neighbor")

_AF_EXT_COMMUNITY_RE = re.compile(r"^\s+Extended community attribute sent")

_AF_MAX_PREFIX_RE = re.compile(r"^\s+Maximum prefixes allowed (?P<max>\d+)")

_AF_MAX_PREFIX_WARN_RE = re.compile(r"^\s+Threshold for warning messages (?P<pct>\d+)%")

_AF_ROUTE_REFLECTOR_RE = re.compile(r"^\s+Route reflector client\s*$")

# Local/Foreign host
_LOCAL_HOST_RE = re.compile(
    r"^\s+Local host:\s+(?P<host>\S+),\s+"
    r"Local port:\s+(?P<port>\d+)"
)

_FOREIGN_HOST_RE = re.compile(
    r"^\s+Foreign host:\s+(?P<host>\S+),\s+"
    r"Foreign port:\s+(?P<port>\d+)"
)

_FD_RE = re.compile(r"^\s+fd = (?P<fd>\d+)")


# Default router ID placeholder — not a real bind address
_DEFAULT_ROUTER_ID = "0.0.0.0"  # nosec B104


# ---------------------------------------------------------------------------
# Helper parsers
# ---------------------------------------------------------------------------


def _build_empty_message_stats() -> MessageStats:
    """Return a zeroed-out MessageStats dict."""
    return {
        "opens_sent": 0,
        "opens_rcvd": 0,
        "notifications_sent": 0,
        "notifications_rcvd": 0,
        "updates_sent": 0,
        "updates_rcvd": 0,
        "keepalives_sent": 0,
        "keepalives_rcvd": 0,
        "route_refresh_sent": 0,
        "route_refresh_rcvd": 0,
        "capability_sent": 0,
        "capability_rcvd": 0,
        "total_sent": 0,
        "total_rcvd": 0,
        "total_bytes_sent": 0,
        "total_bytes_rcvd": 0,
        "bytes_in_queue_sent": 0,
        "bytes_in_queue_rcvd": 0,
    }


def _parse_message_stats(lines: list[str], start_idx: int) -> MessageStats:
    """Parse the message statistics table starting at start_idx."""
    stats: dict[str, tuple[int, int]] = {}
    idx = start_idx

    # Skip to the "Sent  Rcvd" header line
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("Sent") and "Rcvd" in stripped:
            idx += 1
            break
        idx += 1

    # Parse stat rows
    while idx < len(lines):
        m = _MSG_STAT_RE.match(lines[idx])
        if not m:
            break
        label = m.group("label").strip().rstrip(":")
        stats[label] = (int(m.group("sent")), int(m.group("rcvd")))
        idx += 1

    return _stats_dict_to_message_stats(stats)


def _stats_dict_to_message_stats(
    stats: dict[str, tuple[int, int]],
) -> MessageStats:
    """Convert a label-keyed stats dict to a MessageStats TypedDict."""

    def _g(key: str) -> tuple[int, int]:
        return stats.get(key, (0, 0))

    o, n, u = _g("Opens"), _g("Notifications"), _g("Updates")
    k, rr, c = _g("Keepalives"), _g("Route Refresh"), _g("Capability")
    t, tb, bq = _g("Total"), _g("Total bytes"), _g("Bytes in queue")

    return {
        "opens_sent": o[0],
        "opens_rcvd": o[1],
        "notifications_sent": n[0],
        "notifications_rcvd": n[1],
        "updates_sent": u[0],
        "updates_rcvd": u[1],
        "keepalives_sent": k[0],
        "keepalives_rcvd": k[1],
        "route_refresh_sent": rr[0],
        "route_refresh_rcvd": rr[1],
        "capability_sent": c[0],
        "capability_rcvd": c[1],
        "total_sent": t[0],
        "total_rcvd": t[1],
        "total_bytes_sent": tb[0],
        "total_bytes_rcvd": tb[1],
        "bytes_in_queue_sent": bq[0],
        "bytes_in_queue_rcvd": bq[1],
    }


def _apply_af_version_paths(entry: AddressFamilyInfo, line: str) -> bool:
    """Try to match AF version/path lines. Return True if matched."""
    m = _AF_TABLE_VERSION_RE.match(line)
    if m:
        entry["table_version"] = int(m.group("table_ver"))
        entry["neighbor_version"] = int(m.group("nbr_ver"))
        return True

    m = _AF_ACCEPTED_PATHS_RE.match(line)
    if m:
        entry["accepted_paths"] = int(m.group("count"))
        entry["accepted_paths_memory"] = int(m.group("memory"))
        return True

    m = _AF_SENT_PATHS_RE.match(line)
    if m:
        entry["sent_paths"] = int(m.group("count"))
        return True

    return False


def _apply_af_policy_attrs(entry: AddressFamilyInfo, line: str) -> bool:
    """Try to match AF policy/attribute lines. Return True if matched."""
    m = _AF_INBOUND_RM_RE.match(line)
    if m:
        entry["inbound_route_map"] = m.group("name")
        return True

    m = _AF_OUTBOUND_RM_RE.match(line)
    if m:
        entry["outbound_route_map"] = m.group("name")
        return True

    if _AF_INBOUND_SOFT_RE.match(line):
        entry["inbound_soft_reconfig"] = True
        return True

    if _AF_COMMUNITY_RE.match(line):
        entry["community_attr_sent"] = True
        return True

    if _AF_EXT_COMMUNITY_RE.match(line):
        entry["extended_community_attr_sent"] = True
        return True

    m = _AF_MAX_PREFIX_RE.match(line)
    if m:
        entry["max_prefixes"] = int(m.group("max"))
        return True

    m = _AF_MAX_PREFIX_WARN_RE.match(line)
    if m:
        entry["max_prefix_warning_threshold"] = int(m.group("pct"))
        return True

    if _AF_ROUTE_REFLECTOR_RE.match(line):
        entry["route_reflector_client"] = True
        return True

    return False


def _parse_address_families(
    lines: list[str], start_idx: int
) -> dict[str, AddressFamilyInfo]:
    """Parse all address family sections from neighbor lines."""
    afs: dict[str, AddressFamilyInfo] = {}
    current_af: str | None = None
    current_entry: AddressFamilyInfo | None = None

    for idx in range(start_idx, len(lines)):
        line = lines[idx]

        m = _AF_HEADER_RE.match(line)
        if m:
            if current_af is not None and current_entry is not None:
                afs[current_af] = current_entry
            current_af = m.group("af")
            current_entry = {
                "table_version": 0,
                "neighbor_version": 0,
                "accepted_paths": 0,
                "accepted_paths_memory": 0,
                "sent_paths": 0,
            }
            continue

        if current_entry is not None:
            if not _apply_af_version_paths(current_entry, line):
                _apply_af_policy_attrs(current_entry, line)

    if current_af is not None and current_entry is not None:
        afs[current_af] = current_entry

    return afs


def _try_parse_header_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match identity/state lines. Return True if matched."""
    m = _PEER_TEMPLATE_RE.match(line)
    if m:
        entry["peer_template"] = m.group("template")
        return True

    m = _DESCRIPTION_RE.match(line)
    if m:
        entry["description"] = m.group("desc")
        return True

    m = _BGP_VERSION_RE.match(line)
    if m:
        entry["bgp_version"] = int(m.group("version"))
        entry["router_id"] = m.group("router_id")
        return True

    m = _BGP_STATE_UP_RE.match(line)
    if m:
        entry["bgp_state"] = m.group("state")
        entry["state_duration"] = m.group("duration")
        return True

    m = _BGP_STATE_DOWN_RE.match(line)
    if m:
        entry["bgp_state"] = m.group("state")
        entry["state_duration"] = m.group("duration")
        if m.group("reason"):
            entry["state_reason"] = m.group("reason")
        return True

    m = _BGP_STATE_SIMPLE_RE.match(line)
    if m and entry["bgp_state"] == "Unknown":
        entry["bgp_state"] = m.group("state")
        if m.group("reason"):
            entry["state_reason"] = m.group("reason")
        return True

    return False


def _try_parse_transport_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match transport/interface lines. Return True if matched."""
    m = _UPDATE_SOURCE_RE.match(line)
    if m:
        entry["update_source"] = canonical_interface_name(
            m.group("source"),
            os=OS.CISCO_NXOS,
        )
        return True

    m = _ATTACHED_INTF_RE.match(line)
    if m:
        entry["attached_interface"] = canonical_interface_name(
            m.group("intf"),
            os=OS.CISCO_NXOS,
        )
        return True

    m = _BFD_CONFIGURED_STATE_RE.match(line)
    if m:
        entry["bfd_enabled"] = True
        entry["bfd_state"] = m.group("state")
        return True

    if _BFD_CONFIGURED_RE.match(line):
        entry["bfd_enabled"] = True
        return True

    return False


def _try_parse_timer_msg_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match timer/message/connection lines. Return True if matched."""
    m = _LAST_READ_RE.match(line)
    if m:
        entry["last_read"] = m.group("last_read")
        entry["hold_time"] = int(m.group("hold_time"))
        entry["keepalive_interval"] = int(m.group("keepalive"))
        return True

    m = _LAST_WRITTEN_RE.match(line)
    if m:
        entry["last_written"] = m.group("last_written")
        return True

    m = _RECEIVED_RE.match(line)
    if m:
        entry["msgs_rcvd"] = int(m.group("count"))
        entry["notifications_rcvd"] = int(m.group("notif"))
        entry["bytes_in_queue_rcvd"] = int(m.group("bytes"))
        return True

    m = _SENT_RE.match(line)
    if m:
        entry["msgs_sent"] = int(m.group("count"))
        entry["notifications_sent"] = int(m.group("notif"))
        entry["bytes_in_queue_sent"] = int(m.group("bytes"))
        return True

    m = _CONNECTIONS_RE.match(line)
    if m:
        entry["connections_established"] = int(m.group("established"))
        entry["connections_dropped"] = int(m.group("dropped"))
        return True

    m = _CONN_ATTEMPTS_RE.match(line)
    if m:
        entry["connection_attempts"] = int(m.group("attempts"))
        return True

    return _try_parse_reset_fields(line, entry)


def _try_parse_reset_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match reset-related lines. Return True if matched."""
    m = _LAST_RESET_US_RE.match(line)
    if m:
        entry["last_reset_by_us"] = m.group("time")
        entry["last_reset_by_us_reason"] = m.group("reason")
        return True

    m = _LAST_RESET_PEER_RE.match(line)
    if m:
        entry["last_reset_by_peer"] = m.group("time")
        entry["last_reset_by_peer_reason"] = m.group("reason")
        return True

    return False


def _parse_connection_info(
    lines: list[str], start_idx: int, entry: NeighborEntry
) -> None:
    """Parse local/foreign host and fd from lines after AF sections."""
    for line in lines[start_idx:]:
        m = _LOCAL_HOST_RE.match(line)
        if m:
            entry["local_host"] = m.group("host")
            entry["local_port"] = int(m.group("port"))
            continue

        m = _FOREIGN_HOST_RE.match(line)
        if m:
            entry["foreign_host"] = m.group("host")
            entry["foreign_port"] = int(m.group("port"))
            continue

        m = _FD_RE.match(line)
        if m:
            entry["fd"] = int(m.group("fd"))


def _build_initial_entry(header_m: re.Match[str]) -> NeighborEntry:
    """Build an initial NeighborEntry from a parsed header match."""
    entry: NeighborEntry = {
        "remote_as": int(header_m.group("remote_as")),
        "link_type": header_m.group("link_type"),
        "peer_index": int(header_m.group("peer_index")),
        "bgp_version": 4,
        "router_id": _DEFAULT_ROUTER_ID,
        "bgp_state": "Unknown",
        "hold_time": 0,
        "keepalive_interval": 0,
        "last_read": "",
        "last_written": "",
        "msgs_sent": 0,
        "msgs_rcvd": 0,
        "notifications_sent": 0,
        "notifications_rcvd": 0,
        "bytes_in_queue_sent": 0,
        "bytes_in_queue_rcvd": 0,
        "connections_established": 0,
        "connections_dropped": 0,
        "message_stats": _build_empty_message_stats(),
        "address_families": {},
    }
    if header_m.group("local_as"):
        entry["local_as"] = int(header_m.group("local_as"))
    return entry


def _scan_neighbor_lines(
    lines: list[str], entry: NeighborEntry
) -> tuple[int | None, int | None]:
    """Scan neighbor lines for field values and section boundaries.

    Returns (msg_stats_start, af_start) indices.
    """
    msg_stats_start: int | None = None
    af_start: int | None = None

    for idx, line in enumerate(lines[1:], start=1):
        if "Message statistics:" in line:
            msg_stats_start = idx
            continue

        if _AF_HEADER_RE.match(line):
            af_start = idx
            break

        _try_parse_header_fields(line, entry)
        _try_parse_transport_fields(line, entry)
        _try_parse_timer_msg_fields(line, entry)

    return msg_stats_start, af_start


def _parse_neighbor_block(lines: list[str]) -> NeighborEntry:
    """Parse a single neighbor block into a NeighborEntry."""
    header_m = _NEIGHBOR_HEADER_RE.match(lines[0])
    if not header_m:
        msg = f"Invalid neighbor header: {lines[0]}"
        raise ValueError(msg)

    entry = _build_initial_entry(header_m)
    msg_stats_start, af_start = _scan_neighbor_lines(lines, entry)

    if msg_stats_start is not None:
        entry["message_stats"] = _parse_message_stats(lines, msg_stats_start)

    if af_start is not None:
        entry["address_families"] = _parse_address_families(lines, af_start)
        _parse_connection_info(lines, af_start, entry)

    return entry


def _split_vrf_blocks(
    output: str,
) -> list[tuple[str, str]]:
    """Split output into per-VRF blocks.

    Returns list of (vrf_name, block_text) tuples.
    """
    blocks: list[tuple[str, str]] = []
    current_vrf: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _VRF_HEADER_RE.match(line)
        if m:
            if current_vrf is not None:
                blocks.append((current_vrf, "\n".join(current_lines)))
            current_vrf = m.group("vrf")
            current_lines = []
        else:
            current_lines.append(line)

    if current_vrf is not None:
        blocks.append((current_vrf, "\n".join(current_lines)))

    # If no VRF headers found, treat entire output as "default" VRF
    if not blocks:
        blocks.append(("default", output))

    return blocks


def _split_neighbor_blocks(
    text: str,
) -> list[tuple[str, list[str]]]:
    """Split a single VRF block into per-neighbor blocks.

    Returns list of (neighbor_ip, lines) tuples.
    """
    blocks: list[tuple[str, list[str]]] = []
    current_ip: str | None = None
    current_lines: list[str] = []

    for line in text.splitlines():
        m = _NEIGHBOR_HEADER_RE.match(line)
        if m:
            if current_ip is not None:
                blocks.append((current_ip, current_lines))
            current_ip = m.group("neighbor")
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_ip is not None:
        blocks.append((current_ip, current_lines))

    return blocks


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_NXOS, "show bgp vrf all all neighbors")
class ShowBgpVrfAllAllNeighborsParser(
    BaseParser["ShowBgpVrfAllAllNeighborsResult"],
):
    """Parser for 'show bgp vrf all all neighbors' on NX-OS.

    Parses BGP neighbor detail output across all VRFs, nested by
    VRF name and then neighbor IP address.
    """

    @classmethod
    def parse(cls, output: str) -> ShowBgpVrfAllAllNeighborsResult:
        """Parse 'show bgp vrf all all neighbors' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BGP neighbor information keyed by VRF then neighbor.
        """
        vrf_blocks = _split_vrf_blocks(output)
        vrfs: dict[str, dict[str, NeighborEntry]] = {}

        for vrf_name, vrf_text in vrf_blocks:
            neighbor_blocks = _split_neighbor_blocks(vrf_text)
            neighbors: dict[str, NeighborEntry] = {}
            for neighbor_ip, block_lines in neighbor_blocks:
                neighbors[neighbor_ip] = _parse_neighbor_block(block_lines)
            if neighbors:
                vrfs[vrf_name] = neighbors

        return {"vrfs": vrfs}
