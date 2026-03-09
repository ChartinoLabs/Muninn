"""Parser for 'show ip bgp neighbors' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


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
    total_sent: int
    total_rcvd: int


class PrefixActivity(TypedDict):
    """Schema for per-AF prefix activity."""

    prefixes_current_sent: int
    prefixes_current_rcvd: int
    prefixes_total_sent: int
    prefixes_total_rcvd: int
    implicit_withdraw_sent: int
    implicit_withdraw_rcvd: int
    explicit_withdraw_sent: int
    explicit_withdraw_rcvd: int
    used_as_bestpath: int
    used_as_multipath: int


class AddressFamilyInfo(TypedDict):
    """Schema for per-address-family information."""

    table_version: int
    neighbor_version: int
    peer_group: NotRequired[str]
    inbound_soft_reconfig: NotRequired[bool]
    community_attr_sent: NotRequired[bool]
    prefix_activity: NotRequired[PrefixActivity]


class NeighborEntry(TypedDict):
    """Schema for a single BGP neighbor."""

    remote_as: int
    local_as: NotRequired[int]
    link_type: str
    vrf: NotRequired[str]
    description: NotRequired[str]
    peer_group: NotRequired[str]
    bgp_version: int
    router_id: str
    bgp_state: str
    state_duration: NotRequired[str]
    hold_time: int
    keepalive_interval: int
    last_read: str
    last_write: str
    message_stats: MessageStats
    connections_established: int
    connections_dropped: int
    last_reset: NotRequired[str]
    address_families: dict[str, AddressFamilyInfo]
    local_host: NotRequired[str]
    local_port: NotRequired[int]
    foreign_host: NotRequired[str]
    foreign_port: NotRequired[int]


class ShowIpBgpNeighborsResult(TypedDict):
    """Schema for 'show ip bgp neighbors' parsed output on IOS-XE."""

    neighbors: dict[str, NeighborEntry]


# --- Compiled regex patterns ---

_NEIGHBOR_HEADER_RE = re.compile(
    r"^BGP neighbor is (?P<neighbor>\S+),\s+"
    r"(?:vrf (?P<vrf>\S+),\s+)?"
    r"remote AS (?P<remote_as>\d+),\s+"
    r"(?:local AS (?P<local_as>\d+),\s+)?"
    r"(?P<link_type>\S+) link"
)

_PEER_GROUP_RE = re.compile(
    r"^\s*Member of peer-group (?P<group>\S+) for session parameters"
)

_DESCRIPTION_RE = re.compile(r"^\s*Description:\s+(?P<desc>.+)$")

_BGP_VERSION_RE = re.compile(
    r"^\s+BGP version (?P<version>\d+),\s+"
    r"remote router ID (?P<router_id>\S+)"
)

_BGP_STATE_UP_RE = re.compile(
    r"^\s+BGP state = (?P<state>\S+),\s+up for (?P<duration>\S+)"
)

_BGP_STATE_DOWN_RE = re.compile(
    r"^\s+BGP state = (?P<state>\S+),"
    r"\s+down for (?P<duration>\S+)"
)

_BGP_STATE_SIMPLE_RE = re.compile(r"^\s+BGP state = (?P<state>\S+)")

_LAST_READ_RE = re.compile(
    r"^\s+Last read (?P<last_read>\S+),\s+"
    r"last write (?P<last_write>\S+),\s+"
    r"hold time is (?P<hold_time>\d+),\s+"
    r"keepalive interval is (?P<keepalive>\d+) seconds"
)

_CONNECTIONS_RE = re.compile(
    r"^\s+Connections established (?P<established>\d+);\s+"
    r"dropped (?P<dropped>\d+)"
)

_LAST_RESET_RE = re.compile(r"^\s+Last reset (?P<reset>.+)$")

_MSG_STAT_RE = re.compile(r"^\s+(?P<label>[\w ]+?):\s+(?P<sent>\d+)\s+(?P<rcvd>\d+)")

_AF_HEADER_RE = re.compile(r"^\s*For address family:\s+(?P<af>.+?)\s*$")

_AF_TABLE_VERSION_RE = re.compile(
    r"^\s+BGP table version (?P<table_ver>\d+),\s+"
    r"neighbor version (?P<nbr_ver>\d+)"
)

_AF_PEER_GROUP_RE = re.compile(r"^\s+(?P<group>\S+) peer-group member")

_AF_INBOUND_SOFT_RE = re.compile(r"^\s+Inbound soft reconfiguration allowed")

_AF_COMMUNITY_RE = re.compile(r"^\s+Community attribute sent to this neighbor")

_PREFIX_ROW_RE = re.compile(r"^\s+(?P<label>[\w ]+?):\s+(?P<sent>\S+)\s+(?P<rcvd>\S+)")

_LOCAL_HOST_RE = re.compile(
    r"^Local host:\s+(?P<host>\S+),\s+Local port:\s+(?P<port>\d+)"
)

_FOREIGN_HOST_RE = re.compile(
    r"^Foreign host:\s+(?P<host>\S+),\s+Foreign port:\s+(?P<port>\d+)"
)


def _split_neighbor_blocks(
    output: str,
) -> list[tuple[str, list[str]]]:
    """Split output into per-neighbor blocks.

    Returns list of (neighbor_ip, lines) tuples.
    """
    blocks: list[tuple[str, list[str]]] = []
    current_ip: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
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
        "total_sent": 0,
        "total_rcvd": 0,
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

    def _g(key: str) -> tuple[int, int]:
        return stats.get(key, (0, 0))

    o, n, u = _g("Opens"), _g("Notifications"), _g("Updates")
    k, rr, t = _g("Keepalives"), _g("Route Refresh"), _g("Total")

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
        "total_sent": t[0],
        "total_rcvd": t[1],
    }


def _safe_int(value: str) -> int:
    """Convert a string to int, returning 0 for non-numeric sentinel values."""
    stripped = value.strip()
    if not stripped or stripped in ("----", "n/a", "--"):
        return 0
    # Handle values like "113 (Consumes 6328 bytes)"
    parts = stripped.split()
    return int(parts[0])


def _parse_prefix_activity(
    lines: list[str], start_idx: int
) -> tuple[PrefixActivity | None, int]:
    """Parse prefix activity table. Returns (activity, next_idx)."""
    idx = start_idx
    rows: dict[str, tuple[str, str]] = {}

    # Find "Sent  Rcvd" header
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("Prefix activity:"):
            idx += 1
            break
        # Stop if we hit something that isn't part of prefix section
        if _AF_HEADER_RE.match(lines[idx]) or _NEIGHBOR_HEADER_RE.match(lines[idx]):
            return None, idx
        idx += 1
    else:
        return None, idx

    # Parse rows
    while idx < len(lines):
        m = _PREFIX_ROW_RE.match(lines[idx])
        if not m:
            break
        label = m.group("label").strip()
        rows[label] = (m.group("sent"), m.group("rcvd"))
        idx += 1

    if not rows:
        return None, idx

    def _gp(key: str) -> tuple[str, str]:
        return rows.get(key, ("0", "0"))

    cur = _gp("Prefixes Current")
    tot = _gp("Prefixes Total")
    imp = _gp("Implicit Withdraw")
    exp = _gp("Explicit Withdraw")
    best = _gp("Used as bestpath")
    multi = _gp("Used as multipath")

    activity: PrefixActivity = {
        "prefixes_current_sent": _safe_int(cur[0]),
        "prefixes_current_rcvd": _safe_int(cur[1]),
        "prefixes_total_sent": _safe_int(tot[0]),
        "prefixes_total_rcvd": _safe_int(tot[1]),
        "implicit_withdraw_sent": _safe_int(imp[0]),
        "implicit_withdraw_rcvd": _safe_int(imp[1]),
        "explicit_withdraw_sent": _safe_int(exp[0]),
        "explicit_withdraw_rcvd": _safe_int(exp[1]),
        "used_as_bestpath": _safe_int(best[1]),
        "used_as_multipath": _safe_int(multi[1]),
    }

    return activity, idx


def _apply_af_line(entry: AddressFamilyInfo, line: str) -> bool:
    """Try to match an AF-level line. Return True if matched."""
    m = _AF_TABLE_VERSION_RE.match(line)
    if m:
        entry["table_version"] = int(m.group("table_ver"))
        entry["neighbor_version"] = int(m.group("nbr_ver").split("/")[0])
        return True

    m = _AF_PEER_GROUP_RE.match(line)
    if m:
        entry["peer_group"] = m.group("group")
        return True

    if _AF_INBOUND_SOFT_RE.match(line):
        entry["inbound_soft_reconfig"] = True
        return True

    if _AF_COMMUNITY_RE.match(line):
        entry["community_attr_sent"] = True
        return True

    return False


def _is_prefix_header(line: str) -> bool:
    """Check if a line is the Sent/Rcvd header before prefix activity."""
    stripped = line.strip()
    return stripped.startswith("Sent") and "Rcvd" in stripped


def _process_af_line(
    current_entry: AddressFamilyInfo | None,
    lines: list[str],
    idx: int,
) -> int:
    """Process a single AF line. Returns next index to process."""
    if current_entry is None:
        return idx + 1

    line = lines[idx]
    if _apply_af_line(current_entry, line):
        return idx + 1

    if _is_prefix_header(line):
        activity, next_idx = _parse_prefix_activity(lines, idx - 1)
        if activity is not None:
            current_entry["prefix_activity"] = activity
        return next_idx

    return idx + 1


def _parse_address_families(
    lines: list[str], start_idx: int
) -> dict[str, AddressFamilyInfo]:
    """Parse all address family sections from neighbor lines."""
    afs: dict[str, AddressFamilyInfo] = {}
    current_af: str | None = None
    current_entry: AddressFamilyInfo | None = None
    idx = start_idx

    while idx < len(lines):
        m = _AF_HEADER_RE.match(lines[idx])
        if m:
            if current_af is not None and current_entry is not None:
                afs[current_af] = current_entry
            current_af = m.group("af")
            current_entry = {"table_version": 0, "neighbor_version": 0}
            idx += 1
        else:
            idx = _process_af_line(current_entry, lines, idx)

    # Flush last AF
    if current_af is not None and current_entry is not None:
        afs[current_af] = current_entry

    return afs


def _try_parse_header_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match identity/state lines. Return True if matched."""
    m = _PEER_GROUP_RE.match(line)
    if m:
        entry["peer_group"] = m.group("group")
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

    return _try_parse_state_line(line, entry)


def _try_parse_state_line(line: str, entry: NeighborEntry) -> bool:
    """Try to match BGP state lines. Return True if matched."""
    m = _BGP_STATE_UP_RE.match(line)
    if m:
        entry["bgp_state"] = m.group("state")
        entry["state_duration"] = m.group("duration")
        return True

    m = _BGP_STATE_DOWN_RE.match(line)
    if m:
        entry["bgp_state"] = m.group("state")
        entry["state_duration"] = m.group("duration")
        return True

    m = _BGP_STATE_SIMPLE_RE.match(line)
    if m and entry["bgp_state"] == "Unknown":
        entry["bgp_state"] = m.group("state")
        return True

    return False


def _try_parse_timer_fields(line: str, entry: NeighborEntry) -> bool:
    """Try to match timer/connection lines. Return True if matched."""
    m = _LAST_READ_RE.match(line)
    if m:
        entry["last_read"] = m.group("last_read")
        entry["last_write"] = m.group("last_write")
        entry["hold_time"] = int(m.group("hold_time"))
        entry["keepalive_interval"] = int(m.group("keepalive"))
        return True

    m = _CONNECTIONS_RE.match(line)
    if m:
        entry["connections_established"] = int(m.group("established"))
        entry["connections_dropped"] = int(m.group("dropped"))
        return True

    m = _LAST_RESET_RE.match(line)
    if m:
        reset_val = m.group("reset").strip()
        if reset_val != "never":
            entry["last_reset"] = reset_val
        return True

    return False


def _try_parse_connection_line(line: str, entry: NeighborEntry) -> bool:
    """Try to match local/foreign host lines. Return True if matched."""
    m = _LOCAL_HOST_RE.match(line)
    if m:
        entry["local_host"] = m.group("host")
        entry["local_port"] = int(m.group("port"))
        return True

    m = _FOREIGN_HOST_RE.match(line)
    if m:
        entry["foreign_host"] = m.group("host")
        entry["foreign_port"] = int(m.group("port"))
        return True

    return False


_DEFAULT_ROUTER_ID = "0.0.0.0"  # nosec B104 - BGP default, not a bind address


def _build_initial_entry(header_m: re.Match[str]) -> NeighborEntry:
    """Build an initial NeighborEntry from a parsed header match."""
    entry: NeighborEntry = {
        "remote_as": int(header_m.group("remote_as")),
        "link_type": header_m.group("link_type"),
        "bgp_version": 4,
        "router_id": _DEFAULT_ROUTER_ID,
        "bgp_state": "Unknown",
        "hold_time": 0,
        "keepalive_interval": 0,
        "last_read": "",
        "last_write": "",
        "message_stats": _build_empty_message_stats(),
        "connections_established": 0,
        "connections_dropped": 0,
        "address_families": {},
    }
    vrf = header_m.group("vrf")
    if vrf:
        entry["vrf"] = vrf
    local_as = header_m.group("local_as")
    if local_as:
        entry["local_as"] = int(local_as)
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
        _try_parse_timer_fields(line, entry)

    return msg_stats_start, af_start


def _parse_post_af_lines(lines: list[str], af_start: int, entry: NeighborEntry) -> None:
    """Parse connection info and other post-AF-section lines."""
    for line in lines[af_start:]:
        _try_parse_timer_fields(line, entry)
        _try_parse_connection_line(line, entry)


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
        _parse_post_af_lines(lines, af_start, entry)

    return entry


@register(OS.CISCO_IOSXE, "show ip bgp neighbors")
@register(OS.CISCO_IOSXE, "show ip bgp all neighbors")
@register(OS.CISCO_IOSXE, "show bgp neighbors")
@register(OS.CISCO_IOSXE, "show bgp all neighbors")
class ShowIpBgpNeighborsParser(BaseParser["ShowIpBgpNeighborsResult"]):
    """Parser for 'show ip bgp neighbors' on IOS-XE.

    Example output:
        BGP neighbor is 20.30.255.14,  remote AS 1255, internal link
         Member of peer-group RR_SERVERS for session parameters
          BGP version 4, remote router ID 20.40.1.1
          BGP state = Established, up for 7w3d
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpNeighborsResult:
        """Parse 'show ip bgp neighbors' output.

        Args:
            output: Raw CLI output from 'show ip bgp neighbors' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        blocks = _split_neighbor_blocks(output)
        neighbors: dict[str, NeighborEntry] = {}

        for neighbor_ip, block_lines in blocks:
            neighbors[neighbor_ip] = _parse_neighbor_block(block_lines)

        return {"neighbors": neighbors}
