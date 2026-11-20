"""Parser for 'show ip ospf neighbor detail' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class RetransmissionStats(TypedDict):
    """Retransmission scan statistics."""

    last_scan_length: int
    max_scan_length: int
    last_scan_time_msec: int
    max_scan_time_msec: int


class InterfaceNeighborEntry(TypedDict):
    """Schema for a neighbor on a specific interface."""

    interface_address: str
    area: str
    interface: str
    priority: int
    state: str
    state_changes: int
    dr: str
    bdr: str
    dead_timer: str
    uptime: str
    retransmission_queue_length: int
    retransmission_count: int
    retransmission_stats: RetransmissionStats
    interface_id: NotRequired[int]
    sr_adj_label: NotRequired[int]
    hello_options: NotRequired[str]
    dbd_options: NotRequired[str]
    lls_options: NotRequired[str]


class ShowIpOspfNeighborDetailResult(TypedDict):
    """Schema for 'show ip ospf neighbor detail' parsed output."""

    neighbors: dict[str, dict[str, InterfaceNeighborEntry]]


# --- Neighbor header ---
_NEIGHBOR_RE = re.compile(
    r"^\s*Neighbor\s+(\S+),\s+interface address\s+(\S+)"
    r"(?:,\s+interface-id\s+(\S+))?\s*$"
)

# --- Area and interface ---
_AREA_INTF_RE = re.compile(r"^\s*In the area\s+(\S+)\s+via interface\s+(\S+)\s*$")

# --- Priority, state, state changes ---
_STATE_RE = re.compile(
    r"^\s*Neighbor priority is\s+(\d+),\s+State is\s+(\S+),"
    r"\s+(\d+)\s+state changes?\s*$"
)

# --- DR / BDR ---
_DR_BDR_RE = re.compile(r"^\s*DR is\s+(\S+)\s+BDR is\s+(\S+)\s*$")

# --- SR adj label ---
_SR_LABEL_RE = re.compile(r"^\s*SR adj label\s+(\d+)\s*$")

# --- Options in Hello ---
_HELLO_OPTIONS_RE = re.compile(
    r"^\s*Options is\s+(\S+(?:\s+in\s+Hello\s+\(.*?\))?)\s*$"
)
_OPTIONS_HELLO_RE = re.compile(r"^\s*Options is\s+(\S+)\s+in\s+Hello\s+(\(.*?\))\s*$")
_OPTIONS_DBD_RE = re.compile(r"^\s*Options is\s+(\S+)\s+in\s+DBD\s+(\(.*?\))\s*$")
_OPTIONS_PLAIN_RE = re.compile(r"^\s*Options is\s+(\S+)\s*$")

# --- LLS Options ---
_LLS_OPTIONS_RE = re.compile(r"^\s*LLS Options is\s+(.+?)\s*$")

# --- Dead timer ---
_DEAD_TIMER_RE = re.compile(r"^\s*Dead timer due in\s+(\S+)\s*$")

# --- Uptime ---
_UPTIME_RE = re.compile(r"^\s*Neighbor is up for\s+(\S+)\s*$")

# --- Index / retransmission queue ---
_INDEX_RE = re.compile(
    r"^\s*Index\s+\S+,\s+retransmission queue length\s+(\d+),"
    r"\s+number of retransmission\s+(\d+)\s*$"
)

# --- Retransmission scan length ---
_RETX_SCAN_LEN_RE = re.compile(
    r"^\s*Last retransmission scan length is\s+(\d+),"
    r"\s+maximum is\s+(\d+)\s*$"
)

# --- Retransmission scan time ---
_RETX_SCAN_TIME_RE = re.compile(
    r"^\s*Last retransmission scan time is\s+(\d+)\s+msec,"
    r"\s+maximum is\s+(\d+)\s+msec\s*$"
)


def _split_neighbor_blocks(output: str) -> list[list[str]]:
    """Split output into per-neighbor blocks.

    Each block starts with a line matching 'Neighbor <id>, interface address ...'.
    """
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in output.splitlines():
        if _NEIGHBOR_RE.match(line):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)

    if current:
        blocks.append(current)

    return blocks


def _parse_core_fields(lines: list[str], entry: dict) -> str:
    """Parse area, interface, state, DR/BDR, and SR label fields.

    Returns:
        The canonical interface name.
    """
    interface_name = ""

    for line in lines:
        m = _AREA_INTF_RE.match(line)
        if m:
            entry["area"] = m.group(1)
            interface_name = canonical_interface_name(m.group(2), os=OS.CISCO_IOS)
            entry["interface"] = interface_name
            continue

        m = _STATE_RE.match(line)
        if m:
            entry["priority"] = int(m.group(1))
            entry["state"] = m.group(2)
            entry["state_changes"] = int(m.group(3))
            continue

        m = _DR_BDR_RE.match(line)
        if m:
            entry["dr"] = m.group(1)
            entry["bdr"] = m.group(2)
            continue

        m = _SR_LABEL_RE.match(line)
        if m:
            entry["sr_adj_label"] = int(m.group(1))

    return interface_name


def _parse_options(lines: list[str], entry: dict) -> None:
    """Parse OSPF options (Hello, DBD, LLS)."""
    options_seen_hello = False

    for line in lines:
        m = _OPTIONS_HELLO_RE.match(line)
        if m:
            entry["hello_options"] = f"{m.group(1)} {m.group(2)}"
            options_seen_hello = True
            continue

        m = _OPTIONS_DBD_RE.match(line)
        if m:
            entry["dbd_options"] = f"{m.group(1)} {m.group(2)}"
            continue

        if not options_seen_hello:
            m = _OPTIONS_PLAIN_RE.match(line)
            if m:
                entry["hello_options"] = m.group(1)
                continue

        m = _LLS_OPTIONS_RE.match(line)
        if m:
            entry["lls_options"] = m.group(1)


def _parse_timers_and_retransmission(lines: list[str], entry: dict) -> None:
    """Parse dead timer, uptime, and retransmission statistics."""
    for line in lines:
        m = _DEAD_TIMER_RE.match(line)
        if m:
            entry["dead_timer"] = m.group(1)
            continue

        m = _UPTIME_RE.match(line)
        if m:
            entry["uptime"] = m.group(1)
            continue

        m = _INDEX_RE.match(line)
        if m:
            entry["retransmission_queue_length"] = int(m.group(1))
            entry["retransmission_count"] = int(m.group(2))
            continue

        m = _RETX_SCAN_LEN_RE.match(line)
        if m:
            stats = entry.setdefault("retransmission_stats", {})
            stats["last_scan_length"] = int(m.group(1))
            stats["max_scan_length"] = int(m.group(2))
            continue

        m = _RETX_SCAN_TIME_RE.match(line)
        if m:
            stats = entry.setdefault("retransmission_stats", {})
            stats["last_scan_time_msec"] = int(m.group(1))
            stats["max_scan_time_msec"] = int(m.group(2))


def _parse_block(lines: list[str]) -> tuple[str, str, InterfaceNeighborEntry] | None:
    """Parse a single neighbor block.

    Returns:
        Tuple of (neighbor_id, interface_name, entry) or None if unparseable.
    """
    if not lines:
        return None

    header = _NEIGHBOR_RE.match(lines[0])
    if not header:
        return None

    neighbor_id = header.group(1)
    interface_address = header.group(2)
    interface_id_raw = header.group(3)

    entry: dict = {"interface_address": interface_address}

    if interface_id_raw is not None and interface_id_raw != "unknown":
        entry["interface_id"] = int(interface_id_raw)

    body = lines[1:]
    interface_name = _parse_core_fields(body, entry)
    _parse_options(body, entry)
    _parse_timers_and_retransmission(body, entry)

    return neighbor_id, interface_name, cast(InterfaceNeighborEntry, entry)


@register(OS.CISCO_IOS, "show ip ospf neighbor detail")
class ShowIpOspfNeighborDetailParser(
    BaseParser[ShowIpOspfNeighborDetailResult],
):
    """Parser for 'show ip ospf neighbor detail' on IOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNeighborDetailResult:
        """Parse 'show ip ospf neighbor detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed OSPF neighbor details keyed by neighbor router ID,
            then by interface name.

        Raises:
            ValueError: If no OSPF neighbor entries found in output.
        """
        blocks = _split_neighbor_blocks(output)
        neighbors: dict[str, dict[str, InterfaceNeighborEntry]] = {}

        for block_lines in blocks:
            result = _parse_block(block_lines)
            if result is None:
                continue
            neighbor_id, intf_name, entry = result
            neighbors.setdefault(neighbor_id, {})[intf_name] = entry

        if not neighbors:
            msg = "No OSPF neighbor detail entries found in output"
            raise ValueError(msg)

        return {"neighbors": neighbors}
