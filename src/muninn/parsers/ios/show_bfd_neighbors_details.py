"""Parser for 'show bfd neighbors details' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class BfdTimers(TypedDict):
    """BFD timer negotiated values."""

    tx_interval_ms: int
    rx_interval_ms: int
    multiplier: int


class BfdRegisteredProtocol(TypedDict):
    """A protocol registered for BFD on this session."""

    name: str


class BfdSessionEntry(TypedDict):
    """Schema for a single BFD session on an interface."""

    local_address: str
    neighbor_address: str
    interface: str
    state: str
    session_type: NotRequired[str]
    ld_rd: NotRequired[str]
    rh_rs: NotRequired[str]
    holddown_ms: NotRequired[int]
    timers: NotRequired[BfdTimers]
    registered_protocols: NotRequired[list[str]]
    uptime: NotRequired[str]
    last_packet_received_ms: NotRequired[int]
    rx_count: NotRequired[int]
    tx_count: NotRequired[int]
    round_trip_timer_ms: NotRequired[int]
    echo_tx_interval_ms: NotRequired[int]


class ShowBfdNeighborsDetailsResult(TypedDict):
    """Schema for 'show bfd neighbors details' parsed output.

    Keyed by neighbor address, then by interface name.
    """

    neighbors: dict[str, dict[str, BfdSessionEntry]]


# --- Block splitting ---
_NEIGHBOR_HEADER_RE = re.compile(r"^NeighAddr\b", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^-{3,}$")

# --- Neighbor summary line (first data line in a block) ---
# Header: NeighAddr  LD/RD  RH/RS  State  Int
# Example: 10.1.1.2  4097/4097  Up  Up  Gi0/0/1
_SUMMARY_LINE_RE = re.compile(
    r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)"
    r"\s+(?P<ld_rd>\d+/\d+)"
    r"\s+(?P<rh_rs>\S+)"
    r"\s+(?P<state>\S+)"
    r"\s+(?P<interface>\S+)"
)

# --- Detail fields ---
_SESSION_STATE_RE = re.compile(
    r"Session state is\s+(\S+)\s+and using echo function with\s+(\d+)\s+ms interval",
)
_SESSION_STATE_SIMPLE_RE = re.compile(r"Session state is\s+(\S+)")
_OUR_ADDR_RE = re.compile(r"OurAddr:\s*(\S+)")
_MIN_TX_RE = re.compile(r"MinTxInt:\s*(\d+)")
_MIN_RX_RE = re.compile(r"MinRxInt:\s*(\d+)")
_MULTIPLIER_RE = re.compile(r"Multiplier:\s*(\d+)")
_HOLDDOWN_RE = re.compile(r"Holddown\s*\(hits\):\s*(\d+)")
_RX_COUNT_RE = re.compile(r"Rx Count:\s*(\d+)")
_TX_COUNT_RE = re.compile(r"Tx Count:\s*(\d+)")
_ECHO_TX_RE = re.compile(r"Echo Tx Int:\s*(\d+)")
_UPTIME_RE = re.compile(r"Uptime:\s*(\S+)")
_LAST_PKT_RE = re.compile(r"Last packet received:\s*(\d+)\s*ms\s+ago")
_REGISTERED_PROTOCOLS_RE = re.compile(r"Registered protocols:\s*(.+)")
_ROUND_TRIP_RE = re.compile(r"Round trip timer:\s*(\d+)")
_SESSION_TYPE_RE = re.compile(r"Type:\s*(\S+)")


def _split_into_blocks(output: str) -> list[list[str]]:
    """Split output into per-neighbor blocks.

    Each block starts with a neighbor summary line (IP address at column 0)
    and ends before the next header/separator or neighbor summary.
    """
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in output.splitlines():
        stripped = line.strip()

        # Skip empty lines, headers, and separators
        if not stripped:
            continue
        if _NEIGHBOR_HEADER_RE.match(stripped):
            continue
        if _SEPARATOR_RE.match(stripped):
            continue

        # New neighbor block starts with an IP address at the beginning
        if _SUMMARY_LINE_RE.match(stripped):
            if current:
                blocks.append(current)
            current = [stripped]
        elif current:
            current.append(stripped)

    if current:
        blocks.append(current)

    return blocks


def _parse_session_state(line: str, entry: BfdSessionEntry) -> None:
    """Parse session state and echo interval from a detail line."""
    m = _SESSION_STATE_RE.search(line)
    if m:
        entry["state"] = m.group(1)
        entry["echo_tx_interval_ms"] = int(m.group(2))
        return

    m = _SESSION_STATE_SIMPLE_RE.search(line)
    if m:
        entry["state"] = m.group(1)


def _parse_counters_and_timers(line: str, entry: BfdSessionEntry) -> None:
    """Parse packet counters, holddown, uptime, and round-trip fields."""
    m = _HOLDDOWN_RE.search(line)
    if m:
        entry["holddown_ms"] = int(m.group(1))

    m = _UPTIME_RE.search(line)
    if m:
        entry["uptime"] = m.group(1)

    m = _LAST_PKT_RE.search(line)
    if m:
        entry["last_packet_received_ms"] = int(m.group(1))

    m = _RX_COUNT_RE.search(line)
    if m:
        entry["rx_count"] = int(m.group(1))

    m = _TX_COUNT_RE.search(line)
    if m:
        entry["tx_count"] = int(m.group(1))

    m = _ROUND_TRIP_RE.search(line)
    if m:
        entry["round_trip_timer_ms"] = int(m.group(1))


def _parse_bfd_intervals(line: str, entry: BfdSessionEntry) -> None:
    """Parse MinTxInt, MinRxInt, Multiplier, and standalone Echo Tx Int."""
    tx_match = _MIN_TX_RE.search(line)
    rx_match = _MIN_RX_RE.search(line)
    mult_match = _MULTIPLIER_RE.search(line)

    if tx_match:
        timers = entry.setdefault("timers", {})  # type: ignore[typeddict-item]
        timers["tx_interval_ms"] = int(tx_match.group(1))
    if rx_match:
        timers = entry.setdefault("timers", {})  # type: ignore[typeddict-item]
        timers["rx_interval_ms"] = int(rx_match.group(1))
    if mult_match:
        timers = entry.setdefault("timers", {})  # type: ignore[typeddict-item]
        timers["multiplier"] = int(mult_match.group(1))

    # Echo Tx Int on its own line (not part of "Session state is ... with N ms")
    if not _SESSION_STATE_RE.search(line):
        m = _ECHO_TX_RE.search(line)
        if m and "echo_tx_interval_ms" not in entry:
            entry["echo_tx_interval_ms"] = int(m.group(1))


def _parse_detail_fields(lines: list[str], entry: BfdSessionEntry) -> None:
    """Parse the detail lines following the summary line."""
    for line in lines:
        m = _OUR_ADDR_RE.search(line)
        if m:
            entry["local_address"] = m.group(1)

        _parse_session_state(line, entry)

        m = _SESSION_TYPE_RE.search(line)
        if m:
            entry["session_type"] = m.group(1)

        m = _REGISTERED_PROTOCOLS_RE.search(line)
        if m:
            protocols_raw = m.group(1).strip()
            protocols = [p.strip() for p in protocols_raw.split(",") if p.strip()]
            if protocols:
                entry["registered_protocols"] = protocols

        _parse_counters_and_timers(line, entry)
        _parse_bfd_intervals(line, entry)


def _parse_block(lines: list[str]) -> tuple[str, str, BfdSessionEntry] | None:
    """Parse a single neighbor block.

    Returns:
        Tuple of (neighbor_address, interface_name, entry) or None.
    """
    if not lines:
        return None

    summary_match = _SUMMARY_LINE_RE.match(lines[0])
    if not summary_match:
        return None

    neighbor_addr = summary_match.group("neighbor")
    ld_rd = summary_match.group("ld_rd")
    rh_rs = summary_match.group("rh_rs")
    state = summary_match.group("state")
    interface_raw = summary_match.group("interface")
    interface_name = canonical_interface_name(interface_raw, os=OS.CISCO_IOS)

    entry: BfdSessionEntry = {
        "local_address": "",
        "neighbor_address": neighbor_addr,
        "interface": interface_name,
        "state": state,
        "ld_rd": ld_rd,
        "rh_rs": rh_rs,
    }

    if len(lines) > 1:
        _parse_detail_fields(lines[1:], entry)

    # If local_address was not found in detail lines, remove the empty placeholder
    if entry.get("local_address") == "":
        del entry["local_address"]
        entry["local_address"] = neighbor_addr  # fallback

    return neighbor_addr, interface_name, entry


@register(OS.CISCO_IOS, "show bfd neighbors details")
class ShowBfdNeighborsDetailsParser(
    BaseParser[ShowBfdNeighborsDetailsResult],
):
    """Parser for 'show bfd neighbors details' on IOS.

    Parses BFD neighbor session details including state, timers,
    registered protocols, and session statistics.
    """

    @classmethod
    def parse(cls, output: str) -> ShowBfdNeighborsDetailsResult:
        """Parse 'show bfd neighbors details' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed BFD neighbor details keyed by neighbor address,
            then by interface name.

        Raises:
            ValueError: If no BFD neighbor entries found in output.
        """
        blocks = _split_into_blocks(output)
        neighbors: dict[str, dict[str, BfdSessionEntry]] = {}

        for block_lines in blocks:
            result = _parse_block(block_lines)
            if result is None:
                continue
            neighbor_addr, intf_name, entry = result
            neighbors.setdefault(neighbor_addr, {})[intf_name] = entry

        if not neighbors:
            msg = "No BFD neighbor detail entries found in output"
            raise ValueError(msg)

        return {"neighbors": neighbors}
