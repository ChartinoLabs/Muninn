"""Parser for 'show interface' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class RxCountersEntry(TypedDict):
    """Schema for interface RX counters."""

    unicast_packets: NotRequired[int]
    multicast_packets: NotRequired[int]
    broadcast_packets: NotRequired[int]
    bytes: NotRequired[int]
    input_packets: NotRequired[int]
    jumbo_packets: NotRequired[int]
    storm_suppression_packets: NotRequired[int]
    runts: NotRequired[int]
    giants: NotRequired[int]
    crc: NotRequired[int]
    no_buffer: NotRequired[int]
    input_errors: NotRequired[int]
    short_frame: NotRequired[int]
    overrun: NotRequired[int]
    underrun: NotRequired[int]
    ignored: NotRequired[int]
    watchdog: NotRequired[int]
    bad_etype_drop: NotRequired[int]
    bad_proto_drop: NotRequired[int]
    if_down_drop: NotRequired[int]
    input_with_dribble: NotRequired[int]
    input_discard: NotRequired[int]
    pause: NotRequired[int]


class TxCountersEntry(TypedDict):
    """Schema for interface TX counters."""

    unicast_packets: NotRequired[int]
    multicast_packets: NotRequired[int]
    broadcast_packets: NotRequired[int]
    bytes: NotRequired[int]
    output_packets: NotRequired[int]
    jumbo_packets: NotRequired[int]
    output_errors: NotRequired[int]
    collision: NotRequired[int]
    deferred: NotRequired[int]
    late_collision: NotRequired[int]
    lost_carrier: NotRequired[int]
    no_carrier: NotRequired[int]
    babble: NotRequired[int]
    output_discard: NotRequired[int]
    pause: NotRequired[int]


class InterfaceEntry(TypedDict):
    """Schema for a single NX-OS interface entry."""

    status: str
    line_protocol: NotRequired[str]
    admin_state: NotRequired[str]
    hardware: NotRequired[str]
    mtu: NotRequired[int]
    bandwidth_kbps: NotRequired[int]
    delay_usec: NotRequired[int]
    encapsulation: NotRequired[str]
    description: NotRequired[str]
    address: NotRequired[str]
    bia: NotRequired[str]
    ip_address: NotRequired[str]
    ip_prefix_length: NotRequired[int]
    reliability: NotRequired[str]
    txload: NotRequired[str]
    rxload: NotRequired[str]
    duplex: NotRequired[str]
    speed: NotRequired[str]
    media_type: NotRequired[str]
    port_mode: NotRequired[str]
    medium: NotRequired[str]
    beacon: NotRequired[str]
    interface_type: NotRequired[str]
    switchport_monitor: NotRequired[str]
    last_link_flapped: NotRequired[str]
    last_clearing: NotRequired[str]
    interface_resets: NotRequired[int]
    input_rate_bps: NotRequired[int]
    input_rate_pps: NotRequired[int]
    output_rate_bps: NotRequired[int]
    output_rate_pps: NotRequired[int]
    load_interval_1: NotRequired[int]
    load_interval_2: NotRequired[int]
    rx_counters: NotRequired[RxCountersEntry]
    tx_counters: NotRequired[TxCountersEntry]


class ShowInterfaceResult(TypedDict):
    """Schema for 'show interface' parsed output."""

    interfaces: dict[str, InterfaceEntry]


# --- Block delimiter: interface status line ---
_STATUS_RE = re.compile(r"^(\S+) is (.+?)(?:,\s*line protocol is (\S+))?\s*$")

# --- Admin state ---
_ADMIN_STATE_RE = re.compile(r"^\s*admin state is (\w+),?\s*(.*?)\s*$")

# --- Hardware / address ---
_HW_RE = re.compile(
    r"^\s*Hardware:\s*(.+?),"
    r"\s*address:\s*([0-9a-f.]+)\s*\(bia\s*([0-9a-f.]+)\)\s*$"
)
_HW_NO_ADDR_RE = re.compile(r"^\s*Hardware:\s*(.+?)\s*$")

# --- Description ---
_DESC_RE = re.compile(r"^\s*Description:\s*(.+?)\s*$")

# --- IP address ---
_IP_RE = re.compile(r"^\s*Internet Address is (\S+)/(\d+)\s*$")

# --- MTU / BW / DLY ---
_MTU_RE = re.compile(r"^\s*MTU (\d+) bytes,\s*BW (\d+) Kbit(?:/sec)?,\s*DLY (\d+) usec")

# --- Reliability / load ---
_RELIABILITY_RE = re.compile(
    r"^\s*reliability (\d+/\d+),\s*txload (\d+/\d+),\s*rxload (\d+/\d+)"
)

# --- Encapsulation ---
_ENCAP_RE = re.compile(r"^\s*Encapsulation (.+?)(?:,\s*medium is (.+))?\s*$")

# --- Port mode ---
_PORT_MODE_RE = re.compile(r"^\s*Port mode is (.+?)\s*$")

# --- Duplex / speed / media type ---
_DUPLEX_SPEED_RE = re.compile(
    r"^\s*([\w-]+)-duplex,\s*(.+?)(?:,\s*media type is (.+))?\s*$"
)
_AUTO_SPEED_RE = re.compile(r"^\s*auto-speed,\s*(.+?)(?:,\s*media type is (.+))?\s*$")

# --- Beacon ---
_BEACON_RE = re.compile(r"^\s*Beacon is turned (\S+)\s*$")

# --- Interface type ---
_INTF_TYPE_RE = re.compile(r"^\s*(?:Interface type|EtherType) is (.+?)\s*$")

# --- Switchport monitor ---
_SWITCHPORT_MON_RE = re.compile(r"^\s*Switchport monitor is (.+?)\s*$")

# --- Last link flapped ---
_LAST_FLAPPED_RE = re.compile(r"^\s*Last link flapped (.+?)\s*$")

# --- Last clearing ---
_LAST_CLEAR_RE = re.compile(r'^\s*Last clearing of "show interface" counters (.+?)\s*$')

# --- Interface resets ---
_RESETS_RE = re.compile(r"^\s*(\d+) interface resets\s*$")

# --- Load interval ---
_LOAD_INTERVAL_RE = re.compile(
    r"^\s*(?:\d+ seconds )?[Ll]oad-[Ii]nterval #(\d)\s+is\s+(\d+)\s+second"
)

# --- Rate lines ---
_RATE_INPUT_RE = re.compile(
    r"^\s*(?:\d+ seconds )?input rate\s+(\d+)\s+bits/sec,\s*(\d+)\s+packets/sec"
)
_RATE_OUTPUT_RE = re.compile(
    r"^\s*(?:\d+ seconds )?output rate\s+(\d+)\s+bits/sec,\s*(\d+)\s+packets/sec"
)

# --- RX/TX section headers ---
_RX_HEADER_RE = re.compile(r"^\s*RX\s*$")
_TX_HEADER_RE = re.compile(r"^\s*TX\s*$")

# --- Counter value patterns (within RX/TX blocks) ---
_COUNTER_LINE_RE = re.compile(r"(\d+)\s+([a-zA-Z][a-zA-Z/ ]*?)(?=\s{2,}|\s*$)")


# Map of counter field names from CLI output to our schema keys
_RX_FIELD_MAP: dict[str, str] = {
    "unicast packets": "unicast_packets",
    "multicast packets": "multicast_packets",
    "broadcast packets": "broadcast_packets",
    "bytes": "bytes",
    "input packets": "input_packets",
    "jumbo packets": "jumbo_packets",
    "storm suppression packets": "storm_suppression_packets",
    "storm suppression bytes": "storm_suppression_packets",
    "runts": "runts",
    "giants": "giants",
    "crc": "crc",
    "CRC/FCS": "crc",
    "no buffer": "no_buffer",
    "input error": "input_errors",
    "input errors": "input_errors",
    "short frame": "short_frame",
    "overrun": "overrun",
    "underrun": "underrun",
    "ignored": "ignored",
    "watchdog": "watchdog",
    "bad etype drop": "bad_etype_drop",
    "bad proto drop": "bad_proto_drop",
    "if down drop": "if_down_drop",
    "input with dribble": "input_with_dribble",
    "input discard": "input_discard",
    "Rx pause": "pause",
}

_TX_FIELD_MAP: dict[str, str] = {
    "unicast packets": "unicast_packets",
    "multicast packets": "multicast_packets",
    "broadcast packets": "broadcast_packets",
    "bytes": "bytes",
    "output packets": "output_packets",
    "jumbo packets": "jumbo_packets",
    "output error": "output_errors",
    "output errors": "output_errors",
    "collision": "collision",
    "deferred": "deferred",
    "late collision": "late_collision",
    "lost carrier": "lost_carrier",
    "no carrier": "no_carrier",
    "babble": "babble",
    "output discard": "output_discard",
    "Tx pause": "pause",
}


def _split_blocks(output: str) -> list[tuple[str, list[str]]]:
    """Split output into per-interface blocks based on status lines."""
    blocks: list[tuple[str, list[str]]] = []
    current_name: str | None = None
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _STATUS_RE.match(line)
        if m:
            if current_name is not None:
                blocks.append((current_name, current_lines))
            current_name = m.group(1)
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_lines))

    return blocks


def _parse_status_line(line: str) -> dict:
    """Parse the interface status/protocol line."""
    m = _STATUS_RE.match(line)
    if not m:
        return {}
    result: dict = {"status": m.group(2).strip()}
    if m.group(3):
        result["line_protocol"] = m.group(3)
    return result


def _parse_identity_fields(line: str, entry: dict) -> bool:
    """Parse admin state, hardware, description, and IP address fields."""
    m = _ADMIN_STATE_RE.match(line)
    if m:
        entry["admin_state"] = m.group(1)
        intf_type = m.group(2).strip()
        if intf_type:
            entry["interface_type"] = intf_type
        return True

    m = _HW_RE.match(line)
    if m:
        entry["hardware"] = m.group(1).strip()
        entry["address"] = m.group(2)
        entry["bia"] = m.group(3)
        return True

    m = _HW_NO_ADDR_RE.match(line)
    if m and "Hardware:" in line:
        entry["hardware"] = m.group(1).strip()
        return True

    m = _DESC_RE.match(line)
    if m:
        entry["description"] = m.group(1)
        return True

    m = _IP_RE.match(line)
    if m:
        entry["ip_address"] = m.group(1)
        entry["ip_prefix_length"] = int(m.group(2))
        return True

    return False


def _parse_layer1_fields(line: str, entry: dict) -> bool:
    """Parse MTU, bandwidth, delay, and reliability/load fields."""
    m = _MTU_RE.match(line)
    if m:
        entry["mtu"] = int(m.group(1))
        entry["bandwidth_kbps"] = int(m.group(2))
        entry["delay_usec"] = int(m.group(3))
        return True

    m = _RELIABILITY_RE.match(line)
    if m:
        entry["reliability"] = m.group(1)
        entry["txload"] = m.group(2)
        entry["rxload"] = m.group(3)
        return True

    return False


def _parse_encap_and_speed(line: str, entry: dict) -> bool:
    """Parse encapsulation, port mode, and duplex/speed fields."""
    m = _ENCAP_RE.match(line)
    if m and line.strip().startswith("Encapsulation"):
        entry["encapsulation"] = m.group(1)
        if m.group(2):
            entry["medium"] = m.group(2)
        return True

    m = _PORT_MODE_RE.match(line)
    if m:
        entry["port_mode"] = m.group(1)
        return True

    m = _DUPLEX_SPEED_RE.match(line)
    if m:
        entry["duplex"] = m.group(1) + "-duplex"
        entry["speed"] = m.group(2).strip()
        if m.group(3):
            entry["media_type"] = m.group(3).strip()
        return True

    m = _AUTO_SPEED_RE.match(line)
    if m:
        entry["speed"] = "auto-speed"
        if m.group(1):
            entry["media_type"] = m.group(1).strip()
        if m.group(2):
            entry["media_type"] = m.group(2).strip()
        return True

    return False


def _parse_port_attributes(line: str, entry: dict) -> bool:
    """Parse beacon, interface type, and switchport monitor fields."""
    m = _BEACON_RE.match(line)
    if m:
        entry["beacon"] = m.group(1)
        return True

    m = _INTF_TYPE_RE.match(line)
    if m:
        entry["interface_type"] = m.group(1)
        return True

    m = _SWITCHPORT_MON_RE.match(line)
    if m:
        entry["switchport_monitor"] = m.group(1)
        return True

    return False


def _parse_history_fields(line: str, entry: dict) -> bool:
    """Parse last link flapped, last clearing, and interface resets."""
    m = _LAST_FLAPPED_RE.match(line)
    if m:
        entry["last_link_flapped"] = m.group(1)
        return True

    m = _LAST_CLEAR_RE.match(line)
    if m:
        entry["last_clearing"] = m.group(1)
        return True

    m = _RESETS_RE.match(line)
    if m:
        entry["interface_resets"] = int(m.group(1))
        return True

    return False


def _parse_rate_fields(line: str, entry: dict) -> bool:
    """Parse load interval and input/output rate fields."""
    m = _LOAD_INTERVAL_RE.match(line)
    if m:
        interval_num = int(m.group(1))
        interval_sec = int(m.group(2))
        key = f"load_interval_{interval_num}"
        if key in ("load_interval_1", "load_interval_2"):
            entry[key] = interval_sec
        return True

    m = _RATE_INPUT_RE.match(line)
    if m:
        # Only capture rates from the first load interval
        if "input_rate_bps" not in entry:
            entry["input_rate_bps"] = int(m.group(1))
            entry["input_rate_pps"] = int(m.group(2))
        return True

    m = _RATE_OUTPUT_RE.match(line)
    if m:
        if "output_rate_bps" not in entry:
            entry["output_rate_bps"] = int(m.group(1))
            entry["output_rate_pps"] = int(m.group(2))
        return True

    return False


def _parse_counter_values(
    lines: list[str], field_map: dict[str, str]
) -> dict[str, int]:
    """Parse counter lines within an RX or TX section."""
    counters: dict[str, int] = {}
    for line in lines:
        for m in _COUNTER_LINE_RE.finditer(line):
            value = int(m.group(1))
            label = m.group(2).strip()
            if label in field_map:
                counters[field_map[label]] = value
    return counters


def _parse_rx_tx_counters(
    lines: list[str],
) -> tuple[RxCountersEntry | None, TxCountersEntry | None]:
    """Parse RX and TX counter sections from block lines."""
    rx_lines: list[str] = []
    tx_lines: list[str] = []
    section: str | None = None

    for line in lines:
        if _RX_HEADER_RE.match(line):
            section = "rx"
            continue
        if _TX_HEADER_RE.match(line):
            section = "tx"
            continue
        if section == "rx":
            rx_lines.append(line)
        elif section == "tx":
            tx_lines.append(line)

    rx_counters: RxCountersEntry | None = None
    tx_counters: TxCountersEntry | None = None

    if rx_lines:
        parsed_rx = _parse_counter_values(rx_lines, _RX_FIELD_MAP)
        if parsed_rx:
            rx_counters = parsed_rx  # type: ignore[assignment]

    if tx_lines:
        parsed_tx = _parse_counter_values(tx_lines, _TX_FIELD_MAP)
        if parsed_tx:
            tx_counters = parsed_tx  # type: ignore[assignment]

    return rx_counters, tx_counters


_LINE_PARSERS = (
    _parse_identity_fields,
    _parse_layer1_fields,
    _parse_encap_and_speed,
    _parse_port_attributes,
    _parse_history_fields,
    _parse_rate_fields,
)


def _parse_body_lines(lines: list[str], entry: dict) -> None:
    """Apply all line parsers to the body of an interface block."""
    for line in lines:
        if not line.strip():
            continue
        for parser_fn in _LINE_PARSERS:
            if parser_fn(line, entry):
                break


def _parse_block(lines: list[str]) -> InterfaceEntry | None:
    """Parse a single interface block into an InterfaceEntry."""
    if not lines:
        return None

    entry: dict = _parse_status_line(lines[0])
    if not entry:
        return None

    body = lines[1:]
    _parse_body_lines(body, entry)

    rx_counters, tx_counters = _parse_rx_tx_counters(body)
    if rx_counters:
        entry["rx_counters"] = rx_counters
    if tx_counters:
        entry["tx_counters"] = tx_counters

    return entry  # type: ignore[return-value]


@register(OS.CISCO_NXOS, "show interface")
class ShowInterfaceParser(BaseParser[ShowInterfaceResult]):
    """Parser for 'show interface' command on NX-OS.

    Parses detailed interface information including status, hardware,
    addressing, counters, and configuration details.
    """

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceResult:
        """Parse 'show interface' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        blocks = _split_blocks(output)
        interfaces: dict[str, InterfaceEntry] = {}

        for raw_name, block_lines in blocks:
            parsed = _parse_block(block_lines)
            if parsed is None:
                continue
            name = canonical_interface_name(raw_name, os=OS.CISCO_NXOS)
            interfaces[name] = parsed

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
