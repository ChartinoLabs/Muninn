"""Parser for 'show interface detail' command on Cisco FTD."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class InterfaceEntry(TypedDict):
    """Schema for a single FTD interface entry."""

    nameif: NotRequired[str]
    status: str
    line_protocol: str
    hardware: NotRequired[str]
    bandwidth_kbps: NotRequired[int]
    mac_address: NotRequired[str]
    mtu: NotRequired[int]
    ip_address: NotRequired[str]
    subnet_mask: NotRequired[str]
    vlan_id: NotRequired[int]
    description: NotRequired[str]
    packets_input: NotRequired[int]
    bytes_input: NotRequired[int]
    packets_output: NotRequired[int]
    bytes_output: NotRequired[int]
    packets_dropped: NotRequired[int]
    input_errors: NotRequired[int]
    output_errors: NotRequired[int]


class ShowInterfaceDetailResult(TypedDict):
    """Schema for 'show interface detail' parsed output."""

    interfaces: dict[str, InterfaceEntry]


# --- Interface header line ---
_INTF_HEADER_RE = re.compile(
    r'^Interface\s+(\S+)\s+"([^"]*)",\s+is\s+(.+?),\s+line protocol is\s+(\S+)\s*$'
)

# --- Hardware / BW (with BW in Mbps) ---
_HW_BW_RE = re.compile(r"^\s*Hardware is\s+(.*?),\s+BW\s+(\d+)\s+Mbps")
_HW_NOBW_RE = re.compile(r"^\s*Hardware is\s+(.+?)(?:,|\s*$)")

# --- MAC and MTU ---
_MAC_MTU_RE = re.compile(r"^\s*MAC address\s+([0-9a-f.]+),\s+MTU\s+(\d+)\s*$")
_MAC_NOMTU_RE = re.compile(r"^\s*MAC address\s+([0-9a-f.]+),\s+MTU\s+not set\s*$")

# --- IP address ---
_IP_ADDR_RE = re.compile(
    r"^\s*IP address\s+(\d+\.\d+\.\d+\.\d+),\s+subnet mask\s+(\d+\.\d+\.\d+\.\d+)\s*$"
)

# --- VLAN identifier ---
_VLAN_RE = re.compile(r"^\s*VLAN identifier\s+(\d+)\s*$")

# --- Description ---
_DESC_RE = re.compile(r"^\s*Description:\s+(.+?)\s*$")

# --- Data-plane counters (raw format) ---
_RAW_INPUT_RE = re.compile(
    r"^\s*(\d+)\s+packets input,\s+(\d+)\s+bytes,\s+\d+\s+no buffer\s*$"
)
_RAW_OUTPUT_RE = re.compile(
    r"^\s*(\d+)\s+packets output,\s+(\d+)\s+bytes,\s+\d+\s+underruns?\s*$"
)
_RAW_INPUT_ERRORS_RE = re.compile(r"^\s*(\d+)\s+input errors,")
_RAW_OUTPUT_ERRORS_RE = re.compile(r"^\s*(\d+)\s+output errors,")

# --- Traffic Statistics counters (logical interface format) ---
_TRAFFIC_INPUT_RE = re.compile(r"^\s*(\d+)\s+packets input,\s+(\d+)\s+bytes\s*$")
_TRAFFIC_OUTPUT_RE = re.compile(r"^\s*(\d+)\s+packets output,\s+(\d+)\s+bytes\s*$")
_TRAFFIC_DROPPED_RE = re.compile(r"^\s*(\d+)\s+packets dropped\s*$")


def _split_interface_blocks(output: str) -> list[tuple[str, str, list[str]]]:
    """Split output into per-interface blocks based on header lines.

    Returns:
        List of (interface_name, nameif, lines) tuples.
    """
    blocks: list[tuple[str, str, list[str]]] = []
    current_name: str | None = None
    current_nameif: str = ""
    current_lines: list[str] = []

    for line in output.splitlines():
        m = _INTF_HEADER_RE.match(line)
        if m:
            if current_name is not None:
                blocks.append((current_name, current_nameif, current_lines))
            current_name = m.group(1)
            current_nameif = m.group(2)
            current_lines = [line]
        elif current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        blocks.append((current_name, current_nameif, current_lines))

    return blocks


def _parse_header(line: str) -> dict:
    """Parse the interface header line for status and protocol."""
    m = _INTF_HEADER_RE.match(line)
    if not m:
        return {}
    return {
        "status": m.group(3).strip(),
        "line_protocol": m.group(4).strip(),
    }


def _parse_hardware_line(line: str, entry: dict) -> bool:
    """Parse hardware type and bandwidth from a line."""
    m = _HW_BW_RE.match(line)
    if m:
        hw = m.group(1).strip()
        if hw:
            entry["hardware"] = hw
        entry["bandwidth_kbps"] = int(m.group(2)) * 1000
        return True

    m = _HW_NOBW_RE.match(line)
    if m and "Hardware is" in line and "hardware" not in entry:
        hw = m.group(1).strip()
        if hw:
            entry["hardware"] = hw
        return True

    return False


def _parse_addressing_line(line: str, entry: dict) -> bool:
    """Parse MAC, MTU, IP, VLAN, and description from a line."""
    m = _MAC_MTU_RE.match(line)
    if m:
        entry["mac_address"] = m.group(1)
        entry["mtu"] = int(m.group(2))
        return True

    m = _MAC_NOMTU_RE.match(line)
    if m:
        entry["mac_address"] = m.group(1)
        return True

    m = _IP_ADDR_RE.match(line)
    if m:
        entry["ip_address"] = m.group(1)
        entry["subnet_mask"] = m.group(2)
        return True

    m = _VLAN_RE.match(line)
    if m:
        entry["vlan_id"] = int(m.group(1))
        return True

    m = _DESC_RE.match(line)
    if m:
        entry["description"] = m.group(1)
        return True

    return False


def _parse_properties(lines: list[str], entry: dict) -> None:
    """Parse hardware, MAC, MTU, IP, VLAN, and description from block lines."""
    for line in lines:
        if _parse_hardware_line(line, entry):
            continue
        _parse_addressing_line(line, entry)


def _parse_traffic_stats_line(line: str, entry: dict) -> bool:
    """Parse a single Traffic Statistics line (logical interface format)."""
    m = _TRAFFIC_INPUT_RE.match(line)
    if m:
        entry["packets_input"] = int(m.group(1))
        entry["bytes_input"] = int(m.group(2))
        return True

    m = _TRAFFIC_OUTPUT_RE.match(line)
    if m:
        entry["packets_output"] = int(m.group(1))
        entry["bytes_output"] = int(m.group(2))
        return True

    m = _TRAFFIC_DROPPED_RE.match(line)
    if m:
        entry["packets_dropped"] = int(m.group(1))
        return True

    return False


def _parse_raw_counter_line(line: str, entry: dict) -> bool:
    """Parse a single data-plane raw counter line."""
    m = _RAW_INPUT_RE.match(line)
    if m:
        entry["packets_input"] = int(m.group(1))
        entry["bytes_input"] = int(m.group(2))
        return True

    m = _RAW_OUTPUT_RE.match(line)
    if m:
        entry["packets_output"] = int(m.group(1))
        entry["bytes_output"] = int(m.group(2))
        return True

    m = _RAW_INPUT_ERRORS_RE.match(line)
    if m:
        entry["input_errors"] = int(m.group(1))
        return True

    m = _RAW_OUTPUT_ERRORS_RE.match(line)
    if m:
        entry["output_errors"] = int(m.group(1))
        return True

    return False


def _parse_counters(lines: list[str], entry: dict) -> None:
    """Parse traffic counters from interface block lines.

    Handles two formats:
    - Data-plane raw counters (packets input, N bytes, N no buffer)
    - Logical interface Traffic Statistics (packets input, N bytes)
    """
    in_traffic_stats = False

    for line in lines:
        if "Traffic Statistics for" in line:
            in_traffic_stats = True
            continue

        if in_traffic_stats:
            if _parse_traffic_stats_line(line, entry):
                continue
            if "Control Point" in line:
                in_traffic_stats = False
        else:
            _parse_raw_counter_line(line, entry)


def _parse_block(name: str, nameif: str, lines: list[str]) -> InterfaceEntry:
    """Parse a single interface block into an InterfaceEntry."""
    entry: dict = _parse_header(lines[0])

    if nameif:
        entry["nameif"] = nameif

    _parse_properties(lines, entry)
    _parse_counters(lines, entry)

    return InterfaceEntry(**entry)  # type: ignore[typeddict-item]


@register(OS.CISCO_FTD, "show interface detail")
class ShowInterfaceDetailParser(BaseParser[ShowInterfaceDetailResult]):
    """Parser for 'show interface detail' command on Cisco FTD.

    Parses detailed interface information including status, hardware,
    addressing, traffic counters, and configuration details for all
    interfaces on a Firepower Threat Defense appliance.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceDetailResult:
        """Parse 'show interface detail' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        blocks = _split_interface_blocks(output)

        if not blocks:
            msg = "No interfaces found in 'show interface detail' output"
            raise ValueError(msg)

        interfaces: dict[str, InterfaceEntry] = {}
        for name, nameif, block_lines in blocks:
            interfaces[name] = _parse_block(name, nameif, block_lines)

        return ShowInterfaceDetailResult(interfaces=interfaces)
