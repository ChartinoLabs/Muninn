"""Parser for 'show vlans' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Matches both "VLAN ID: <id>" and "Virtual LAN ID:  <id>" header lines
_VLAN_HEADER_RE = re.compile(
    r"^(?:Virtual\s+LAN\s+ID|VLAN\s+ID):\s+(\d+)\s+"
    r"\((?P<encapsulation>[^)]+)\)"
)

# Native VLAN indicator
_NATIVE_VLAN_RE = re.compile(r"^\s*This is configured as native Vlan")

# "Protocols Configured:" header (marks start of protocol counters section)
_PROTOCOLS_HEADER_RE = re.compile(r"^\s+Protocols Configured:")

# Trunk interface section header (newer format)
_TRUNK_SECTION_RE = re.compile(
    r"^VLAN\s+trunk\s+interfaces?\s+for\s+VLAN\s+ID\s+\d+\s*:"
)

# vLAN Trunk Interface(s): header (older format)
_VLAN_TRUNK_INTF_RE = re.compile(r"^\s+vLAN\s+Trunk\s+Interfaces?:")

# Interface with VLAN tag: "GigabitEthernet0/0/0 (1)" or
# "Port-channel14.5013017 (501/3017)"
_INTERFACE_TAG_RE = re.compile(r"^(\S+)\s+\((\S+)\)\s*$")

# Per-interface address line (newer format uses "PROTOCOL: address")
_INTF_ADDRESS_RE = re.compile(r"^\s+(?P<protocol>IP|IPv6|MPLS):\s+(?P<address>\S+)\s*$")

# Protocol counter line (works for both VLAN-level and per-interface)
_PROTOCOL_LINE_RE = re.compile(
    r"^\s+(?P<protocol>\S+)"
    r"(?:\s+(?P<address>\d+\.\d+\.\d+\.\d+|[0-9a-fA-F]+(?::[0-9a-fA-F]*)+))?"
    r"\s+(?P<received>\d+)"
    r"\s+(?P<transmitted>\d+)\s*$"
)

# Protocol line with address but NO counters (e.g., "IP  10.252.202.197")
_PROTOCOL_ADDR_ONLY_RE = re.compile(
    r"^\s+(?P<protocol>IP|IPv6|MPLS)\s+(?P<address>\S+)\s*$"
)

# Total traffic counters (newer format with "Total" prefix)
_TOTAL_PACKETS_RE = re.compile(
    r"^\s+Total\s+(?P<packets>\d+)\s+packets,\s+"
    r"(?P<bytes>\d+)\s+bytes\s+(?P<direction>input|output)"
)

# Summary traffic line (older format without "Total" prefix)
_SUMMARY_PACKETS_RE = re.compile(
    r"^\s+(?P<packets>\d+)\s+packets,\s+"
    r"(?P<bytes>\d+)\s+bytes\s+(?P<direction>input|output)"
)

# Oversubscription drops
_OVERSUB_RE = re.compile(
    r"^\s+Total\s+(?P<drops>\d+)\s+oversubscription\s+packet\s+drops"
)


class ProtocolCounterEntry(TypedDict):
    """Schema for protocol-level traffic counters."""

    received: int
    transmitted: int


class InterfaceEntry(TypedDict):
    """Schema for a single trunk interface within a VLAN."""

    interface: str
    vlan_tag: str
    addresses: NotRequired[dict[str, str]]
    packets_input: NotRequired[int]
    bytes_input: NotRequired[int]
    packets_output: NotRequired[int]
    bytes_output: NotRequired[int]
    oversubscription_drops: NotRequired[int]


class VlanEntry(TypedDict):
    """Schema for a single dot1q VLAN entry."""

    vlan_id: int
    encapsulation: str
    is_native: NotRequired[bool]
    protocols: NotRequired[dict[str, ProtocolCounterEntry]]
    interfaces: NotRequired[dict[str, InterfaceEntry]]


class ShowVlansResult(TypedDict):
    """Schema for 'show vlans' parsed output."""

    vlans: dict[str, VlanEntry]


class _ParseState:
    """Mutable state for the VLAN parsing loop."""

    __slots__ = ("vlans", "current_vlan", "current_intf", "in_protocols_section")

    def __init__(self) -> None:
        self.vlans: dict[str, VlanEntry] = {}
        self.current_vlan: VlanEntry | None = None
        self.current_intf: InterfaceEntry | None = None
        self.in_protocols_section: bool = False


def _set_traffic_stats(
    entry: InterfaceEntry, packets: int, byte_count: int, direction: str
) -> None:
    """Set traffic statistics on an interface entry."""
    if direction == "input":
        entry["packets_input"] = packets
        entry["bytes_input"] = byte_count
    else:
        entry["packets_output"] = packets
        entry["bytes_output"] = byte_count


def _handle_vlan_header(stripped: str, state: _ParseState) -> bool:
    """Process a VLAN header line. Returns True if matched."""
    header_match = _VLAN_HEADER_RE.match(stripped)
    if not header_match:
        return False

    vlan_id_str = header_match.group(1)
    encapsulation = header_match.group("encapsulation")
    state.current_vlan = {
        "vlan_id": int(vlan_id_str),
        "encapsulation": encapsulation,
    }
    state.vlans[vlan_id_str] = state.current_vlan
    state.current_intf = None
    state.in_protocols_section = False
    return True


def _handle_interface_tag(stripped: str, state: _ParseState) -> bool:
    """Process an interface tag line. Returns True if matched."""
    tag_match = _INTERFACE_TAG_RE.match(stripped)
    if not tag_match or state.current_vlan is None:
        return False

    raw_intf = tag_match.group(1)
    vlan_tag = tag_match.group(2)
    intf_name = canonical_interface_name(raw_intf, os=OS.CISCO_IOS)
    state.current_intf = {
        "interface": intf_name,
        "vlan_tag": vlan_tag,
    }
    if "interfaces" not in state.current_vlan:
        state.current_vlan["interfaces"] = {}
    state.current_vlan["interfaces"][intf_name] = state.current_intf
    state.in_protocols_section = False
    return True


def _handle_address_line(line: str, state: _ParseState) -> bool:
    """Process a per-interface address line (newer format). Returns True if matched."""
    addr_match = _INTF_ADDRESS_RE.match(line)
    if not addr_match or state.current_intf is None:
        return False

    protocol = addr_match.group("protocol")
    address = addr_match.group("address")
    if "addresses" not in state.current_intf:
        state.current_intf["addresses"] = {}
    state.current_intf["addresses"][protocol] = address
    return True


def _handle_protocol_line(line: str, state: _ParseState) -> bool:
    """Process a protocol counter line. Returns True if matched."""
    if state.current_vlan is None:
        return False

    proto_match = _PROTOCOL_LINE_RE.match(line)
    if not proto_match:
        return False

    protocol = proto_match.group("protocol")
    address = proto_match.group("address")
    received = int(proto_match.group("received"))
    transmitted = int(proto_match.group("transmitted"))

    if state.in_protocols_section or state.current_intf is None:
        # VLAN-level protocol counters
        if "protocols" not in state.current_vlan:
            state.current_vlan["protocols"] = {}
        state.current_vlan["protocols"][protocol] = {
            "received": received,
            "transmitted": transmitted,
        }
    elif address:
        # Per-interface protocol line (older format) - capture address
        if "addresses" not in state.current_intf:
            state.current_intf["addresses"] = {}
        state.current_intf["addresses"][protocol] = address

    return True


def _handle_protocol_addr_only(line: str, state: _ParseState) -> bool:
    """Process a protocol line with address but no counters. Returns True if matched."""
    addr_only_match = _PROTOCOL_ADDR_ONLY_RE.match(line)
    if not addr_only_match or state.current_intf is None:
        return False

    protocol = addr_only_match.group("protocol")
    address = addr_only_match.group("address")
    if "addresses" not in state.current_intf:
        state.current_intf["addresses"] = {}
    state.current_intf["addresses"][protocol] = address
    return True


def _handle_traffic_stats(line: str, state: _ParseState) -> bool:
    """Process traffic statistics lines. Returns True if matched."""
    if state.current_intf is None:
        return False

    # Total packets (newer format with "Total" prefix)
    total_match = _TOTAL_PACKETS_RE.match(line)
    if total_match:
        _set_traffic_stats(
            state.current_intf,
            int(total_match.group("packets")),
            int(total_match.group("bytes")),
            total_match.group("direction"),
        )
        return True

    # Oversubscription drops
    oversub_match = _OVERSUB_RE.match(line)
    if oversub_match:
        drops = int(oversub_match.group("drops"))
        if drops > 0:
            state.current_intf["oversubscription_drops"] = drops
        return True

    # Summary packets (older format without "Total" prefix)
    summary_match = _SUMMARY_PACKETS_RE.match(line)
    if summary_match:
        _set_traffic_stats(
            state.current_intf,
            int(summary_match.group("packets")),
            int(summary_match.group("bytes")),
            summary_match.group("direction"),
        )
        return True

    return False


def _handle_section_markers(line: str, stripped: str, state: _ParseState) -> bool:
    """Process section markers (native, protocols header, trunk headers).

    Returns True if the line was consumed.
    """
    if state.current_vlan is None:
        return False

    if _NATIVE_VLAN_RE.match(stripped):
        state.current_vlan["is_native"] = True
        return True

    if _PROTOCOLS_HEADER_RE.match(line):
        state.in_protocols_section = True
        return True

    if _TRUNK_SECTION_RE.match(stripped) or _VLAN_TRUNK_INTF_RE.match(line):
        state.in_protocols_section = False
        return True

    return False


def _try_content_handlers(line: str, state: _ParseState) -> bool:
    """Try content-level handlers for a line within a VLAN block.

    Returns True if any handler matched.
    """
    stripped = line.strip()

    if _handle_section_markers(line, stripped, state):
        return True

    if _handle_interface_tag(stripped, state):
        return True

    if _handle_address_line(line, state):
        return True

    if _handle_protocol_line(line, state):
        return True

    if _handle_protocol_addr_only(line, state):
        return True

    return _handle_traffic_stats(line, state)


def _parse_vlans(lines: list[str]) -> dict[str, VlanEntry]:
    """Parse all VLAN blocks from show vlans output."""
    state = _ParseState()
    for line in lines:
        stripped = line.strip()

        if _handle_vlan_header(stripped, state):
            continue

        if state.current_vlan is None:
            continue

        if not _try_content_handlers(line, state):
            # End protocols section on unrecognized non-empty line
            if stripped and state.in_protocols_section:
                state.in_protocols_section = False

    return state.vlans


@register(OS.CISCO_IOS, "show vlans")
class ShowVlansParser(BaseParser[ShowVlansResult]):
    """Parser for 'show vlans' on IOS.

    Parses dot1q VLAN information including trunk interfaces,
    protocol counters, and per-interface traffic statistics.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"switching", "vlan"})

    @classmethod
    def parse(cls, output: str) -> ShowVlansResult:
        """Parse 'show vlans' output into structured data.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VLAN entries keyed by VLAN ID.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()
        vlans = _parse_vlans(lines)

        if not vlans:
            msg = "No VLAN entries found in output"
            raise ValueError(msg)

        return {"vlans": vlans}
