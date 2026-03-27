"""Parser for 'show interfaces' command on Juniper Junos."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LogicalInterfaceEntry(TypedDict):
    """Schema for a Junos logical interface (unit)."""

    name: str
    index: NotRequired[int]
    snmp_ifindex: NotRequired[int]
    description: NotRequired[str]
    flags: NotRequired[str]
    encapsulation: NotRequired[str]
    vlan_tag: NotRequired[str]
    input_packets: NotRequired[int]
    output_packets: NotRequired[int]
    mtu: NotRequired[int]
    protocol: NotRequired[str]
    addresses: NotRequired[list[str]]
    local_address: NotRequired[str]
    destination_prefix: NotRequired[str]
    broadcast_address: NotRequired[str]


class PhysicalInterfaceEntry(TypedDict):
    """Schema for a Junos physical interface."""

    admin_status: str
    link_status: str
    interface_index: NotRequired[int]
    snmp_ifindex: NotRequired[int]
    description: NotRequired[str]
    link_level_type: NotRequired[str]
    mtu: NotRequired[str]
    speed: NotRequired[str]
    mac_address: NotRequired[str]
    hardware_address: NotRequired[str]
    last_flapped: NotRequired[str]
    input_rate_bps: NotRequired[int]
    input_rate_pps: NotRequired[int]
    output_rate_bps: NotRequired[int]
    output_rate_pps: NotRequired[int]
    logical_interfaces: NotRequired[dict[str, LogicalInterfaceEntry]]


class ShowInterfacesResult(TypedDict):
    """Schema for 'show interfaces' parsed output.

    Captures physical interface details and their logical sub-interfaces
    from Juniper Junos devices.
    """

    interfaces: dict[str, PhysicalInterfaceEntry]


@register(OS.JUNIPER_JUNOS, "show interfaces")
class ShowInterfacesParser(BaseParser[ShowInterfacesResult]):
    """Parser for 'show interfaces' command on Juniper Junos.

    Parses physical interfaces and their logical units, including status,
    counters, addressing, and link-level properties.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.INTERFACES,
        }
    )

    # Physical interface header line
    _PHYSICAL_IF = re.compile(
        r"^Physical interface:\s+(?P<name>\S+),\s+"
        r"(?P<admin>\S+),\s+Physical link is (?P<link>\S+)\s*$"
    )

    # Interface index line
    _IF_INDEX = re.compile(
        r"^\s+Interface index:\s+(?P<index>\d+)"
        r"(?:,\s+SNMP ifIndex:\s+(?P<snmp>\d+))?"
    )

    # Description line
    _DESCRIPTION = re.compile(r"^\s+Description:\s+(?P<desc>.+?)\s*$")

    # Link-level type and MTU (may have Type: prefix or not)
    # Values may be followed by commas due to continuation on the same line.
    _LINK_LEVEL = re.compile(
        r"^\s+(?:Type:\s+\S+,\s+)?Link-level type:\s+(?P<lltype>[A-Za-z0-9_-]+)"
        r"(?:,\s+MTU:\s+(?P<mtu>[A-Za-z0-9]+))?"
    )

    # Speed (can appear on link-level line or separately)
    _SPEED = re.compile(r"Speed:\s+(?P<speed>[A-Za-z0-9]+)")

    # MAC / hardware address
    _MAC_ADDR = re.compile(
        r"^\s+Current address:\s+(?P<mac>[0-9a-f:]+)"
        r",\s+Hardware address:\s+(?P<hw>[0-9a-f:]+)"
    )

    # Last flapped
    _LAST_FLAPPED = re.compile(r"^\s+Last flapped\s+:\s+(?P<flapped>.+?)\s*$")

    # Input/output rate
    _INPUT_RATE = re.compile(
        r"^\s+Input rate\s+:\s+(?P<bps>\d+)\s+bps\s+\((?P<pps>\d+)\s+pps\)"
    )
    _OUTPUT_RATE = re.compile(
        r"^\s+Output rate\s+:\s+(?P<bps>\d+)\s+bps\s+\((?P<pps>\d+)\s+pps\)"
    )

    # Logical interface line
    _LOGICAL_IF = re.compile(
        r"^\s+Logical interface\s+(?P<name>\S+)\s+"
        r"\(Index\s+(?P<index>\d+)\)"
        r"(?:\s+\(SNMP ifIndex\s+(?P<snmp>\d+)\))?"
    )

    # Logical interface flags with optional VLAN tag
    _LOGICAL_FLAGS = re.compile(
        r"^\s+Flags:\s+(?P<flags>.+?)(?:\s+VLAN-Tag\s+\[\s*(?P<vlan>\S+)\s*\])?"
        r"(?:\s+Encapsulation:\s+(?P<encap>\S+))?\s*$"
    )

    # Logical interface input/output packets
    _LOGICAL_INPUT = re.compile(r"^\s+Input packets\s*:\s*(?P<packets>\d+)")
    _LOGICAL_OUTPUT = re.compile(r"^\s+Output packets\s*:\s*(?P<packets>\d+)")

    # Protocol line with MTU
    _PROTOCOL = re.compile(
        r"^\s+Protocol\s+(?P<proto>\S+?)(?:,\s+MTU:\s+(?P<mtu>\d+))?"
        r"\s*$"
    )

    # Address line: Destination / Local / Broadcast
    _ADDRESS = re.compile(
        r"^\s+Destination:\s+(?P<dest>[^\s,]+)"
        r",\s+Local:\s+(?P<local>[^\s,]+)"
        r"(?:,\s+Broadcast:\s+(?P<bcast>[^\s,]+))?"
    )

    # Logical description (indented further than physical)
    _LOGICAL_DESC = re.compile(r"^\s{4,}Description:\s+(?P<desc>.+?)\s*$")

    # Junos prompt lines like "{master:0}" or "{primary:node0}"
    _PROMPT = re.compile(r"^\{.+\}\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesResult:
        """Parse 'show interfaces' output on Juniper Junos.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface information keyed by interface name.

        Raises:
            ValueError: If no interfaces can be parsed from output.
        """
        interfaces: dict[str, PhysicalInterfaceEntry] = {}
        current_physical: dict[str, object] | None = None
        current_physical_name: str | None = None
        current_logical: dict[str, object] | None = None
        current_logical_name: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            # Skip empty lines and prompt lines
            if not stripped or cls._PROMPT.match(stripped):
                continue

            # Check for new physical interface
            match = cls._PHYSICAL_IF.match(line)
            if match:
                # Save previous logical interface
                cls._save_logical(
                    current_physical, current_logical, current_logical_name
                )
                current_logical = None
                current_logical_name = None

                current_physical_name = match.group("name")
                current_physical = {
                    "admin_status": match.group("admin"),
                    "link_status": match.group("link"),
                }
                interfaces[current_physical_name] = cast(
                    PhysicalInterfaceEntry, current_physical
                )
                continue

            if current_physical is None:
                continue

            # Check for logical interface
            match = cls._LOGICAL_IF.match(line)
            if match:
                # Save previous logical interface
                cls._save_logical(
                    current_physical, current_logical, current_logical_name
                )

                current_logical_name = match.group("name")
                current_logical = {
                    "name": current_logical_name,
                    "index": int(match.group("index")),
                }
                snmp = match.group("snmp")
                if snmp is not None:
                    current_logical["snmp_ifindex"] = int(snmp)
                continue

            # If we are inside a logical interface, parse logical-level fields
            if current_logical is not None:
                cls._parse_logical_line(line, current_logical)
                continue

            # Parse physical interface fields
            cls._parse_physical_line(line, current_physical)

        # Save last logical interface
        cls._save_logical(current_physical, current_logical, current_logical_name)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return cast(ShowInterfacesResult, {"interfaces": interfaces})

    @classmethod
    def _parse_physical_link_level(cls, line: str, result: dict[str, object]) -> bool:
        """Parse link-level type, MTU, and speed from a physical interface line."""
        match = cls._LINK_LEVEL.match(line)
        if match:
            result["link_level_type"] = match.group("lltype")
            mtu = match.group("mtu")
            if mtu is not None:
                result["mtu"] = mtu
            speed_match = cls._SPEED.search(line)
            if speed_match:
                result["speed"] = speed_match.group("speed")
            return True

        # Speed can also appear on continuation lines (e.g., Link-mode line)
        if "speed" not in result:
            speed_match = cls._SPEED.search(line)
            if speed_match:
                result["speed"] = speed_match.group("speed")
        return False

    @classmethod
    def _parse_physical_counters(cls, line: str, result: dict[str, object]) -> bool:
        """Parse rate counters and MAC addresses from a physical interface line."""
        match = cls._MAC_ADDR.match(line)
        if match:
            result["mac_address"] = match.group("mac")
            result["hardware_address"] = match.group("hw")
            return True

        match = cls._INPUT_RATE.match(line)
        if match:
            result["input_rate_bps"] = int(match.group("bps"))
            result["input_rate_pps"] = int(match.group("pps"))
            return True

        match = cls._OUTPUT_RATE.match(line)
        if match:
            result["output_rate_bps"] = int(match.group("bps"))
            result["output_rate_pps"] = int(match.group("pps"))
            return True

        return False

    @classmethod
    def _parse_physical_line(cls, line: str, result: dict[str, object]) -> None:
        """Parse a single physical interface line, updating result in place."""
        match = cls._IF_INDEX.match(line)
        if match:
            result["interface_index"] = int(match.group("index"))
            snmp = match.group("snmp")
            if snmp is not None:
                result["snmp_ifindex"] = int(snmp)
            return

        match = cls._DESCRIPTION.match(line)
        if match:
            result["description"] = match.group("desc")
            return

        if cls._parse_physical_link_level(line, result):
            return

        match = cls._LAST_FLAPPED.match(line)
        if match:
            result["last_flapped"] = match.group("flapped")
            return

        cls._parse_physical_counters(line, result)

    @classmethod
    def _parse_logical_protocol(cls, line: str, result: dict[str, object]) -> bool:
        """Parse protocol and address fields from a logical interface line."""
        match = cls._PROTOCOL.match(line)
        if match:
            result["protocol"] = match.group("proto")
            mtu = match.group("mtu")
            if mtu is not None:
                result["mtu"] = int(mtu)
            return True

        match = cls._ADDRESS.match(line)
        if match:
            result["destination_prefix"] = match.group("dest")
            result["local_address"] = match.group("local")
            bcast = match.group("bcast")
            if bcast is not None:
                result["broadcast_address"] = bcast
            return True

        return False

    @classmethod
    def _parse_logical_line(cls, line: str, result: dict[str, object]) -> None:
        """Parse a single logical interface line, updating result in place."""
        match = cls._LOGICAL_FLAGS.match(line)
        if match and "flags" not in result:
            result["flags"] = match.group("flags").strip()
            vlan = match.group("vlan")
            if vlan is not None:
                result["vlan_tag"] = vlan
            encap = match.group("encap")
            if encap is not None:
                result["encapsulation"] = encap
            return

        match = cls._LOGICAL_DESC.match(line)
        if match:
            result["description"] = match.group("desc")
            return

        match = cls._LOGICAL_INPUT.match(line)
        if match:
            result["input_packets"] = int(match.group("packets"))
            return

        match = cls._LOGICAL_OUTPUT.match(line)
        if match:
            result["output_packets"] = int(match.group("packets"))
            return

        cls._parse_logical_protocol(line, result)

    @classmethod
    def _save_logical(
        cls,
        physical: dict[str, object] | None,
        logical: dict[str, object] | None,
        logical_name: str | None,
    ) -> None:
        """Save a completed logical interface into its parent physical interface."""
        if physical is None or logical is None or logical_name is None:
            return

        if "logical_interfaces" not in physical:
            physical["logical_interfaces"] = {}

        logical_dict = cast(
            dict[str, LogicalInterfaceEntry], physical["logical_interfaces"]
        )
        logical_dict[logical_name] = cast(LogicalInterfaceEntry, logical)
