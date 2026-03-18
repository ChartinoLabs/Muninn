"""Parser for 'show interface brief' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypeAlias, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class EthernetEntry(TypedDict):
    """Schema for an Ethernet interface entry."""

    type: str
    mode: str
    status: str
    reason: str
    speed: str
    vlan: NotRequired[str]
    port_channel: NotRequired[str]


class PortChannelEntry(TypedDict):
    """Schema for a Port-channel interface entry."""

    type: str
    mode: str
    status: str
    reason: str
    speed: str
    protocol: str
    vlan: NotRequired[str]


class ManagementEntry(TypedDict):
    """Schema for a management interface entry."""

    status: str
    speed: int
    mtu: int
    vrf: NotRequired[str]
    ip_address: NotRequired[str]


class LoopbackEntry(TypedDict):
    """Schema for a Loopback interface entry."""

    status: str
    description: NotRequired[str]


class VlanEntry(TypedDict):
    """Schema for a VLAN interface entry."""

    status: str
    reason: NotRequired[str]
    secondary_vlan: NotRequired[str]


ShowInterfaceBriefEntry: TypeAlias = (
    EthernetEntry | PortChannelEntry | ManagementEntry | LoopbackEntry | VlanEntry
)

ShowInterfaceBriefResult: TypeAlias = dict[str, ShowInterfaceBriefEntry]


# Separator line pattern
_SEPARATOR = re.compile(r"^-{10,}$")


@register(OS.CISCO_NXOS, "show interface brief")
class ShowInterfaceBriefParser(BaseParser[ShowInterfaceBriefResult]):
    """Parser for 'show interface brief' command on NX-OS.

    Parses multi-section output covering Ethernet, Port-channel,
    Management, Loopback, and VLAN interface summaries.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Ethernet section header pattern:
    # Ethernet      VLAN    Type Mode   Status  Reason                   Speed     Port
    # Interface                                                                    Ch #
    _ETHERNET_HEADER = re.compile(
        r"Ethernet\s+VLAN\s+Type\s+Mode\s+Status\s+Reason\s+Speed\s+Port"
    )

    # Ethernet data line:
    # Eth1/1        1      eth  trunk  up      none                        10G(D) 4000
    # Eth1/2        --     eth  routed down    SFP not inserted            1000(D) --
    _ETHERNET_PATTERN = re.compile(
        r"^(?P<interface>Eth\S+)\s+"
        r"(?P<vlan>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<mode>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<reason>.+?)\s{2,}"
        r"(?P<speed>\S+)\s+"
        r"(?P<port_channel>\S+)\s*$"
    )

    # Port-channel section header pattern:
    # Port-channel VLAN Type Mode Status Reason Speed Protocol
    # Interface
    _PORT_CHANNEL_HEADER = re.compile(
        r"Port-channel\s+VLAN\s+Type\s+Mode\s+Status\s+Reason\s+Speed\s+Protocol"
    )

    # Port-channel data line:
    # Po10         1     eth  trunk  up      none                       a-10G(D)  lacp
    _PORT_CHANNEL_PATTERN = re.compile(
        r"^(?P<interface>Po\S+)\s+"
        r"(?P<vlan>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<mode>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<reason>.+?)\s{2,}"
        r"(?P<speed>\S+)\s+"
        r"(?P<protocol>\S+)\s*$"
    )

    # Management section header pattern:
    # Port   VRF          Status IP Address                              Speed    MTU
    _MGMT_HEADER = re.compile(r"Port\s+VRF\s+Status\s+IP\s+Address\s+Speed\s+MTU")

    # Management data line:
    # mgmt0  --           up     192.168.10.37                           100      1500
    _MGMT_PATTERN = re.compile(
        r"^(?P<interface>mgmt\S*)\s+"
        r"(?P<vrf>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<ip_address>\S+)\s+"
        r"(?P<speed>\d+)\s+"
        r"(?P<mtu>\d+)\s*$"
    )

    # Loopback/Tunnel section header with "Status" and "Description":
    # Interface                  Status    Description
    _LOOPBACK_HEADER = re.compile(r"Interface\s+Status\s+Description")

    # Loopback data line:
    # Lo0                        up        Router ID loopback
    # Lo1                        up        --
    _LOOPBACK_PATTERN = re.compile(
        r"^(?P<interface>Lo\S+)\s+"
        r"(?P<status>\S+)\s*"
        r"(?P<description>.*)?$"
    )

    # VLAN section header with "Secondary VLAN":
    # Interface   Secondary VLAN(Type)                    Status Reason
    _VLAN_HEADER = re.compile(r"Interface\s+Secondary\s+VLAN")

    # VLAN data line:
    # Vlan1     --                                      down   Administratively down
    _VLAN_PATTERN = re.compile(
        r"^(?P<interface>Vlan\S+)\s+"
        r"(?P<secondary_vlan>\S+)\s+"
        r"(?P<status>\S+)\s+"
        r"(?P<reason>.+?)\s*$"
    )

    @classmethod
    def _detect_section(cls, line: str) -> str | None:
        """Detect which section a header line belongs to.

        Args:
            line: A line from the CLI output.

        Returns:
            Section name string, or None if not a header.
        """
        if cls._ETHERNET_HEADER.search(line):
            return "ethernet"
        if cls._PORT_CHANNEL_HEADER.search(line):
            return "port_channel"
        if cls._MGMT_HEADER.search(line):
            return "management"
        if cls._VLAN_HEADER.search(line):
            return "vlan"
        if cls._LOOPBACK_HEADER.search(line):
            return "loopback"
        return None

    @classmethod
    def _parse_ethernet(cls, line: str) -> tuple[str, EthernetEntry] | None:
        """Parse an Ethernet interface line."""
        match = cls._ETHERNET_PATTERN.match(line)
        if not match:
            return None

        interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_NXOS)
        port_ch = match.group("port_channel").strip()

        vlan = match.group("vlan")

        entry: EthernetEntry = {
            "type": match.group("type"),
            "mode": match.group("mode"),
            "status": match.group("status"),
            "reason": match.group("reason").strip(),
            "speed": cls._normalize_speed(match.group("speed")),
        }
        if vlan != "--":
            entry["vlan"] = vlan
        if port_ch != "--":
            entry["port_channel"] = port_ch

        return interface, entry

    @staticmethod
    def _normalize_speed(speed: str) -> str:
        """Remove unsupported NX-OS speed suffixes from speed values."""
        return speed.removesuffix("(D)")

    @classmethod
    def _parse_port_channel(cls, line: str) -> tuple[str, PortChannelEntry] | None:
        """Parse a Port-channel interface line."""
        match = cls._PORT_CHANNEL_PATTERN.match(line)
        if not match:
            return None

        interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_NXOS)

        vlan = match.group("vlan")

        entry: PortChannelEntry = {
            "type": match.group("type"),
            "mode": match.group("mode"),
            "status": match.group("status"),
            "reason": match.group("reason").strip(),
            "speed": cls._normalize_speed(match.group("speed")),
            "protocol": match.group("protocol"),
        }
        if vlan != "--":
            entry["vlan"] = vlan

        return interface, entry

    @classmethod
    def _parse_management(cls, line: str) -> tuple[str, ManagementEntry] | None:
        """Parse a management interface line."""
        match = cls._MGMT_PATTERN.match(line)
        if not match:
            return None

        interface = match.group("interface")
        ip_addr = match.group("ip_address")

        vrf = match.group("vrf")

        entry: ManagementEntry = {
            "status": match.group("status"),
            "speed": int(match.group("speed")),
            "mtu": int(match.group("mtu")),
        }
        if vrf != "--":
            entry["vrf"] = vrf
        if ip_addr != "--":
            entry["ip_address"] = ip_addr

        return interface, entry

    @classmethod
    def _parse_loopback(cls, line: str) -> tuple[str, LoopbackEntry] | None:
        """Parse a Loopback interface line."""
        match = cls._LOOPBACK_PATTERN.match(line)
        if not match:
            return None

        interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_NXOS)

        entry: LoopbackEntry = {
            "status": match.group("status"),
        }
        desc = match.group("description")
        if desc:
            desc = desc.strip()
            if desc and desc != "--":
                entry["description"] = desc

        return interface, entry

    @classmethod
    def _parse_vlan(cls, line: str) -> tuple[str, VlanEntry] | None:
        """Parse a VLAN interface line."""
        match = cls._VLAN_PATTERN.match(line)
        if not match:
            return None

        interface = canonical_interface_name(match.group("interface"), os=OS.CISCO_NXOS)

        reason = match.group("reason").strip()

        entry: VlanEntry = {
            "status": match.group("status"),
        }
        if reason != "--":
            entry["reason"] = reason
        secondary = match.group("secondary_vlan")
        if secondary != "--":
            entry["secondary_vlan"] = secondary

        return interface, entry

    # Map section names to their parser method names
    _SECTION_PARSERS: dict[str, str] = {
        "ethernet": "_parse_ethernet",
        "port_channel": "_parse_port_channel",
        "management": "_parse_management",
        "loopback": "_parse_loopback",
        "vlan": "_parse_vlan",
    }

    # Lines that are sub-headers to skip
    _SKIP_LINES = frozenset({"Interface", "Ch #"})

    @classmethod
    def _is_skip_line(cls, stripped: str) -> bool:
        """Check if a line should be skipped during parsing."""
        if not stripped or _SEPARATOR.match(stripped):
            return True
        return stripped in cls._SKIP_LINES

    @classmethod
    def _process_data_line(
        cls,
        stripped: str,
        current_section: str,
        result: ShowInterfaceBriefResult,
    ) -> None:
        """Parse a data line and add it to the result dict."""
        method_name = cls._SECTION_PARSERS.get(current_section)
        if not method_name:
            return
        parser_fn = getattr(cls, method_name)
        parsed = parser_fn(stripped)
        if parsed:
            intf_name, entry = parsed
            result[intf_name] = entry

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceBriefResult:
        """Parse 'show interface brief' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface data keyed by interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        result: ShowInterfaceBriefResult = {}
        current_section: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if cls._is_skip_line(stripped):
                continue

            section = cls._detect_section(stripped)
            if section is not None:
                current_section = section
                continue

            if current_section:
                cls._process_data_line(stripped, current_section, result)

        if not result:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return result
