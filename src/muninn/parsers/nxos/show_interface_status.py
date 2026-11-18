"""Parser for 'show interface status' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class InterfaceStatusEntry(TypedDict):
    """Schema for a single interface status entry."""

    status: str
    duplex: str
    speed: str
    name: NotRequired[str]
    vlan: NotRequired[str]
    type: NotRequired[str]


class TunnelStatusEntry(TypedDict):
    """Schema for a tunnel status entry (ACI iVXLAN tunnels)."""

    status: str
    reason: str
    name: NotRequired[str]


class ShowInterfaceStatusResult(TypedDict):
    """Schema for 'show interface status' parsed output."""

    interfaces: dict[str, InterfaceStatusEntry]
    tunnels: NotRequired[dict[str, TunnelStatusEntry]]


@register(OS.CISCO_ACI, "show interface status")
@register(OS.CISCO_NXOS, "show interface status")
class ShowInterfaceStatusParser(BaseParser[ShowInterfaceStatusResult]):
    """Parser for 'show interface status' command on NX-OS.

    Parses interface status including description, VLAN, duplex, speed, and type.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Pattern for interface status entries
    # Port          Name               Status    Vlan      Duplex  Speed   Type
    # Eth1/1        managed by puppet  disabled  routed    auto    auto
    #              SFP-H10GB-CU2M
    # mgmt0         --                 connected routed    full    100     --
    # ACI switches also print sfpabsent, out-of-ser and parentdown.
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<port>(?:Eth|mgmt|Po|Lo|Vlan|nve|Ser|Tu|Fa|Gi)\S*)\s+"
        r"(?P<name>.{14,}?)\s+"
        r"(?P<status>connected|disabled|sfpAbsent|xcvrAbsen|notconnec|noOperMem|"
        r"linkFlapE|channelDo|sfpabsent|out-of-ser|parentdown|down|up)\s+"
        r"(?P<vlan>\d+|routed|trunk|f-path|--)\s+"
        r"(?P<duplex>full|half|auto)\s+"
        r"(?P<speed>\S+)\s*"
        r"(?P<type>\S.*)?$"
    )

    # ACI switches add a separate tunnel table:
    # Interface     Name                Status    Reason
    # Tunnel1       --                  up        no-reason
    _TUNNEL_PATTERN = re.compile(
        r"^(?P<port>Tunnel\S+)\s+"
        r"(?P<name>.+?)\s{2,}"
        r"(?P<status>\S+)\s+"
        r"(?P<reason>\S.*?)\s*$"
    )

    @classmethod
    def _parse_tunnel(cls, line: str, tunnels: dict[str, TunnelStatusEntry]) -> None:
        """Parse a tunnel table line into ``tunnels`` if it matches."""
        match = cls._TUNNEL_PATTERN.match(line)
        if not match:
            return
        entry: TunnelStatusEntry = {
            "status": match.group("status"),
            "reason": match.group("reason"),
        }
        name = cls._normalize_value(match.group("name"))
        if name:
            entry["name"] = name
        tunnels[match.group("port")] = entry

    @classmethod
    def _normalize_value(cls, value: str | None) -> str | None:
        """Normalize a field value, converting -- to None.

        Args:
            value: Raw field value from CLI output.

        Returns:
            Normalized value or None if --/empty.
        """
        if value is None:
            return None
        value = value.strip()
        if not value or value == "--":
            return None
        return value

    @classmethod
    def _build_entry(cls, match: re.Match[str]) -> InterfaceStatusEntry:
        """Build an InterfaceStatusEntry from an interface row match."""
        entry: InterfaceStatusEntry = {
            "status": match.group("status"),
            "duplex": match.group("duplex"),
            "speed": match.group("speed"),
        }
        name = cls._normalize_value(match.group("name"))
        if name:
            entry["name"] = name
        vlan = cls._normalize_value(match.group("vlan"))
        if vlan:
            entry["vlan"] = vlan
        intf_type = cls._normalize_value(match.group("type"))
        if intf_type:
            entry["type"] = intf_type
        return entry

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceStatusResult:
        """Parse 'show interface status' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed interface status data keyed by interface name.

        Raises:
            ValueError: If no interfaces found.
        """
        interfaces: dict[str, InterfaceStatusEntry] = {}
        tunnels: dict[str, TunnelStatusEntry] = {}

        for line in output.splitlines():
            # Skip header, dashes, and empty lines
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("Port")
                or stripped.startswith("Interface")
                or stripped.startswith("---")
            ):
                continue

            match = cls._INTERFACE_PATTERN.match(stripped)
            if match:
                port = canonical_interface_name(match.group("port"), os=OS.CISCO_NXOS)
                interfaces[port] = cls._build_entry(match)
            else:
                cls._parse_tunnel(stripped, tunnels)

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        result = ShowInterfaceStatusResult(interfaces=interfaces)
        if tunnels:
            result["tunnels"] = tunnels
        return result
