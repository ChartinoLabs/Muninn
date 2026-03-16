"""Parser for 'show interface status' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class InterfaceStatusEntry(TypedDict):
    """Schema for a single interface status entry."""

    status: str
    duplex: str
    speed: str
    name: NotRequired[str]
    vlan: NotRequired[str]
    type: NotRequired[str]


class ShowInterfaceStatusResult(TypedDict):
    """Schema for 'show interface status' parsed output."""

    interfaces: dict[str, InterfaceStatusEntry]


@register(OS.CISCO_NXOS, "show interface status")
class ShowInterfaceStatusParser(BaseParser[ShowInterfaceStatusResult]):
    """Parser for 'show interface status' command on NX-OS.

    Parses interface status including description, VLAN, duplex, speed, and type.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    # Pattern for interface status entries
    # Port          Name               Status    Vlan      Duplex  Speed   Type
    # Eth1/1        managed by puppet  disabled  routed    auto    auto
    #              SFP-H10GB-CU2M
    # mgmt0         --                 connected routed    full    100     --
    _INTERFACE_PATTERN = re.compile(
        r"^(?P<port>(?:Eth|mgmt|Po|Lo|Vlan|nve|Ser|Tu|Fa|Gi)\S*)\s+"
        r"(?P<name>.{14,}?)\s+"
        r"(?P<status>connected|disabled|sfpAbsent|xcvrAbsen|notconnec|noOperMem|"
        r"linkFlapE|channelDo|down|up)\s+"
        r"(?P<vlan>\d+|routed|trunk|f-path|--)\s+"
        r"(?P<duplex>full|half|auto)\s+"
        r"(?P<speed>\S+)\s*"
        r"(?P<type>\S.*)?$"
    )

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

        for line in output.splitlines():
            # Skip header, dashes, and empty lines
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("Port")
                or stripped.startswith("---")
            ):
                continue

            match = cls._INTERFACE_PATTERN.match(stripped)
            if match:
                port = canonical_interface_name(match.group("port"), os=OS.CISCO_NXOS)
                name = cls._normalize_value(match.group("name"))
                status = match.group("status")
                vlan = cls._normalize_value(match.group("vlan"))
                duplex = match.group("duplex")
                speed = match.group("speed")
                intf_type = cls._normalize_value(match.group("type"))

                entry: InterfaceStatusEntry = {
                    "status": status,
                    "duplex": duplex,
                    "speed": speed,
                }

                if name:
                    entry["name"] = name
                if vlan:
                    entry["vlan"] = vlan
                if intf_type:
                    entry["type"] = intf_type

                interfaces[port] = entry

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowInterfaceStatusResult(interfaces=interfaces)
