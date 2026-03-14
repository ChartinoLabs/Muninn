"""Parser for 'show ip vrf interfaces' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class VrfInterfaceEntry(TypedDict):
    """Schema for a single VRF interface entry."""

    vrf: str
    protocol: str
    ip_address: NotRequired[str]


class ShowIpVrfInterfacesResult(TypedDict):
    """Schema for 'show ip vrf interfaces' parsed output."""

    interfaces: dict[str, VrfInterfaceEntry]


@register(OS.CISCO_IOS, "show ip vrf interfaces")
class ShowIpVrfInterfacesParser(BaseParser[ShowIpVrfInterfacesResult]):
    """Parser for 'show ip vrf interfaces' command.

    Example output:
        Interface              IP-Address      VRF                              Protocol
        Vl1100                 192.168.100.1   BYOD-Guest                       up
        Gi0/0                  unassigned      Mgmt-vrf                         down
    """

    _ROW_PATTERN = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<ip_address>\S+)\s+"
        r"(?P<vrf>\S+)\s+"
        r"(?P<protocol>\S+)\s*$"
    )

    _HEADER_PATTERN = re.compile(r"^Interface\s+IP-Address", re.IGNORECASE)

    @classmethod
    def parse(cls, output: str) -> ShowIpVrfInterfacesResult:
        """Parse 'show ip vrf interfaces' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VRF interface entries keyed by canonical interface name.

        Raises:
            ValueError: If no VRF interface entries found.
        """
        interfaces: dict[str, VrfInterfaceEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._HEADER_PATTERN.match(line):
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                raw_interface = match.group("interface")
                ip_address = match.group("ip_address")
                vrf = match.group("vrf")
                protocol = match.group("protocol")

                interface_name = canonical_interface_name(raw_interface)

                entry: VrfInterfaceEntry = {
                    "vrf": vrf,
                    "protocol": protocol,
                }

                if ip_address != "unassigned":
                    entry["ip_address"] = ip_address

                interfaces[interface_name] = entry

        if not interfaces:
            msg = "No VRF interface entries found in output"
            raise ValueError(msg)

        return ShowIpVrfInterfacesResult(interfaces=interfaces)
