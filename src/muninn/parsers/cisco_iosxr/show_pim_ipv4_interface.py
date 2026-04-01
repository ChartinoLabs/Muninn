"""Parser for 'show pim ipv4 interface' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class PimIpv4InterfaceEntry(TypedDict):
    """Schema for a single PIM IPv4 interface entry."""

    address: str
    pim_enabled: bool
    neighbor_count: int
    hello_interval: int
    dr_priority: int
    dr_address: str


ShowPimIpv4InterfaceResult = dict[str, PimIpv4InterfaceEntry]


# Data row pattern for IOS-XR show pim ipv4 interface:
# 192.0.2.1             BVI10                         on   11    30     1     192.0.2.2
_INTERFACE_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<pim_enabled>on|off)\s+"
    r"(?P<neighbor_count>\d+)\s+"
    r"(?P<hello_interval>\d+)\s+"
    r"(?P<dr_priority>\d+)\s+"
    rf"(?P<dr_address>{IPV4_ADDRESS})\s*$"
)


@register(OS.CISCO_IOSXR, "show pim ipv4 interface")
class ShowPimIpv4InterfaceParser(BaseParser["ShowPimIpv4InterfaceResult"]):
    """Parser for 'show pim ipv4 interface' command on IOS-XR.

    Parses PIM IPv4 interface information including neighbor counts,
    hello intervals, DR priority, and designated router address.
    Results are keyed by interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    @classmethod
    def parse(cls, output: str) -> "ShowPimIpv4InterfaceResult":
        """Parse 'show pim ipv4 interface' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by interface name with PIM interface details.

        Raises:
            ValueError: If no PIM interfaces found in output.
        """
        result: ShowPimIpv4InterfaceResult = {}

        for line in output.splitlines():
            match = _INTERFACE_PATTERN.match(line.strip())
            if match is None:
                continue

            interface = match.group("interface")
            result[interface] = PimIpv4InterfaceEntry(
                address=match.group("address"),
                pim_enabled=match.group("pim_enabled") == "on",
                neighbor_count=int(match.group("neighbor_count")),
                hello_interval=int(match.group("hello_interval")),
                dr_priority=int(match.group("dr_priority")),
                dr_address=match.group("dr_address"),
            )

        if not result:
            msg = "No PIM interfaces found in output"
            raise ValueError(msg)

        return result
