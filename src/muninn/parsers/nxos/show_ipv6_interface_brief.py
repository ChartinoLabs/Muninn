"""Parser for 'show ipv6 interface brief' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class IPv6InterfaceBriefEntry(TypedDict):
    """Schema for a single IPv6 interface brief entry."""

    ipv6_address: str
    link_local: NotRequired[str]
    protocol_status: str
    link_status: str
    admin_status: str


class ShowIPv6InterfaceBriefResult(TypedDict):
    """Schema for 'show ipv6 interface brief' parsed output."""

    interfaces: dict[str, IPv6InterfaceBriefEntry]


# Pattern for interface lines:
#   Vlan44           2a01:3333:1:44::2                         up/up/up
_INTERFACE_LINE_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<ipv6_address>\S+)\s+"
    r"(?P<protocol>up|down)/(?P<link>up|down)/(?P<admin>up|down)$"
)

# Pattern for link-local continuation lines:
#                  fe80::333:4444:5555:8888
_LINK_LOCAL_PATTERN = re.compile(r"^\s+(?P<link_local>fe80:\S+)$")


@register(OS.CISCO_NXOS, "show ipv6 interface brief")
class ShowIPv6InterfaceBriefParser(BaseParser[ShowIPv6InterfaceBriefResult]):
    """Parser for 'show ipv6 interface brief' command on NX-OS.

    Parses IPv6 interface status including address, link-local address,
    and protocol/link/admin status.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIPv6InterfaceBriefResult:
        """Parse 'show ipv6 interface brief' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv6 interface brief data keyed by canonical interface name.

        Raises:
            ValueError: If no interfaces found in output.
        """
        interfaces: dict[str, IPv6InterfaceBriefEntry] = {}
        last_interface: str | None = None

        for line in output.splitlines():
            intf_match = _INTERFACE_LINE_PATTERN.match(line)
            if intf_match:
                name = canonical_interface_name(
                    intf_match.group("interface"), os=OS.CISCO_NXOS
                )
                entry: IPv6InterfaceBriefEntry = {
                    "ipv6_address": intf_match.group("ipv6_address"),
                    "protocol_status": intf_match.group("protocol"),
                    "link_status": intf_match.group("link"),
                    "admin_status": intf_match.group("admin"),
                }
                interfaces[name] = entry
                last_interface = name
                continue

            ll_match = _LINK_LOCAL_PATTERN.match(line)
            if ll_match and last_interface is not None:
                interfaces[last_interface]["link_local"] = ll_match.group("link_local")
                continue

        if not interfaces:
            msg = "No interfaces found in output"
            raise ValueError(msg)

        return ShowIPv6InterfaceBriefResult(interfaces=interfaces)
