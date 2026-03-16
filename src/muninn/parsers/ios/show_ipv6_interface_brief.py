"""Parser for 'show ipv6 interface brief' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Interface header line: "InterfaceName    [status/protocol]"
_INTF_RE = re.compile(
    r"^(?P<interface>\S+)\s+\[(?P<status>.+?)/(?P<protocol>\S+)\]\s*$"
)

# Indented address line (IPv6 address or "unassigned")
_ADDR_RE = re.compile(r"^\s+(?P<address>\S+)\s*$")


class Ipv6InterfaceBriefEntry(TypedDict):
    """Schema for a single IPv6 interface brief entry."""

    status: str
    protocol: str
    ipv6_addresses: NotRequired[list[str]]


class ShowIpv6InterfaceBriefResult(TypedDict):
    """Schema for 'show ipv6 interface brief' parsed output."""

    interfaces: dict[str, Ipv6InterfaceBriefEntry]


@register(OS.CISCO_IOS, "show ipv6 interface brief")
class ShowIpv6InterfaceBriefParser(
    BaseParser[ShowIpv6InterfaceBriefResult],
):
    """Parser for 'show ipv6 interface brief' on IOS.

    Parses the IPv6 interface summary table showing interface name,
    status, protocol, and assigned IPv6 addresses.
    """

    tags: ClassVar[frozenset[str]] = frozenset({"interfaces"})

    @classmethod
    def parse(cls, output: str) -> ShowIpv6InterfaceBriefResult:
        """Parse 'show ipv6 interface brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed IPv6 interface brief entries keyed by canonical
            interface name.

        Raises:
            ValueError: If no valid interface entries are found.
        """
        interfaces: dict[str, Ipv6InterfaceBriefEntry] = {}
        current_name: str | None = None

        for line in output.splitlines():
            # Try interface header line
            intf_match = _INTF_RE.match(line)
            if intf_match:
                raw_name = intf_match.group("interface")
                current_name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)
                entry: Ipv6InterfaceBriefEntry = {
                    "status": intf_match.group("status"),
                    "protocol": intf_match.group("protocol"),
                }
                interfaces[current_name] = entry
                continue

            # Try indented address line
            addr_match = _ADDR_RE.match(line)
            if addr_match and current_name is not None:
                address = addr_match.group("address")
                # Skip "unassigned" — omit ipv6_addresses key entirely
                if address.lower() == "unassigned":
                    continue
                current_entry = interfaces[current_name]
                if "ipv6_addresses" not in current_entry:
                    current_entry["ipv6_addresses"] = []
                current_entry["ipv6_addresses"].append(address)

        if not interfaces:
            msg = "No valid interface entries found in output"
            raise ValueError(msg)

        return cast(ShowIpv6InterfaceBriefResult, {"interfaces": interfaces})
