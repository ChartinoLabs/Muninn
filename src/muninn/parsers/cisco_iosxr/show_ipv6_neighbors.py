"""Parser for 'show ipv6 neighbors' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import MAC_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class Ipv6NeighborEntry(TypedDict):
    """Schema for a single IPv6 neighbor (NDP) entry."""

    age: str
    link_layer_address: str
    state: str
    interface: str
    location: NotRequired[str]


class ShowIpv6NeighborsResult(TypedDict):
    """Schema for 'show ipv6 neighbors' parsed output on IOS-XR.

    Keyed by IPv6 address. Multicast adjacency entries (``[Mcast adjacency]``)
    are excluded because they lack a meaningful unique key and represent
    internal platform state rather than real neighbor relationships.
    """

    neighbors: dict[str, Ipv6NeighborEntry]


# IPv6 neighbor table row pattern for IOS-XR.
# Columns: IPv6 Address, Age, Link-layer Addr, State, Interface, Location.
# Age can be a number (seconds) or ``-`` for multicast adjacencies.
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<ipv6_address>\S+)\s+"
    r"(?P<age>\d+)\s+"
    rf"(?P<link_layer_address>{MAC_ADDRESS})\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<interface>\S+)"
    r"(?:\s+(?P<location>\S+))?\s*$"
)


@register(OS.CISCO_IOSXR, "show ipv6 neighbors")
class ShowIpv6NeighborsParser(BaseParser["ShowIpv6NeighborsResult"]):
    """Parser for 'show ipv6 neighbors' on Cisco IOS-XR.

    Parses the IPv6 neighbor discovery (NDP) table. Entries are keyed
    by IPv6 address. Multicast adjacency rows are skipped.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ARP})

    @classmethod
    def parse(cls, output: str) -> "ShowIpv6NeighborsResult":
        """Parse 'show ipv6 neighbors' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor entries keyed by IPv6 address.

        Raises:
            ValueError: If no neighbor entries found in output.
        """
        neighbors: dict[str, Ipv6NeighborEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _NEIGHBOR_PATTERN.match(stripped)
            if not match:
                continue

            ipv6_address = match.group("ipv6_address")
            interface_raw = match.group("interface")
            interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)

            entry: Ipv6NeighborEntry = {
                "age": match.group("age"),
                "link_layer_address": match.group("link_layer_address").lower(),
                "state": match.group("state").upper(),
                "interface": interface,
            }

            location = match.group("location")
            if location:
                entry["location"] = location

            neighbors[ipv6_address] = entry

        if not neighbors:
            msg = "No IPv6 neighbor entries found in output"
            raise ValueError(msg)

        return cast("ShowIpv6NeighborsResult", {"neighbors": neighbors})
