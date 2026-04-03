"""Parser for 'show rsvp neighbors' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class RsvpInterfaceNeighborEntry(TypedDict):
    """Schema for a single RSVP interface neighbor within a global neighbor."""

    interface_neighbor: str


class RsvpGlobalNeighborEntry(TypedDict):
    """Schema for a single RSVP global neighbor."""

    interfaces: dict[str, RsvpInterfaceNeighborEntry]


# Top-level result keyed by global neighbor address.
ShowRsvpNeighborsResult = dict[str, RsvpGlobalNeighborEntry]

# "Global Neighbor: 10.100.100.120"
_GLOBAL_NEIGHBOR_PATTERN = re.compile(
    rf"^Global\s+Neighbor:\s+(?P<global_neighbor>{IPV4_ADDRESS})\s*$"
)

# "10.100.100.141       FortyGigE0/0/1/0"
_INTERFACE_NEIGHBOR_PATTERN = re.compile(
    rf"^\s+(?P<intf_neighbor>{IPV4_ADDRESS})\s+(?P<interface>\S+(?:\s+\d\S*)?)\s*$"
)


@register(OS.CISCO_IOSXR, "show rsvp neighbors")
class ShowRsvpNeighborsParser(BaseParser["ShowRsvpNeighborsResult"]):
    """Parser for 'show rsvp neighbors' command on IOS-XR.

    Parses RSVP neighbor information, grouping interface neighbors
    under their global neighbor address. Output is keyed by global
    neighbor address, with interfaces keyed by canonical interface name.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MPLS})

    @classmethod
    def parse(cls, output: str) -> "ShowRsvpNeighborsResult":
        """Parse 'show rsvp neighbors' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by global neighbor address.

        Raises:
            ValueError: If no RSVP neighbors found in output.
        """
        result: ShowRsvpNeighborsResult = {}
        current_global: str | None = None

        for line in output.splitlines():
            global_match = _GLOBAL_NEIGHBOR_PATTERN.match(line.strip())
            if global_match:
                current_global = global_match.group("global_neighbor")
                result[current_global] = {"interfaces": {}}
                continue

            if current_global is None:
                continue

            intf_match = _INTERFACE_NEIGHBOR_PATTERN.match(line)
            if intf_match:
                interface_raw = intf_match.group("interface").strip()
                interface = canonical_interface_name(interface_raw, os=OS.CISCO_IOSXR)
                intf_neighbor = intf_match.group("intf_neighbor")
                result[current_global]["interfaces"][interface] = {
                    "interface_neighbor": intf_neighbor,
                }

        if not result:
            msg = "No RSVP neighbors found in output"
            raise ValueError(msg)

        return result
