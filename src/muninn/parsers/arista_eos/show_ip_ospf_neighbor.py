"""Parser for 'show ip ospf neighbor' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class OspfNeighborEntry(TypedDict):
    """Schema for a single Arista EOS OSPF neighbor entry."""

    priority: int
    state: str
    dead_time: str
    address: str
    role: NotRequired[str]
    instance: NotRequired[str]


class ShowIpOspfNeighborResult(TypedDict):
    """Schema for 'show ip ospf neighbor' parsed output.

    Neighbors are nested by VRF, then canonical interface name, then
    neighbor router ID.  This avoids collisions when the same router-ID
    appears in multiple VRFs or when parallel adjacencies exist on
    different interfaces.
    """

    vrfs: dict[str, dict[str, dict[str, OspfNeighborEntry]]]


# Neighbor table row pattern.  Arista EOS emits two layouts: one with an
# "Instance" column and one without.  The Instance group is optional and
# recognised by being a digit-only token preceding the VRF name.
#
# Without Instance:
#   3.3.3.3    default  1  FULL/BDR  00:00:34  10.3.4.3  Ethernet2
# With Instance:
#   192.0.2.2  1        red  1  FULL  00:00:31  192.0.2.1  Ethernet20/1
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<neighbor_id>{IPV4_ADDRESS})\s+"
    r"(?:(?P<instance>\d+)\s+)?"
    r"(?P<vrf>\S+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state_role>\S+)\s+"
    r"(?P<dead_time>\d{1,2}:\d{2}:\d{2})\s+"
    rf"(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s*$"
)


@register(OS.ARISTA_EOS, "show ip ospf neighbor")
class ShowIpOspfNeighborParser(BaseParser["ShowIpOspfNeighborResult"]):
    """Parser for 'show ip ospf neighbor' command on Arista EOS.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Output is nested by VRF, then canonical interface name, then
    neighbor router ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIpOspfNeighborResult":
        """Parse 'show ip ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data nested by VRF, interface, and neighbor
            router ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        vrfs: dict[str, dict[str, dict[str, OspfNeighborEntry]]] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _NEIGHBOR_PATTERN.match(stripped)
            if match is None:
                continue

            vrf = match.group("vrf")
            interface = canonical_interface_name(
                match.group("interface"), os=OS.ARISTA_EOS
            )
            neighbor_id = match.group("neighbor_id")

            vrfs.setdefault(vrf, {}).setdefault(interface, {})[neighbor_id] = (
                cls._build_entry(match)
            )

        if not vrfs:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return ShowIpOspfNeighborResult(vrfs=vrfs)

    @staticmethod
    def _build_entry(match: re.Match[str]) -> OspfNeighborEntry:
        state, _, role = match.group("state_role").partition("/")
        entry: OspfNeighborEntry = {
            "priority": int(match.group("priority")),
            "state": state.strip().upper(),
            "dead_time": match.group("dead_time"),
            "address": match.group("address"),
        }

        role = role.strip()
        if role and role != "-":
            entry["role"] = role

        instance = match.group("instance")
        if instance:
            entry["instance"] = instance

        return entry
