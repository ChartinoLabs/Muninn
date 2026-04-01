"""Parser for 'show ip ospf neighbor' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class OspfNeighborEntry(TypedDict):
    """Schema for a single Arista EOS OSPF neighbor entry."""

    priority: int
    state: str
    dead_time: str
    address: str
    interface: str
    vrf: NotRequired[str]
    role: NotRequired[str]


class ShowIpOspfNeighborResult(TypedDict):
    """Schema for 'show ip ospf neighbor' parsed output.

    Neighbors are keyed by neighbor router ID.
    """

    neighbors: dict[str, OspfNeighborEntry]


# Neighbor table row pattern for Arista EOS:
# Neighbor ID     VRF    Pri   State            Dead Time   Address         Interface
# 3.3.3.3         default    1   FULL/BDR         00:00:34    10.3.4.3        Ethernet2
# 2.2.2.2         default    1   FULL             00:00:38    10.2.4.2        Ethernet3
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<neighbor_id>{IPV4_ADDRESS})\s+"
    r"(?P<vrf>\S+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state>\w+)(?:/(?P<role>\S+))?\s+"
    r"(?P<dead_time>\d{1,2}:\d{2}:\d{2})\s+"
    rf"(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s*$"
)


@register(OS.ARISTA_EOS, "show ip ospf neighbor")
class ShowIpOspfNeighborParser(BaseParser["ShowIpOspfNeighborResult"]):
    """Parser for 'show ip ospf neighbor' command on Arista EOS.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Neighbors are keyed by neighbor router ID.
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
            Parsed neighbor data keyed by neighbor router ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, OspfNeighborEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            match = _NEIGHBOR_PATTERN.match(stripped)
            if match is None:
                continue

            neighbor_id = match.group("neighbor_id")
            entry: OspfNeighborEntry = {
                "priority": int(match.group("priority")),
                "state": match.group("state").upper(),
                "dead_time": match.group("dead_time"),
                "address": match.group("address"),
                "interface": match.group("interface"),
            }

            vrf = match.group("vrf")
            if vrf and vrf != "default":
                entry["vrf"] = vrf

            role = match.group("role")
            if role:
                entry["role"] = role

            neighbors[neighbor_id] = entry

        if not neighbors:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return cast("ShowIpOspfNeighborResult", {"neighbors": neighbors})
