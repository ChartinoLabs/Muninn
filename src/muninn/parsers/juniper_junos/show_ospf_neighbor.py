"""Parser for 'show ospf neighbor' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class OspfNeighborEntry(TypedDict):
    """Schema for a single Junos OSPF neighbor entry.

    Attributes:
        address: Neighbor interface address.
        interface: Local interface name (e.g., ``ge-0/0/0.0``).
        state: Adjacency state (e.g., ``Full``, ``2Way``, ``Init``).
        neighbor_id: OSPF router ID of the neighbor.
        priority: Neighbor priority value.
        dead_time: Dead timer countdown in seconds.
    """

    address: str
    interface: str
    state: str
    neighbor_id: str
    priority: int
    dead_time: int


class ShowOspfNeighborResult(TypedDict):
    """Schema for 'show ospf neighbor' parsed output.

    Top-level dict-of-dicts keyed by neighbor address.
    """

    neighbors: dict[str, OspfNeighborEntry]


# Junos 'show ospf neighbor' output format:
# Address          Interface              State     ID               Pri  Dead
# 10.1.2.2         ge-0/0/2.0             Full      2.2.2.2            1    37
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<state>\S+)\s+"
    rf"(?P<neighbor_id>{IPV4_ADDRESS})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<dead_time>\d+)\s*$"
)

# Junos prompt lines like "{master:0}" or "{primary:node0}"
_PROMPT_PATTERN = re.compile(r"^\{.+\}\s*$")


@register(OS.JUNIPER_JUNOS, "show ospf neighbor")
class ShowOspfNeighborParser(BaseParser[ShowOspfNeighborResult]):
    """Parser for 'show ospf neighbor' command on Juniper Junos.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Neighbors are keyed by their interface address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowOspfNeighborResult:
        """Parse 'show ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, OspfNeighborEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Skip header lines, command echo, and prompt lines
            if _PROMPT_PATTERN.match(stripped):
                continue

            match = _NEIGHBOR_PATTERN.match(stripped)
            if match is None:
                continue

            address = match.group("address")
            neighbors[address] = OspfNeighborEntry(
                address=address,
                interface=match.group("interface"),
                state=match.group("state"),
                neighbor_id=match.group("neighbor_id"),
                priority=int(match.group("priority")),
                dead_time=int(match.group("dead_time")),
            )

        if not neighbors:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return cast(ShowOspfNeighborResult, {"neighbors": neighbors})
