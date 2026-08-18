"""Parser for 'show ospf3 neighbor' command on Juniper Junos."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class Ospf3NeighborEntry(TypedDict):
    """Schema for a single Junos OSPFv3 neighbor entry.

    Attributes:
        neighbor_id: OSPF router ID of the neighbor.
        interface: Local interface name (e.g., ``ge-0/0/0.0``).
        state: Adjacency state (e.g., ``Full``, ``2Way``, ``Init``).
        priority: Neighbor priority value.
        dead_time: Dead timer countdown in seconds.
        neighbor_address: IPv6 link-local address of the neighbor. Omitted when
            the device does not emit a ``Neighbor-address`` continuation line
            for this entry.
    """

    neighbor_id: str
    interface: str
    state: str
    priority: int
    dead_time: int
    neighbor_address: NotRequired[str]


class ShowOspf3NeighborResult(TypedDict):
    """Schema for 'show ospf3 neighbor' parsed output.

    Top-level dict-of-dicts keyed by neighbor router ID.
    """

    neighbors: dict[str, Ospf3NeighborEntry]


# Junos 'show ospf3 neighbor' output format:
# ID               Interface              State     Pri   Dead
# 10.189.5.253     ge-0/0/0.0             Full      128     35
#   Neighbor-address fe80::250:56ff:fe8d:53c0
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<neighbor_id>{IPV4_ADDRESS})\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<dead_time>\d+)\s*$"
)

_NEIGHBOR_ADDRESS_PATTERN = re.compile(
    r"^\s+Neighbor-address\s+(?P<neighbor_address>\S+)\s*$"
)

# Junos prompt lines like "{master:0}" or "{primary:node0}"
_PROMPT_PATTERN = re.compile(r"^\{.+\}\s*$")


@register(OS.JUNIPER_JUNOS, "show ospf3 neighbor")
class ShowOspf3NeighborParser(BaseParser[ShowOspf3NeighborResult]):
    """Parser for 'show ospf3 neighbor' command on Juniper Junos.

    Parses OSPFv3 neighbor adjacency information from the neighbor table.
    Neighbors are keyed by their router ID.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowOspf3NeighborResult:
        """Parse 'show ospf3 neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by neighbor router ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, Ospf3NeighborEntry] = {}
        last_neighbor_id: str | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if _PROMPT_PATTERN.match(stripped):
                continue

            neighbor_match = _NEIGHBOR_PATTERN.match(stripped)
            if neighbor_match:
                neighbor_id = neighbor_match.group("neighbor_id")
                last_neighbor_id = neighbor_id
                neighbors[neighbor_id] = Ospf3NeighborEntry(
                    neighbor_id=neighbor_id,
                    interface=neighbor_match.group("interface"),
                    state=neighbor_match.group("state"),
                    priority=int(neighbor_match.group("priority")),
                    dead_time=int(neighbor_match.group("dead_time")),
                )
                continue

            addr_match = _NEIGHBOR_ADDRESS_PATTERN.match(line)
            if addr_match and last_neighbor_id is not None:
                neighbors[last_neighbor_id]["neighbor_address"] = addr_match.group(
                    "neighbor_address"
                )
                continue

        if not neighbors:
            msg = "No OSPFv3 neighbors found in output"
            raise ValueError(msg)

        return cast(ShowOspf3NeighborResult, {"neighbors": neighbors})
