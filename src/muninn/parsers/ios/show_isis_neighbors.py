"""Parser for 'show isis neighbors' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class IsisAdjacencyEntry(TypedDict):
    """Schema for a single IS-IS adjacency (per type on an interface)."""

    state: str
    holdtime: int
    circuit_id: str
    ip_address: NotRequired[str]


class IsisInterfaceEntry(TypedDict):
    """Schema for IS-IS adjacencies on a specific interface, keyed by type."""

    adjacencies: dict[str, IsisAdjacencyEntry]


class IsisNeighborEntry(TypedDict):
    """Schema for an IS-IS neighbor, keyed by interface."""

    interfaces: dict[str, IsisInterfaceEntry]


class ShowIsisNeighborsResult(TypedDict):
    """Schema for 'show isis neighbors' parsed output on IOS."""

    neighbors: dict[str, IsisNeighborEntry]


_NEIGHBOR_ROW_PATTERN = re.compile(
    r"^(?P<system_id>\S+)\s+"
    r"(?P<type>L[12])\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<ip_address>\S+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<holdtime>\d+)\s+"
    r"(?P<circuit_id>\S+)\s*$"
)

_HEADER_PATTERN = re.compile(r"^System\s+Id", re.IGNORECASE)


def _build_adjacency(match: re.Match[str]) -> IsisAdjacencyEntry:
    """Build an adjacency entry from a regex match."""
    holdtime_str = match.group("holdtime")
    try:
        holdtime = int(holdtime_str)
    except ValueError:
        msg = f"Invalid holdtime value: {holdtime_str!r}"
        raise ValueError(msg) from None

    adjacency: IsisAdjacencyEntry = {
        "state": match.group("state"),
        "holdtime": holdtime,
        "circuit_id": match.group("circuit_id"),
    }

    ip_address = match.group("ip_address")
    if ip_address:
        adjacency["ip_address"] = ip_address

    return adjacency


def _insert_adjacency(
    neighbors: dict[str, IsisNeighborEntry],
    system_id: str,
    interface: str,
    adj_type: str,
    adjacency: IsisAdjacencyEntry,
) -> None:
    """Insert an adjacency into the nested neighbor structure."""
    if system_id not in neighbors:
        neighbors[system_id] = IsisNeighborEntry(interfaces={})

    interfaces = neighbors[system_id]["interfaces"]
    if interface not in interfaces:
        interfaces[interface] = IsisInterfaceEntry(adjacencies={})

    interfaces[interface]["adjacencies"][adj_type] = adjacency


@register(OS.CISCO_IOS, "show isis neighbors")
class ShowIsisNeighborsParser(BaseParser["ShowIsisNeighborsResult"]):
    """Parser for 'show isis neighbors' on IOS.

    Example output:
        System Id       Type Interface     IP Address      State Holdtime Circuit Id
        vMX1            L1   Gi2           10.1.2.1        UP    19       XRv3.03
        vMX1            L2   Gi2           10.1.2.1        UP    24       XRv3.03
        XRv3            L1   Gi2           10.1.2.3        UP    8        XRv3.03
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIsisNeighborsResult:
        """Parse 'show isis neighbors' output.

        Args:
            output: Raw CLI output from 'show isis neighbors' command.

        Returns:
            Parsed IS-IS neighbor data keyed by system ID, then interface,
            then adjacency type.

        Raises:
            ValueError: If no IS-IS neighbor entries are found.
        """
        neighbors: dict[str, IsisNeighborEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line or _HEADER_PATTERN.match(line):
                continue

            match = _NEIGHBOR_ROW_PATTERN.match(line)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_IOS
            )
            adjacency = _build_adjacency(match)
            _insert_adjacency(
                neighbors,
                match.group("system_id"),
                interface,
                match.group("type"),
                adjacency,
            )

        if not neighbors:
            msg = "No IS-IS neighbor entries found in output"
            raise ValueError(msg)

        return ShowIsisNeighborsResult(neighbors=neighbors)
