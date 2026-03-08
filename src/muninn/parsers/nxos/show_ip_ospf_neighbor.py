"""Parser for 'show ip ospf neighbor' command on NX-OS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class OspfNeighborEntry(TypedDict):
    """Schema for a single NX-OS OSPF neighbor entry."""

    priority: int
    state: str
    up_time: str
    address: str
    role: NotRequired[str]


class ShowIpOspfNeighborResult(TypedDict):
    """Schema for 'show ip ospf neighbor' parsed output."""

    neighbors: dict[str, dict[str, OspfNeighborEntry]]


# Pattern for neighbor table rows on NX-OS:
# Neighbor ID     Pri State            Up Time  Address         Interface
# 192.168.1.8       1 FULL/ -          2y0w     192.168.2.2     Vlan2
# 10.0.0.6          1 INIT/DROTHER     -        77.77.77.77     Po4
_NEIGHBOR_PATTERN = re.compile(
    r"^(?P<neighbor_id>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<priority>\d+)\s+"
    r"(?P<state>\w+)/\s*(?P<role>DR|BDR|DROTHER|-)\s+"
    r"(?P<up_time>\S+)\s+"
    r"(?P<address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"(?P<interface>\S+)\s*$"
)


@register(OS.CISCO_NXOS, "show ip ospf neighbor")
class ShowIpOspfNeighborParser(BaseParser[ShowIpOspfNeighborResult]):
    """Parser for 'show ip ospf neighbor' command on NX-OS.

    Parses OSPF neighbor adjacency information from the neighbor table.
    Neighbors are keyed by canonical interface name, then by neighbor router ID.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNeighborResult:
        """Parse 'show ip ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by interface then neighbor ID.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, dict[str, OspfNeighborEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _NEIGHBOR_PATTERN.match(line)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_NXOS
            )
            neighbor_id = match.group("neighbor_id")
            role = match.group("role")

            if interface not in neighbors:
                neighbors[interface] = {}

            entry: OspfNeighborEntry = {
                "priority": int(match.group("priority")),
                "state": match.group("state").upper(),
                "up_time": match.group("up_time"),
                "address": match.group("address"),
            }

            if role != "-":
                entry["role"] = role

            neighbors[interface][neighbor_id] = entry

        if not neighbors:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return ShowIpOspfNeighborResult(neighbors=neighbors)
