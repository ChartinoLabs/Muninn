"""Parser for 'show ip ospf neighbor' command on IOS/IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.utils import canonical_interface_name


class OspfNeighborEntry(TypedDict):
    """Schema for a single OSPF neighbor entry."""

    priority: int
    state: str
    dead_time: str
    address: str
    role: NotRequired[str]


class ShowIpOspfNeighborResult(TypedDict):
    """Schema for 'show ip ospf neighbor' parsed output."""

    neighbors: dict[str, dict[str, OspfNeighborEntry]]


@register(OS.CISCO_IOS, "show ip ospf neighbor")
@register(OS.CISCO_IOSXE, "show ip ospf neighbor")
class ShowIpOspfNeighborParser(BaseParser[ShowIpOspfNeighborResult]):
    """Parser for 'show ip ospf neighbor' command.

    Parses OSPF neighbor adjacency information.
    """

    # Pattern for neighbor entries
    # Neighbor ID     Pri   State           Dead Time   Address         Interface
    # 172.18.197.242    1   FULL/BDR        00:00:32    172.19.197.93
    #                                                GigabitEthernet0/0/0
    # 10.16.2.2         0   FULL/  -        00:00:32    10.169.197.97   GigabitEthernet4
    _NEIGHBOR_PATTERN = re.compile(
        rf"^(?P<neighbor_id>{IPV4_ADDRESS})\s+"
        r"(?P<priority>\d+)\s+"
        r"(?P<state>\w+)/\s*(?P<role>DR|BDR|-)\s+"
        r"(?P<dead_time>\d{2}:\d{2}:\d{2})\s+"
        rf"(?P<address>{IPV4_ADDRESS})\s+"
        r"(?P<interface>\S+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfNeighborResult:
        """Parse 'show ip ospf neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed neighbor data keyed by interface then neighbor ID.

        Raises:
            ValueError: If no neighbors found.
        """
        neighbors: dict[str, dict[str, OspfNeighborEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._NEIGHBOR_PATTERN.match(line)
            if match:
                interface = canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXE
                )
                neighbor_id = match.group("neighbor_id")
                role = match.group("role")

                if interface not in neighbors:
                    neighbors[interface] = {}

                entry: OspfNeighborEntry = {
                    "priority": int(match.group("priority")),
                    "state": match.group("state").upper(),
                    "dead_time": match.group("dead_time"),
                    "address": match.group("address"),
                }

                if role != "-":
                    entry["role"] = role

                neighbors[interface][neighbor_id] = entry

        if not neighbors:
            msg = "No OSPF neighbors found in output"
            raise ValueError(msg)

        return ShowIpOspfNeighborResult(neighbors=neighbors)
