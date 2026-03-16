"""Parser for 'show ipv6 eigrp neighbors' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class Ipv6EigrpNeighborEntry(TypedDict):
    """Schema for a single IPv6 EIGRP neighbor entry."""

    handle: int
    hold_time: int
    uptime: str
    srtt: int
    rto: int
    queue_count: int
    sequence_number: int


class ShowIpv6EigrpNeighborsResult(TypedDict):
    """Schema for 'show ipv6 eigrp neighbors' parsed output."""

    neighbors: dict[str, dict[str, Ipv6EigrpNeighborEntry]]


@register(OS.CISCO_IOSXE, "show ipv6 eigrp neighbors")
class ShowIpv6EigrpNeighborsParser(BaseParser[ShowIpv6EigrpNeighborsResult]):
    """Parser for 'show ipv6 eigrp neighbors' command.

    Example output::

        EIGRP-IPv6 Neighbors for AS(1)
        H   Address              Interface   Hold Uptime  SRTT  RTO Q Seq
                                             (sec)        (ms)     Cnt Num
        0   FE80::A8BB:CCFF:FE00:200 Gi0/0   12 00:00:21  10  100 0  3
    """

    tags: ClassVar[frozenset[str]] = frozenset({"eigrp", "routing"})

    _ROW_PATTERN = re.compile(
        r"^(?P<handle>\d+)\s+"
        r"(?P<address>[0-9A-Fa-f:]+(?:%\S+)?)\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<hold>\d+)\s+"
        r"(?P<uptime>\S+)\s+"
        r"(?P<srtt>\d+)\s+"
        r"(?P<rto>\d+)\s+"
        r"(?P<q_count>\d+)\s+"
        r"(?P<seq_num>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpv6EigrpNeighborsResult:
        """Parse 'show ipv6 eigrp neighbors' output.

        Args:
            output: Raw CLI output from 'show ipv6 eigrp neighbors' command.

        Returns:
            Parsed neighbor data keyed by interface then neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, dict[str, Ipv6EigrpNeighborEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._ROW_PATTERN.match(line)
            if not match:
                continue

            interface = canonical_interface_name(
                match.group("interface"), os=OS.CISCO_IOSXE
            )
            address = match.group("address")

            if interface not in neighbors:
                neighbors[interface] = {}

            neighbors[interface][address] = Ipv6EigrpNeighborEntry(
                handle=int(match.group("handle")),
                hold_time=int(match.group("hold")),
                uptime=match.group("uptime"),
                srtt=int(match.group("srtt")),
                rto=int(match.group("rto")),
                queue_count=int(match.group("q_count")),
                sequence_number=int(match.group("seq_num")),
            )

        if not neighbors:
            msg = "No EIGRP IPv6 neighbors found in output"
            raise ValueError(msg)

        return ShowIpv6EigrpNeighborsResult(neighbors=neighbors)
