"""Parser for 'show ip eigrp neighbors' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.utils import canonical_interface_name


class EigrpNeighborEntry(TypedDict):
    """Schema for a single EIGRP neighbor entry."""

    handle: int
    hold_time: int
    uptime: str
    srtt: int
    rto: int
    queue_count: int
    sequence_number: int


class ShowIpEigrpNeighborsResult(TypedDict):
    """Schema for 'show ip eigrp neighbors' parsed output."""

    neighbors: dict[str, dict[str, EigrpNeighborEntry]]


@register(OS.CISCO_IOSXE, "show ip eigrp neighbors")
class ShowIpEigrpNeighborsParser(BaseParser[ShowIpEigrpNeighborsResult]):
    """Parser for 'show ip eigrp neighbors' command.

    Example output:
        H   Address      Interface  Hold  Uptime    SRTT   RTO    Q   Seq
                                    (sec)           (ms)          Cnt Num
        0   10.1.1.2     Gi0/0      13    00:00:03  1996   5000   0   5
    """

    tags: ClassVar[frozenset[str]] = frozenset({"eigrp", "routing"})

    _ROW_PATTERN = re.compile(
        r"^(?P<handle>\d+)\s+"
        rf"(?P<address>{IPV4_ADDRESS})\s+"
        r"(?P<interface>\S+)\s+"
        r"(?P<hold>\d+)\s+"
        r"(?P<uptime>\S+)\s+"
        r"(?P<srtt>\d+)\s+"
        r"(?P<rto>\d+)\s+"
        r"(?P<q_count>\d+)\s+"
        r"(?P<seq_num>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpEigrpNeighborsResult:
        """Parse 'show ip eigrp neighbors' output.

        Args:
            output: Raw CLI output from 'show ip eigrp neighbors' command.

        Returns:
            Parsed neighbor data keyed by interface then neighbor address.

        Raises:
            ValueError: If no neighbors found in output.
        """
        neighbors: dict[str, dict[str, EigrpNeighborEntry]] = {}

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

            neighbors[interface][address] = EigrpNeighborEntry(
                handle=int(match.group("handle")),
                hold_time=int(match.group("hold")),
                uptime=match.group("uptime"),
                srtt=int(match.group("srtt")),
                rto=int(match.group("rto")),
                queue_count=int(match.group("q_count")),
                sequence_number=int(match.group("seq_num")),
            )

        if not neighbors:
            msg = "No EIGRP neighbors found in output"
            raise ValueError(msg)

        return ShowIpEigrpNeighborsResult(neighbors=neighbors)
