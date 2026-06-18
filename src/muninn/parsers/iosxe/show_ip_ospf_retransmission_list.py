"""Parser for 'show ip ospf retransmission-list' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_PROCESS_RE = re.compile(
    rf"OSPF Router with ID \((?P<router_id>{IPV4_ADDRESS})\)"
    r" \(Process ID (?P<process_id>\d+)\)"
)

_NEIGHBOR_RE = re.compile(
    rf"Neighbor (?P<neighbor_id>{IPV4_ADDRESS}),\s+"
    rf"interface (?P<interface>\S+)\s+"
    rf"address (?P<address>{IPV4_ADDRESS})"
)


class RetransmissionNeighborEntry(TypedDict):
    """Schema for a single retransmission-list neighbor entry."""

    address: str


class OspfProcessRetransmissionEntry(TypedDict):
    """Schema for a single OSPF process retransmission-list block."""

    router_id: str
    neighbors: dict[str, dict[str, RetransmissionNeighborEntry]]


class ShowIpOspfRetransmissionListResult(TypedDict):
    """Schema for 'show ip ospf retransmission-list' parsed output."""

    processes: dict[str, OspfProcessRetransmissionEntry]


@register(OS.CISCO_IOSXE, "show ip ospf retransmission-list")
class ShowIpOspfRetransmissionListParser(
    BaseParser[ShowIpOspfRetransmissionListResult],
):
    """Parser for 'show ip ospf retransmission-list' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.OSPF, ParserTag.ROUTING}
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfRetransmissionListResult:
        """Parse 'show ip ospf retransmission-list' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed retransmission-list data keyed by process ID.

        Raises:
            ValueError: If no OSPF processes found in output.
        """
        processes: dict[str, dict] = {}
        current_process_id: str | None = None

        for line in output.splitlines():
            process_match = _PROCESS_RE.search(line)
            if process_match:
                current_process_id = process_match.group("process_id")
                router_id = process_match.group("router_id")
                processes[current_process_id] = {
                    "router_id": router_id,
                    "neighbors": {},
                }
                continue

            if current_process_id is None:
                continue

            neighbor_match = _NEIGHBOR_RE.search(line)
            if neighbor_match:
                neighbor_id = neighbor_match.group("neighbor_id")
                interface = canonical_interface_name(
                    neighbor_match.group("interface"), os=OS.CISCO_IOSXE
                )
                address = neighbor_match.group("address")

                neighbors = processes[current_process_id]["neighbors"]
                if interface not in neighbors:
                    neighbors[interface] = {}

                neighbors[interface][neighbor_id] = {
                    "address": address,
                }

        if not processes:
            msg = "No OSPF processes found in output"
            raise ValueError(msg)

        return cast(ShowIpOspfRetransmissionListResult, {"processes": processes})
