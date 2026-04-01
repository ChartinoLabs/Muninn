"""Parser for 'show pim ipv4 neighbor' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS
from muninn.registry import register
from muninn.tags import ParserTag


class PimNeighborEntry(TypedDict):
    """Schema for a single PIM neighbor entry."""

    interface: str
    uptime: str
    expires: str
    dr_priority: int
    is_designated_router: bool
    bidir_capable: bool
    proxy_capable: bool
    ecmp_redirect_capable: bool
    is_self: bool
    bfd_state: NotRequired[str]


ShowPimIpv4NeighborResult = dict[str, PimNeighborEntry]

# Neighbor row pattern for IOS-XR PIM neighbor table:
# 192.0.2.1*                   Bundle-Ether10.10      1d09h     00:01:29 1      B E
# 192.0.2.2                    Bundle-Ether10.20      02:26:23  00:01:26 1 (DR)
_NEIGHBOR_PATTERN = re.compile(
    rf"^(?P<address>{IPV4_ADDRESS})(?P<self_flag>\*)?\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<uptime>\S+)\s+"
    r"(?P<expires>\S+)\s+"
    r"(?P<dr_pri>\d+)\s*"
    r"(?P<dr_flag>\(DR\))?\s*"
    r"(?P<flags>[BPDE\s]*)$"
)


@register(OS.CISCO_IOSXR, "show pim ipv4 neighbor")
class ShowPimIpv4NeighborParser(BaseParser["ShowPimIpv4NeighborResult"]):
    """Parser for 'show pim ipv4 neighbor' command on IOS-XR.

    Parses PIM neighbor adjacency information. Neighbors are keyed by
    their IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    @classmethod
    def parse(cls, output: str) -> "ShowPimIpv4NeighborResult":
        """Parse 'show pim ipv4 neighbor' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary keyed by neighbor address with neighbor details.

        Raises:
            ValueError: If no PIM neighbors found in output.
        """
        result: ShowPimIpv4NeighborResult = {}

        for line in output.splitlines():
            match = _NEIGHBOR_PATTERN.match(line.strip())
            if match is None:
                continue

            address = match.group("address")
            flags = match.group("flags").strip()
            flag_set = set(flags.split()) if flags else set()

            entry = PimNeighborEntry(
                interface=match.group("interface"),
                uptime=match.group("uptime"),
                expires=match.group("expires"),
                dr_priority=int(match.group("dr_pri")),
                is_designated_router=match.group("dr_flag") is not None,
                bidir_capable="B" in flag_set,
                proxy_capable="P" in flag_set,
                ecmp_redirect_capable="E" in flag_set,
                is_self=match.group("self_flag") is not None,
            )

            result[address] = entry

        if not result:
            msg = "No PIM neighbors found in output"
            raise ValueError(msg)

        return result
