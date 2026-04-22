"""Parser for 'show pim ipv4 neighbor' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PimNeighborEntry(TypedDict):
    """Schema for a single PIM neighbor entry."""

    interface: str
    uptime: str
    expires: str
    mode: str
    transport: str


ShowPimIpv4NeighborResult = dict[str, dict[str, PimNeighborEntry]]


@register(OS.ARISTA_EOS, "show pim ipv4 neighbor")
class ShowPimIpv4NeighborParser(BaseParser[ShowPimIpv4NeighborResult]):
    """Parser for 'show pim ipv4 neighbor' command on Arista EOS.

    Returns a nested dict keyed by VRF name, then neighbor IP address.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    _VRF_HEADER = re.compile(r"^PIM Neighbor Table for (?P<vrf>\S+) VRF$")

    # Columns: Neighbor Address, Interface, Uptime, Expires, Mode, Transport
    _NEIGHBOR_LINE = re.compile(
        r"^(?P<neighbor>\d+\.\d+\.\d+\.\d+)"
        r"\s+(?P<interface>\S+)"
        r"\s+(?P<uptime>\S+)"
        r"\s+(?P<expires>\S+)"
        r"\s+(?P<mode>\S+)"
        r"\s+(?P<transport>\S+)$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowPimIpv4NeighborResult:
        """Parse 'show pim ipv4 neighbor' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Nested dict keyed by VRF name, then neighbor IP address.
        """
        result: ShowPimIpv4NeighborResult = {}
        current_vrf = "default"

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            vrf_match = cls._VRF_HEADER.match(stripped)
            if vrf_match:
                current_vrf = vrf_match.group("vrf")
                continue

            neighbor_match = cls._NEIGHBOR_LINE.match(stripped)
            if neighbor_match:
                neighbor_addr = neighbor_match.group("neighbor")
                if current_vrf not in result:
                    result[current_vrf] = {}
                result[current_vrf][neighbor_addr] = PimNeighborEntry(
                    interface=canonical_interface_name(
                        neighbor_match.group("interface"), os=OS.ARISTA_EOS
                    ),
                    uptime=neighbor_match.group("uptime"),
                    expires=neighbor_match.group("expires"),
                    mode=neighbor_match.group("mode"),
                    transport=neighbor_match.group("transport"),
                )

        return result
