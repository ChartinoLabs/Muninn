"""Parser for 'show bgp l2vpn evpn neighbors' command on Cisco IOS-XR.

IOS-XR ``show bgp l2vpn evpn neighbors`` displays detailed information about
BGP neighbors participating in the L2VPN EVPN address family.  The output
format is identical to ``show bgp neighbors``; parsing logic is reused from
that parser.

The parser produces a dict-of-dicts keyed by neighbor IP address (IPv4 or
IPv6).
"""

from typing import ClassVar

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.cisco_iosxr.show_bgp_neighbors import (
    ShowBgpNeighborsResult,
    _build_neighbor_entry,
    _split_neighbor_blocks,
)
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpL2vpnEvpnNeighborsParser"]


@register(OS.CISCO_IOSXR, "show bgp l2vpn evpn neighbors")
class ShowBgpL2vpnEvpnNeighborsParser(BaseParser[ShowBgpNeighborsResult]):
    """Parser for 'show bgp l2vpn evpn neighbors' on Cisco IOS-XR.

    Parses detailed BGP neighbor information for L2VPN EVPN peers including
    session state, timers, message counters, and per-address-family prefix
    statistics.

    The output format is identical to 'show bgp neighbors'; parsing logic
    is reused from that parser.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpNeighborsResult:
        """Parse 'show bgp l2vpn evpn neighbors' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by neighbor address with detailed neighbor info.

        Raises:
            ValueError: If no neighbor blocks are found in the output.
        """
        blocks = _split_neighbor_blocks(output)
        if not blocks:
            msg = "No BGP neighbor data found in output"
            raise ValueError(msg)

        result: ShowBgpNeighborsResult = {}
        for addr, lines in blocks:
            result[addr] = _build_neighbor_entry(lines)

        return result
