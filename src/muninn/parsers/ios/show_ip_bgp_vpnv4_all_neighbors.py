"""Parser for 'show ip bgp vpnv4 all neighbors' command on Cisco IOS.

This command produces output identical in format to 'show ip bgp neighbors'
on IOS-XE.  We reuse the existing parsing logic and register it under the
additional command name and OS.
"""

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.iosxe.show_ip_bgp_neighbors import (
    NeighborEntry,
    ShowIpBgpNeighborsResult,
    _parse_neighbor_block,
    _split_neighbor_blocks,
)
from muninn.registry import register

__all__ = ["ShowIpBgpVpnv4AllNeighborsParser"]


@register(OS.CISCO_IOS, "show ip bgp vpnv4 all neighbors")
class ShowIpBgpVpnv4AllNeighborsParser(BaseParser["ShowIpBgpNeighborsResult"]):
    """Parser for 'show ip bgp vpnv4 all neighbors' on Cisco IOS.

    Example output::

        BGP neighbor is 10.255.11.4,  vrf VRF11,
          remote AS 65514,  local AS 65534, external link
          BGP version 4, remote router ID 10.255.255.6
          BGP state = Established, up for 2w6d
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpNeighborsResult:
        """Parse 'show ip bgp vpnv4 all neighbors' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed data keyed by neighbor IP address.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        blocks = _split_neighbor_blocks(output)
        neighbors: dict[str, NeighborEntry] = {}

        for neighbor_ip, block_lines in blocks:
            neighbors[neighbor_ip] = _parse_neighbor_block(block_lines)

        return {"neighbors": neighbors}
