"""Parser for 'show bgp vpnv4 unicast summary' command on Cisco IOS-XR.

IOS-XR ``show bgp vpnv4 unicast summary`` displays BGP process information
and the neighbor table for the VPNv4 unicast address family.  The output
format is identical to ``show bgp summary`` (single-AF variant); parsing
logic is reused from that parser.

The parser produces the same ``ShowBgpSummaryResult`` structure: a dict
with an ``address_families`` key containing a ``"default"`` entry (since
no explicit Address Family header is present in this output).
"""

from typing import ClassVar, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.cisco_iosxr.show_bgp_summary import (
    ShowBgpSummaryParser,
    ShowBgpSummaryResult,
)
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpVpnv4UnicastSummaryParser"]


@register(OS.CISCO_IOSXR, "show bgp vpnv4 unicast summary")
class ShowBgpVpnv4UnicastSummaryParser(BaseParser["ShowBgpSummaryResult"]):
    """Parser for 'show bgp vpnv4 unicast summary' on Cisco IOS-XR.

    Parses BGP process information, speaker table, and neighbor summary
    table for the VPNv4 unicast address family.  Supports IPv6 neighbor
    address wrapping.

    The output format is identical to 'show bgp summary'; parsing logic
    is reused from that parser.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowBgpSummaryResult:
        """Parse 'show bgp vpnv4 unicast summary' output on Cisco IOS-XR.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed BGP summary information with address_families dict.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        return cast(ShowBgpSummaryResult, ShowBgpSummaryParser.parse(output))
