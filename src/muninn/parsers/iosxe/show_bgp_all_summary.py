"""Parser for 'show bgp all summary' command on IOS-XE.

This command produces output identical in format to 'show ip bgp summary'
with multiple address-family sections.  We reuse the existing parsing
logic and register it under the additional command name.
"""

from typing import ClassVar

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.ios.show_ip_bgp_summary import (
    AddressFamilyEntry,
    ShowIpBgpSummaryResult,
    _parse_address_family,
    _split_address_families,
    _strip_prompt_lines,
)
from muninn.registry import register
from muninn.tags import ParserTag

__all__ = ["ShowBgpAllSummaryParser"]


@register(OS.CISCO_IOSXE, "show bgp all summary")
@register(OS.CISCO_IOSXE, "show ip bgp all summary")
class ShowBgpAllSummaryParser(BaseParser["ShowIpBgpSummaryResult"]):
    """Parser for 'show bgp all summary' command on IOS-XE.

    Example output::

        For address family: IPv4 Unicast
        BGP router identifier 192.168.111.1, local AS number 100
        BGP table version is 28, main routing table version 28
        ...
        Neighbor  V  AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
        192.168.111.1  4  100  0  0  1  0  0 01:07:38 Idle

    The output format is identical to 'show ip bgp summary'; parsing logic
    is reused from that parser.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.BGP, ParserTag.ROUTING})

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpSummaryResult:
        """Parse 'show bgp all summary' output.

        Args:
            output: Raw CLI output from 'show bgp all summary' command.

        Returns:
            Parsed data with neighbors grouped by address family.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        raw_lines = output.splitlines()
        lines = _strip_prompt_lines(raw_lines)

        sections = _split_address_families(lines)
        address_families: dict[str, AddressFamilyEntry] = {}

        for af_name, af_lines in sections:
            parsed = _parse_address_family(af_lines, af_name)
            if parsed is not None:
                address_families[af_name] = parsed

        return {"address_families": address_families}
