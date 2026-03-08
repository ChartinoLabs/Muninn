"""Parser for 'show bgp vrf all all' command on NX-OS.

This command produces output identical in format to 'show ip bgp'
with multiple VRF and address-family sections.  We reuse the existing
parsing logic and register it under the additional command name.
"""

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.parsers.nxos.show_ip_bgp import (
    ShowIpBgpResult,
    VrfEntry,
    _parse_section,
    _split_sections,
    _strip_noise,
)
from muninn.registry import register

__all__ = ["ShowBgpVrfAllAllParser"]


@register(OS.CISCO_NXOS, "show bgp vrf all all")
class ShowBgpVrfAllAllParser(BaseParser["ShowIpBgpResult"]):
    """Parser for 'show bgp vrf all all' command on NX-OS.

    Example output::

        BGP routing table information for VRF VRF1, address family IPv4 Unicast
        BGP table version is 35, local router ID is 10.229.11.11
        Status: s-suppressed, x-deleted, S-stale, ...
        ...
           Network            Next Hop            Metric     LocPrf     Weight Path
        *>a10.121.0.0/8         0.0.0.0                           100      32768 i

    The output format is identical to 'show ip bgp'; parsing logic
    is reused from that parser.
    """

    @classmethod
    def parse(cls, output: str) -> ShowIpBgpResult:
        """Parse 'show bgp vrf all all' output.

        Args:
            output: Raw CLI output from 'show bgp vrf all all' command.

        Returns:
            Parsed data with routes grouped by VRF, address family,
            and network prefix.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        raw_lines = output.splitlines()
        lines = _strip_noise(raw_lines)

        sections = _split_sections(lines)
        vrfs: dict[str, VrfEntry] = {}

        for vrf_name, af_name, section_lines in sections:
            parsed = _parse_section(section_lines)
            if parsed is None:
                continue

            if vrf_name not in vrfs:
                vrfs[vrf_name] = {"address_families": {}}
            vrfs[vrf_name]["address_families"][af_name] = parsed

        return {"vrfs": vrfs}
