"""Parser for 'show pim ipv4 group-map' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import IPV4_ADDRESS, IPV4_PREFIX
from muninn.registry import register
from muninn.tags import ParserTag


class PimGroupMapEntry(TypedDict):
    """Schema for a single PIM group-map entry."""

    protocol: str
    client: str
    groups: int
    rp_address: str
    active: bool
    bsr_active_in_mrib: bool
    info: NotRequired[str]


# Parsed output keyed by group range (e.g. '224.0.1.1/32').
ShowPimIpv4GroupMapResult = dict[str, PimGroupMapEntry]

# Matches a PIM group-map table row.
# Example: 224.0.1.1/32*       DM    perm     0      0.0.0.0
#          224.0.0.0/4*+       SM    static   7      0.0.0.0         RPF: Null,0.0.0.0
_GROUP_MAP_PATTERN = re.compile(
    rf"^(?P<group_range>{IPV4_PREFIX})"
    r"(?P<flags>[*+]*)\s+"
    r"(?P<protocol>\S+)\s+"
    r"(?P<client>\S+)\s+"
    r"(?P<groups>\d+)\s+"
    rf"(?P<rp_address>{IPV4_ADDRESS})"
    r"(?:\s+(?P<info>\S.*))?$"
)


@register(OS.CISCO_IOSXR, "show pim ipv4 group-map")
class ShowPimIpv4GroupMapParser(BaseParser["ShowPimIpv4GroupMapResult"]):
    """Parser for 'show pim ipv4 group-map' command on IOS-XR.

    Parses the PIM IPv4 group mapping table. Entries are keyed by
    group range (e.g. '224.0.1.1/32').
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    @classmethod
    def parse(cls, output: str) -> "ShowPimIpv4GroupMapResult":
        """Parse 'show pim ipv4 group-map' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed group-map data keyed by group range.

        Raises:
            ValueError: If no group-map entries found in output.
        """
        result: ShowPimIpv4GroupMapResult = {}

        for line in output.splitlines():
            match = _GROUP_MAP_PATTERN.match(line.strip())
            if match is None:
                continue

            group_range = match.group("group_range")
            flags = match.group("flags")

            entry: PimGroupMapEntry = {
                "protocol": match.group("protocol"),
                "client": match.group("client"),
                "groups": int(match.group("groups")),
                "rp_address": match.group("rp_address"),
                "active": "*" in flags,
                "bsr_active_in_mrib": "+" in flags,
            }

            info = match.group("info")
            if info is not None:
                info = info.strip()
                if info:
                    entry["info"] = info

            result[group_range] = entry

        if not result:
            msg = "No PIM group-map entries found in output"
            raise ValueError(msg)

        return result
