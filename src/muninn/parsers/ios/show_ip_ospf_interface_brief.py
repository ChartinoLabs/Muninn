"""Parser for 'show ip ospf interface brief' command on IOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Header line that marks the start of tabular data
_HEADER_RE = re.compile(
    r"^Interface\s+PID\s+Area\s+IP Address/Mask\s+Cost\s+State\s+Nbrs F/C"
)

# Data line: interface, PID, area, IP/mask, cost, state, nbrs_full/nbrs_count
_DATA_RE = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<pid>\d+)\s+"
    r"(?P<area>\S+)\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)/(?P<mask>\d+)\s+"
    r"(?P<cost>\d+)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<nbrs_full>\d+)/(?P<nbrs_count>\d+)\s*$"
)


def _normalize_area(area: str) -> str:
    """Normalize area to dotted notation.

    Plain integers are converted: '0' -> '0.0.0.0', '11' -> '0.0.0.11'.
    Already-dotted values are returned as-is.
    """
    if "." in area:
        return area
    num = int(area)
    return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"


class OspfInterfaceBriefEntry(TypedDict):
    """Schema for a single OSPF interface brief entry."""

    process_id: int
    area: str
    ip_address: str
    prefix_length: int
    cost: int
    state: str
    neighbors_full: int
    neighbors_count: int


class ShowIpOspfInterfaceBriefResult(TypedDict):
    """Schema for 'show ip ospf interface brief' parsed output."""

    interfaces: dict[str, OspfInterfaceBriefEntry]


@register(OS.CISCO_IOS, "show ip ospf interface brief")
class ShowIpOspfInterfaceBriefParser(
    BaseParser[ShowIpOspfInterfaceBriefResult],
):
    """Parser for 'show ip ospf interface brief' on IOS.

    Parses the OSPF interface summary table showing interface name,
    process ID, area, IP address/mask, cost, state, and neighbor counts.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.OSPF,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpOspfInterfaceBriefResult:
        """Parse 'show ip ospf interface brief' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed OSPF interface brief entries keyed by interface name.
        """
        interfaces: dict[str, OspfInterfaceBriefEntry] = {}

        for line in output.splitlines():
            match = _DATA_RE.match(line)
            if not match:
                continue

            raw_name = match.group("interface")
            name = canonical_interface_name(raw_name, os=OS.CISCO_IOS)

            entry: OspfInterfaceBriefEntry = {
                "process_id": int(match.group("pid")),
                "area": _normalize_area(match.group("area")),
                "ip_address": match.group("ip"),
                "prefix_length": int(match.group("mask")),
                "cost": int(match.group("cost")),
                "state": match.group("state"),
                "neighbors_full": int(match.group("nbrs_full")),
                "neighbors_count": int(match.group("nbrs_count")),
            }

            interfaces[name] = entry

        return cast(ShowIpOspfInterfaceBriefResult, {"interfaces": interfaces})
