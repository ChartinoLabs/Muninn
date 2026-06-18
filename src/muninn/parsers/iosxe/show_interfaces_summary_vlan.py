"""Parser for 'show interfaces summary vlan' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Matches "Total number of Vlan interfaces: <N>"
_TOTAL_RE = re.compile(
    r"^\s*Total\s+number\s+of\s+Vlan\s+interfaces:\s*(?P<total>\d+)\s*$",
    re.IGNORECASE,
)

# Matches the "Vlan interfaces configured:" section header.
_CONFIGURED_HEADER_RE = re.compile(
    r"^\s*Vlan\s+interfaces\s+configured:\s*$",
    re.IGNORECASE,
)

# Matches a line containing only VLAN IDs (one or more integers).
_VLAN_IDS_RE = re.compile(r"^\s*(\d+(?:\s+\d+)*)\s*$")


class ShowInterfacesSummaryVlanResult(TypedDict):
    """Schema for 'show interfaces summary vlan' parsed output.

    Contains the total count of VLAN interfaces and a sorted list
    of configured VLAN IDs.
    """

    total: int
    configured_vlans: list[int]


def _parse_vlan_ids(lines: list[str], start: int) -> list[int]:
    """Extract VLAN IDs from lines following the configured header.

    Args:
        lines: All output lines.
        start: Index of the first line after the header.

    Returns:
        Sorted list of VLAN IDs found.
    """
    vlans: list[int] = []
    for line in lines[start:]:
        ids_match = _VLAN_IDS_RE.match(line)
        if ids_match:
            vlans.extend(int(v) for v in ids_match.group(1).split())
    vlans.sort()
    return vlans


@register(OS.CISCO_IOSXE, "show interfaces summary vlan")
class ShowInterfacesSummaryVlanParser(
    BaseParser[ShowInterfacesSummaryVlanResult],
):
    """Parser for 'show interfaces summary vlan' on Cisco IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.INTERFACES, ParserTag.VLAN}
    )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesSummaryVlanResult:
        """Parse 'show interfaces summary vlan' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed result with total VLAN interface count and list of
            configured VLAN IDs.

        Raises:
            ValueError: If the total count line cannot be found.
        """
        lines = output.splitlines()
        total: int | None = None
        configured_vlans: list[int] = []

        for idx, line in enumerate(lines):
            total_match = _TOTAL_RE.match(line)
            if total_match:
                total = int(total_match.group("total"))
                continue

            if _CONFIGURED_HEADER_RE.match(line):
                configured_vlans = _parse_vlan_ids(lines, idx + 1)
                break

        if total is None:
            msg = "Missing 'Total number of Vlan interfaces' line in output"
            raise ValueError(msg)

        return ShowInterfacesSummaryVlanResult(
            total=total,
            configured_vlans=configured_vlans,
        )
