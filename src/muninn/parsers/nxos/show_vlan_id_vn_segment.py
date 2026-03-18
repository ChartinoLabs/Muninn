"""Parser for 'show vlan id 1-4093 vn-segment' command on NX-OS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class VlanSegmentEntry(TypedDict):
    """Schema for a VLAN to VN-segment mapping."""

    vlan_id: str
    vn_segment_id: int


class ShowVlanIdVnSegmentResult(TypedDict):
    """Schema for 'show vlan id 1-4093 vn-segment' parsed output."""

    vlans: dict[str, VlanSegmentEntry]


@register(OS.CISCO_NXOS, "show vlan id 1-4093 vn-segment")
class ShowVlanIdVnSegmentParser(BaseParser[ShowVlanIdVnSegmentResult]):
    """Parser for 'show vlan id 1-4093 vn-segment' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.SWITCHING,
            ParserTag.VLAN,
        }
    )

    _ROW_PATTERN = re.compile(r"^(?P<vlan>\d+)\s+(?P<segment>\d+)$")

    @classmethod
    def parse(cls, output: str) -> ShowVlanIdVnSegmentResult:
        """Parse 'show vlan id 1-4093 vn-segment' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed VLAN to VN-segment mapping.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        vlans: dict[str, VlanSegmentEntry] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.lower().startswith("vlan") or set(line) == {"-"}:
                continue

            match = cls._ROW_PATTERN.match(line)
            if match:
                vlan_id = match.group("vlan")
                vlans[vlan_id] = {
                    "vlan_id": vlan_id,
                    "vn_segment_id": int(match.group("segment")),
                }

        if not vlans:
            msg = "No VLAN segment mappings found"
            raise ValueError(msg)

        return ShowVlanIdVnSegmentResult(vlans=vlans)
