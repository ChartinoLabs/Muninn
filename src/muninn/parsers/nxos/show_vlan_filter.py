"""Parser for 'show vlan filter' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class VlanFilterEntry(TypedDict):
    """Schema for a VLAN filter entry."""

    access_map_tag: str


class ShowVlanFilterResult(TypedDict):
    """Schema for 'show vlan filter' parsed output."""

    vlan_id: dict[str, VlanFilterEntry]


@register(OS.CISCO_NXOS, "show vlan filter")
class ShowVlanFilterParser(BaseParser[ShowVlanFilterResult]):
    """Parser for 'show vlan filter' command.

    Example output:
        vlan map ed:
        Configured on VLANs:    3,402
    """

    _MAP_PATTERN = re.compile(r"^vlan\s+map\s+(?P<tag>\S+):$", re.I)
    _VLANS_PATTERN = re.compile(
        r"^Configured\s+on\s+VLANs:\s+(?P<vlans>[\d,\s]+)$", re.I
    )

    @classmethod
    def parse(cls, output: str) -> ShowVlanFilterResult:
        """Parse 'show vlan filter' output.

        Args:
            output: Raw CLI output from 'show vlan filter' command.

        Returns:
            Parsed VLAN filter data keyed by VLAN ID.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: ShowVlanFilterResult = {"vlan_id": {}}
        access_map_tag: str | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._MAP_PATTERN.match(line)
            if match:
                access_map_tag = match.group("tag")
                continue

            match = cls._VLANS_PATTERN.match(line)
            if match and access_map_tag:
                vlans = [
                    v.strip() for v in match.group("vlans").split(",") if v.strip()
                ]
                for vlan_id in vlans:
                    result["vlan_id"][vlan_id] = {"access_map_tag": access_map_tag}

        if not result["vlan_id"]:
            msg = "No matching VLAN filter entries found"
            raise ValueError(msg)

        return result
