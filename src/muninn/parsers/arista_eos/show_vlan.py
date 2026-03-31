"""Parser for 'show vlan' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class VlanEntry(TypedDict):
    """Schema for a single VLAN entry."""

    name: str
    status: str
    interfaces: list[str]


# Dict-of-dicts keyed by VLAN ID (as string).
ShowVlanResult = dict[str, VlanEntry]


@register(OS.ARISTA_EOS, "show vlan")
class ShowVlanParser(BaseParser[ShowVlanResult]):
    """Parser for 'show vlan' command on Arista EOS.

    Parses VLAN table output into a dict keyed by VLAN ID string,
    with each value containing the VLAN name, status, and list of
    associated interfaces.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.VLAN})

    # Matches a VLAN row: ID, name, status, and optional port list.
    # Example: "10    Test1                            active    Et1, Et2"
    _VLAN_LINE = re.compile(
        r"^(?P<vlan_id>\d+)"
        r"\s+(?P<name>\S+)"
        r"\s+(?P<status>active|suspended|act/lshut|act/unsup)"
        r"(?:\s+(?P<ports>.+))?$"
    )

    # Header / separator lines to skip.
    _SKIP_LINE = re.compile(r"^(?:VLAN|----)")

    @classmethod
    def parse(cls, output: str) -> ShowVlanResult:
        """Parse 'show vlan' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of VLAN entries keyed by VLAN ID string.

        Raises:
            ValueError: If no VLAN entries are found.
        """
        result: ShowVlanResult = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or cls._SKIP_LINE.match(stripped):
                continue

            match = cls._VLAN_LINE.match(stripped)
            if not match:
                continue

            vlan_id = match.group("vlan_id")
            ports_str = match.group("ports")
            interfaces: list[str] = []
            if ports_str:
                interfaces = [p.strip() for p in ports_str.split(",") if p.strip()]

            result[vlan_id] = VlanEntry(
                name=match.group("name"),
                status=match.group("status"),
                interfaces=interfaces,
            )

        if not result:
            msg = "No VLAN entries found in output"
            raise ValueError(msg)

        return result
