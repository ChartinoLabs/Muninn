"""Parser for 'show adjacency' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class AdjacencyEntry(TypedDict):
    """Schema for a single adjacency entry."""

    protocol: str
    incomplete: NotRequired[bool]


class ShowAdjacencyResult(TypedDict):
    """Schema for 'show adjacency' parsed output.

    Keyed by next-hop address, then interface name.
    """

    adjacencies: dict[str, dict[str, AdjacencyEntry]]


# Matches an adjacency table entry line:
# IP       GigabitEthernet0/0/0      10.180.14.15(13)
# IP       Tunnel0                   227.0.0.0(3) (incomplete)
_ENTRY_PATTERN = re.compile(
    r"^(?P<protocol>\S+)\s+"
    r"(?P<interface>\S+)\s+"
    r"(?P<address>\S+?)"
    r"\(\d+\)"
    r"(?:\s+\((?P<flags>[^)]+)\))?"
    r"\s*$",
)


@register(OS.CISCO_IOS, "show adjacency")
class ShowAdjacencyParser(BaseParser[ShowAdjacencyResult]):
    """Parser for 'show adjacency' command.

    Parses adjacency table entries showing protocol, interface, and
    next-hop address relationships.
    """

    @classmethod
    def parse(cls, output: str) -> ShowAdjacencyResult:
        """Parse 'show adjacency' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed adjacency entries keyed by address, then interface.

        Raises:
            ValueError: If no adjacency entries found.
        """
        adjacencies: dict[str, dict[str, AdjacencyEntry]] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _ENTRY_PATTERN.match(line)
            if not match:
                continue

            protocol = match.group("protocol")
            raw_interface = match.group("interface")
            address = match.group("address")
            flags = match.group("flags")

            interface = canonical_interface_name(raw_interface, os=OS.CISCO_IOS)

            entry: AdjacencyEntry = {
                "protocol": protocol,
            }

            if flags and "incomplete" in flags.lower():
                entry["incomplete"] = True

            if address not in adjacencies:
                adjacencies[address] = {}
            adjacencies[address][interface] = entry

        if not adjacencies:
            msg = "No adjacency entries found in output"
            raise ValueError(msg)

        return ShowAdjacencyResult(adjacencies=adjacencies)
