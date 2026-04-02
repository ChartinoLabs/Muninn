"""Parser for 'show cef drops location' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CefDropEntry(TypedDict):
    """Schema for a single CEF drop counter within a node."""

    packets: int


class CefDropNodeEntry(TypedDict):
    """Schema for a single node's CEF drop statistics."""

    drops: dict[str, CefDropEntry]


# Top-level result keyed by node location (e.g. '0/RSP0/CPU0').
ShowCefDropsLocationResult = dict[str, CefDropNodeEntry]


@register(OS.CISCO_IOSXR, "show cef drops location")
class ShowCefDropsLocationParser(BaseParser[ShowCefDropsLocationResult]):
    """Parser for 'show cef drops location' on Cisco IOS-XR.

    Parses per-node CEF drop counters into a dict-of-dicts keyed by
    node location, then by drop reason.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _NODE_HEADER = re.compile(r"^Node:\s+(?P<node>\S+)")
    _DROP_LINE = re.compile(r"^\s+(?P<reason>.+?)\s+packets\s*:\s+(?P<packets>\d+)\s*$")

    @classmethod
    def parse(cls, output: str) -> ShowCefDropsLocationResult:
        """Parse 'show cef drops location' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by node location, each containing a drops dict
            keyed by drop reason name.

        Raises:
            ValueError: If no node data is found in the output.
        """
        result: ShowCefDropsLocationResult = {}
        current_node: str | None = None

        for line in output.splitlines():
            node_match = cls._NODE_HEADER.match(line)
            if node_match:
                current_node = node_match.group("node")
                result[current_node] = CefDropNodeEntry(drops={})
                continue

            if current_node is None:
                continue

            drop_match = cls._DROP_LINE.match(line)
            if drop_match:
                reason = drop_match.group("reason").strip()
                packets = int(drop_match.group("packets"))
                result[current_node]["drops"][reason] = CefDropEntry(
                    packets=packets,
                )

        if not result:
            msg = "No CEF drop statistics found in output"
            raise ValueError(msg)

        return result
