"""Parser for 'show drops np all' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DropCounter(TypedDict):
    """Schema for an individual drop counter."""

    packets: int


class NpDrops(TypedDict):
    """Schema for drops on a single Network Processor."""

    counters: dict[str, DropCounter]


class ShowDropsNpAllResult(TypedDict):
    """Schema for 'show drops np all' parsed output.

    Keyed by node location, then by NP index (as string).
    """

    nodes: dict[str, dict[str, NpDrops]]


@register(OS.CISCO_IOSXR, "show drops np all")
class ShowDropsNpAllParser(BaseParser[ShowDropsNpAllResult]):
    """Parser for 'show drops np all' command on Cisco IOS-XR.

    Parses per-node, per-NP packet drop counters from network processors.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    _NODE_PATTERN = re.compile(r"Node:\s+(?P<node>\S+)")
    _NP_HEADER_PATTERN = re.compile(r"^NP\s+(?P<np_id>\d+)\s+Drops:")
    _COUNTER_PATTERN = re.compile(r"^(?P<name>[A-Z][A-Z0-9_]+)\s+(?P<packets>\d+)\s*$")

    @classmethod
    def _parse_node(cls, line: str, nodes: dict[str, dict[str, NpDrops]]) -> str | None:
        """Try to parse a node header line, returning the node name if matched."""
        node_match = cls._NODE_PATTERN.search(line)
        if not node_match:
            return None
        node = node_match.group("node")
        if node not in nodes:
            nodes[node] = {}
        return node

    @classmethod
    def _parse_np_header(cls, line: str) -> str | None:
        """Try to parse an NP header line, returning the NP ID if matched."""
        np_match = cls._NP_HEADER_PATTERN.match(line)
        if np_match:
            return np_match.group("np_id")
        return None

    @classmethod
    def _parse_counter(cls, line: str, np_drops: NpDrops) -> bool:
        """Try to parse a counter line and add it to the NP drops dict."""
        counter_match = cls._COUNTER_PATTERN.match(line)
        if not counter_match:
            return False
        name = counter_match.group("name")
        packets = int(counter_match.group("packets"))
        np_drops["counters"][name] = DropCounter(packets=packets)
        return True

    @classmethod
    def parse(cls, output: str) -> ShowDropsNpAllResult:
        """Parse 'show drops np all' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed drop counter data organized by node and NP.

        Raises:
            ValueError: If no node information is found in the output.
        """
        nodes: dict[str, dict[str, NpDrops]] = {}
        current_node: str | None = None
        current_np_drops: NpDrops | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("---"):
                continue

            parsed_node = cls._parse_node(stripped, nodes)
            if parsed_node is not None:
                current_node = parsed_node
                current_np_drops = None
                continue

            if current_node is None:
                continue

            np_id = cls._parse_np_header(stripped)
            if np_id is not None:
                current_np_drops = NpDrops(counters={})
                nodes[current_node][np_id] = current_np_drops
                continue

            if current_np_drops is not None:
                cls._parse_counter(stripped, current_np_drops)

        if not nodes:
            msg = "No node information found in output"
            raise ValueError(msg)

        return ShowDropsNpAllResult(nodes=nodes)
