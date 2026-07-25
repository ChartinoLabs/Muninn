"""Parser for 'show isis node summary' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IsisNodeLevelSummary(TypedDict):
    """Schema for IS-IS node summary at a single level.

    Contains the list of node system IDs discovered at this
    IS-IS level and a convenience count.
    """

    nodes: list[str]
    node_count: int


class ShowIsisNodeSummaryResult(TypedDict):
    """Schema for 'show isis node summary' parsed output on IOS-XE.

    Top-level key is a dict of IS-IS tags. Each tag maps level
    identifiers (e.g. "level-1", "level-2") to a summary of nodes
    at that level.
    """

    tags: dict[str, dict[str, IsisNodeLevelSummary]]


# Tag line: "Tag nSVL-1:" or "Tag 64512:"
_TAG_PATTERN = re.compile(r"^Tag\s+(?P<tag>\S+):\s*$")

# Node info line: "ISIS level-1 node information for sw.F87A4137BE0.00"
_NODE_PATTERN = re.compile(
    r"^ISIS\s+level-(?P<level>\d+)\s+node\s+information\s+for\s+"
    r"(?P<system_id>\S+)\s*$"
)


@register(OS.CISCO_IOSXE, "show isis node summary")
class ShowIsisNodeSummaryParser(BaseParser["ShowIsisNodeSummaryResult"]):
    """Parser for 'show isis node summary' command on IOS-XE.

    Parses IS-IS node summary output showing the list of nodes
    known at each IS-IS level, grouped by IS-IS instance tag.

    Example output::

        Tag nSVL-1:
        ISIS level-1 node information for sw.F87A4137BE0.00
        ISIS level-1 node information for sw.F87A4137BE0.01
        ISIS level-1 node information for sw.40B5C1FFEE0.00

        Tag nSVL-1:
        ISIS level-2 node information for sw.F87A4137BE0.00
        ISIS level-2 node information for sw.F87A4137BE0.01
        ISIS level-2 node information for sw.40B5C1FFEE0.00
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ISIS,
            ParserTag.ROUTING,
        }
    )

    @classmethod
    def parse(cls, output: str) -> "ShowIsisNodeSummaryResult":
        """Parse 'show isis node summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed node summary data grouped by IS-IS tag and level.

        Raises:
            ValueError: If no IS-IS node information found in output.
        """
        all_tags: dict[str, dict[str, list[str]]] = {}
        current_tag: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped:
                continue

            tag_match = _TAG_PATTERN.match(stripped)
            if tag_match:
                current_tag = tag_match.group("tag")
                all_tags.setdefault(current_tag, {})
                continue

            node_match = _NODE_PATTERN.match(stripped)
            if node_match and current_tag is not None:
                level_key = f"level-{node_match.group('level')}"
                system_id = node_match.group("system_id")
                all_tags[current_tag].setdefault(level_key, [])
                all_tags[current_tag][level_key].append(system_id)

        if not all_tags or not any(
            nodes for levels in all_tags.values() for nodes in levels.values()
        ):
            msg = "No IS-IS node information found in output"
            raise ValueError(msg)

        result_tags: dict[str, dict[str, IsisNodeLevelSummary]] = {}
        for tag, levels in all_tags.items():
            result_tags[tag] = {}
            for level_key, nodes in levels.items():
                result_tags[tag][level_key] = {
                    "nodes": nodes,
                    "node_count": len(nodes),
                }

        return cast(ShowIsisNodeSummaryResult, {"tags": result_tags})
