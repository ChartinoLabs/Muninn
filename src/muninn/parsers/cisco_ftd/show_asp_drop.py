"""Parser for 'show asp drop' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DropEntry(TypedDict):
    """Schema for a single ASP drop counter entry."""

    description: str
    count: int


class DropSection(TypedDict):
    """Schema for a drop section (frame or flow)."""

    drops: dict[str, DropEntry]
    last_clearing: str


class ShowAspDropResult(TypedDict):
    """Schema for 'show asp drop' parsed output."""

    frame_drops: DropSection
    flow_drops: DropSection


# Pattern matches lines like:
#   No valid adjacency (no-adjacency)                                       797415
#   Flow is denied by configured rule (acl-drop)                             31803
_DROP_ENTRY_PATTERN = re.compile(
    r"^\s+"
    r"(?P<description>.+?)\s+"
    r"\((?P<reason>[^)]+)\)\s+"
    r"(?P<count>\d+)\s*$"
)

_LAST_CLEARING_PATTERN = re.compile(r"^Last clearing:\s+(.+)$")

_SECTION_HEADERS = {"Frame drop:": "frame", "Flow drop:": "flow"}


@register(OS.CISCO_FTD, "show asp drop")
class ShowAspDropParser(BaseParser[ShowAspDropResult]):
    """Parser for 'show asp drop' command on Cisco FTD.

    Parses ASP (Accelerated Security Path) drop counters showing
    frame-level and flow-level packet drops with reasons and counts.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SECURITY})

    @classmethod
    def _parse_lines(
        cls, output: str
    ) -> tuple[dict[str, DropEntry], str, dict[str, DropEntry], str]:
        """Extract drop entries and last-clearing timestamps from raw output.

        Returns:
            Tuple of (frame_drops, frame_last_clearing, flow_drops, flow_last_clearing).
        """
        sections: dict[str, dict[str, DropEntry]] = {"frame": {}, "flow": {}}
        last_clearings: dict[str, str] = {"frame": "", "flow": ""}
        current_section: str | None = None

        for line in output.splitlines():
            stripped = line.strip()

            # Detect section headers
            if stripped in _SECTION_HEADERS:
                current_section = _SECTION_HEADERS[stripped]
                continue

            # Match last clearing line
            clearing_match = _LAST_CLEARING_PATTERN.match(stripped)
            if clearing_match and current_section:
                last_clearings[current_section] = clearing_match.group(1)
                continue

            # Match drop entry lines
            entry_match = _DROP_ENTRY_PATTERN.match(line)
            if entry_match and current_section:
                reason = entry_match.group("reason")
                sections[current_section][reason] = DropEntry(
                    description=entry_match.group("description"),
                    count=int(entry_match.group("count")),
                )

        return (
            sections["frame"],
            last_clearings["frame"],
            sections["flow"],
            last_clearings["flow"],
        )

    @classmethod
    def parse(cls, output: str) -> ShowAspDropResult:
        """Parse 'show asp drop' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed drop counters organized by frame drops and flow drops.

        Raises:
            ValueError: If no drop sections found in output.
        """
        frame_drops, frame_clearing, flow_drops, flow_clearing = cls._parse_lines(
            output
        )

        if not frame_drops and not flow_drops:
            msg = "No ASP drop entries found in output"
            raise ValueError(msg)

        return ShowAspDropResult(
            frame_drops=DropSection(
                drops=frame_drops,
                last_clearing=frame_clearing,
            ),
            flow_drops=DropSection(
                drops=flow_drops,
                last_clearing=flow_clearing,
            ),
        )
