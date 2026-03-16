"""Parser for 'show mpls forwarding-table summary' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowMplsForwardingTableSummaryResult(TypedDict):
    """Schema for 'show mpls forwarding-table summary' parsed output."""

    total_label: int


@register(OS.CISCO_IOSXE, "show mpls forwarding-table summary")
class ShowMplsForwardingTableSummaryParser(
    BaseParser[ShowMplsForwardingTableSummaryResult]
):
    """Parser for 'show mpls forwarding-table summary' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"mpls"})

    _TOTAL_PATTERN = re.compile(r"^(?P<count>\d+)\s+total\s+labels$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowMplsForwardingTableSummaryResult:
        """Parse 'show mpls forwarding-table summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed summary data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._TOTAL_PATTERN.match(line)
            if match:
                return ShowMplsForwardingTableSummaryResult(
                    total_label=int(match.group("count"))
                )

        msg = "No MPLS forwarding-table summary found"
        raise ValueError(msg)
