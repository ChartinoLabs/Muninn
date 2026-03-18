"""Parser for 'show ip igmp snooping groups count' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class IgmpGroupsCount(TypedDict):
    """Schema for IGMP groups count."""

    igmp_groups_count: int


class ShowIpIgmpSnoopingGroupsCountResult(TypedDict):
    """Schema for 'show ip igmp snooping groups count' parsed output."""

    total_number_of_groups: IgmpGroupsCount


@register(OS.CISCO_IOSXE, "show ip igmp snooping groups count")
class ShowIpIgmpSnoopingGroupsCountParser(
    BaseParser[ShowIpIgmpSnoopingGroupsCountResult]
):
    """Parser for 'show ip igmp snooping groups count' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.MULTICAST})

    _COUNT_PATTERN = re.compile(
        r"^Total\s+number\s+of\s+groups:\s*(?P<count>\d+)$", re.I
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpIgmpSnoopingGroupsCountResult:
        """Parse output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed group count.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._COUNT_PATTERN.match(line)
            if match:
                return ShowIpIgmpSnoopingGroupsCountResult(
                    total_number_of_groups={
                        "igmp_groups_count": int(match.group("count"))
                    }
                )

        msg = "No IGMP snooping groups count found"
        raise ValueError(msg)
