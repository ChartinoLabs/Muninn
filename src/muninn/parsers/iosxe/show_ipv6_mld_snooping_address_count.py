"""Parser for 'show ipv6 mld snooping address count' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class MldGroupsCount(TypedDict):
    """Schema for MLD groups count."""

    mld_groups_count: int


class ShowIpv6MldSnoopingAddressCountResult(TypedDict):
    """Schema for 'show ipv6 mld snooping address count' parsed output."""

    total_number_of_groups: MldGroupsCount


@register(OS.CISCO_IOSXE, "show ipv6 mld snooping address count")
class ShowIpv6MldSnoopingAddressCountParser(
    BaseParser[ShowIpv6MldSnoopingAddressCountResult]
):
    """Parser for 'show ipv6 mld snooping address count' command."""

    _COUNT_PATTERN = re.compile(
        r"^Total\s+number\s+of\s+groups:\s*(?P<count>\d+)$", re.I
    )

    @classmethod
    def parse(cls, output: str) -> ShowIpv6MldSnoopingAddressCountResult:
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
                return ShowIpv6MldSnoopingAddressCountResult(
                    total_number_of_groups={
                        "mld_groups_count": int(match.group("count"))
                    }
                )

        msg = "No MLD snooping address count found"
        raise ValueError(msg)
