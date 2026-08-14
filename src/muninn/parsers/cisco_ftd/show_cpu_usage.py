"""Parser for 'show cpu usage' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowCpuUsageResult(TypedDict):
    """Schema for 'show cpu usage' parsed output on Cisco FTD."""

    cpu_5_seconds_pct: int
    cpu_1_minute_pct: int
    cpu_5_minutes_pct: int


@register(OS.CISCO_FTD, "show cpu usage")
class ShowCpuUsageParser(BaseParser[ShowCpuUsageResult]):
    """Parser for 'show cpu usage' command on Cisco FTD.

    Parses CPU utilization percentages for 5-second, 1-minute, and 5-minute
    intervals.

    Expected CLI output format::

        CPU utilization for 5 seconds = 0%; 1 minute: 0%; 5 minutes: 0%
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _CPU_PATTERN = re.compile(
        r"CPU utilization for 5 seconds = (?P<five_sec>\d+)%;\s*"
        r"1 minute:\s*(?P<one_min>\d+)%;\s*"
        r"5 minutes:\s*(?P<five_min>\d+)%"
    )

    @classmethod
    def parse(cls, output: str) -> ShowCpuUsageResult:
        """Parse 'show cpu usage' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CPU utilization percentages for each time interval.

        Raises:
            ValueError: If CPU utilization line cannot be parsed from the output.
        """
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._CPU_PATTERN.search(stripped):
                return ShowCpuUsageResult(
                    cpu_5_seconds_pct=int(match.group("five_sec")),
                    cpu_1_minute_pct=int(match.group("one_min")),
                    cpu_5_minutes_pct=int(match.group("five_min")),
                )

        msg = "No CPU utilization line found in output"
        raise ValueError(msg)
