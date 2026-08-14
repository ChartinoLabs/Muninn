"""Parser for 'show cpu core' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class CoreEntry(TypedDict):
    """Schema for a single CPU core utilization entry."""

    five_seconds_pct: float
    one_minute_pct: float
    five_minutes_pct: float


ShowCpuCoreResult = dict[str, CoreEntry]


@register(OS.CISCO_FTD, "show cpu core")
class ShowCpuCoreParser(BaseParser[ShowCpuCoreResult]):
    """Parser for 'show cpu core' command on Cisco FTD.

    Parses per-core CPU utilization table showing 5-second,
    1-minute, and 5-minute utilization percentages for each core.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Matches lines like: "Core 0             0.2%   0.1%   0.0%"
    _CORE_ENTRY = re.compile(
        r"^\s*Core\s+(?P<core>\d+)\s+"
        r"(?P<five_sec>[\d.]+)%\s+"
        r"(?P<one_min>[\d.]+)%\s+"
        r"(?P<five_min>[\d.]+)%\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowCpuCoreResult:
        """Parse 'show cpu core' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dictionary of core entries keyed by core number string.

        Raises:
            ValueError: If no CPU core entries found in output.
        """
        result: ShowCpuCoreResult = {}

        for line in output.splitlines():
            match = cls._CORE_ENTRY.match(line)
            if match:
                core_id = match.group("core")
                result[core_id] = CoreEntry(
                    five_seconds_pct=float(match.group("five_sec")),
                    one_minute_pct=float(match.group("one_min")),
                    five_minutes_pct=float(match.group("five_min")),
                )

        if not result:
            msg = "No CPU core entries found in output"
            raise ValueError(msg)

        return result
