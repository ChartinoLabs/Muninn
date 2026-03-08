"""Parser for 'show clock' command on IOS-XE and IOS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowClockResult(TypedDict):
    """Schema for 'show clock' parsed output."""

    time: str
    timezone: str
    day_of_week: str
    month: str
    day: str
    year: str


@register(OS.CISCO_IOS, "show clock")
@register(OS.CISCO_IOSXE, "show clock")
class ShowClockParser(BaseParser[ShowClockResult]):
    """Parser for 'show clock' command.

    Parses the system clock output into structured components.

    Example output formats:
        *04:45:00.857 UTC Thu Aug 7 2025
        .04:37:54.849 UTC Thu Aug 7 2025
        18:56:04.554 EST Mon Oct 17 2016
    """

    # Pattern matches: [*|.]HH:MM:SS.mmm TZ Day Mon DD YYYY
    _CLOCK_PATTERN = re.compile(
        r"^[*.]?"  # Optional * or . prefix (clock sync status)
        r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"  # Time with milliseconds
        r"(?P<timezone>\S+)\s+"  # Timezone
        r"(?P<day_of_week>\w+)\s+"  # Day of week
        r"(?P<month>\w+)\s+"  # Month
        r"(?P<day>\d+)\s+"  # Day of month
        r"(?P<year>\d{4})"  # Year
    )

    @classmethod
    def parse(cls, output: str) -> ShowClockResult:
        """Parse 'show clock' output.

        Args:
            output: Raw CLI output from 'show clock' command.

        Returns:
            Parsed clock data with time components.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._CLOCK_PATTERN.match(line)
            if match:
                return ShowClockResult(
                    time=match.group("time"),
                    timezone=match.group("timezone"),
                    day_of_week=match.group("day_of_week"),
                    month=match.group("month"),
                    day=match.group("day"),
                    year=match.group("year"),
                )

        msg = "No matching clock line found"
        raise ValueError(msg)
