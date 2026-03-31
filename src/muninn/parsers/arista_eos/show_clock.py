"""Parser for 'show clock' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowClockResult(TypedDict):
    """Schema for 'show clock' parsed output on Arista EOS."""

    time: str
    timezone: str
    day_of_week: str
    month: str
    day: str
    year: str


@register(OS.ARISTA_EOS, "show clock")
class ShowClockParser(BaseParser[ShowClockResult]):
    """Parser for 'show clock' command on Arista EOS.

    Parses the current device time, date components, and timezone.

    Expected CLI output format::

        Mon Jan 14 18:42:49 2013
        timezone is US/Central
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    # Line 1: day_of_week month day HH:MM:SS year
    _DATETIME_PATTERN = re.compile(
        r"^(?P<day_of_week>\w+)\s+"
        r"(?P<month>\w+)\s+"
        r"(?P<day>\d+)\s+"
        r"(?P<time>\d+:\d+:\d+)\s+"
        r"(?P<year>\d{4})$"
    )

    # Line 2: timezone is <tz>
    _TIMEZONE_PATTERN = re.compile(r"^timezone is\s+(?P<timezone>\S+)")

    @classmethod
    def parse(cls, output: str) -> ShowClockResult:
        """Parse 'show clock' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed clock information with time, timezone, and date fields.

        Raises:
            ValueError: If required fields cannot be parsed from the output.
        """
        datetime_match = None
        timezone_value = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if match := cls._DATETIME_PATTERN.match(stripped):
                datetime_match = match

            if match := cls._TIMEZONE_PATTERN.match(stripped):
                timezone_value = match.group("timezone")

        if datetime_match is None:
            msg = "No date/time line found in output"
            raise ValueError(msg)

        if timezone_value is None:
            msg = "No timezone line found in output"
            raise ValueError(msg)

        return ShowClockResult(
            time=datetime_match.group("time"),
            timezone=timezone_value,
            day_of_week=datetime_match.group("day_of_week"),
            month=datetime_match.group("month"),
            day=datetime_match.group("day"),
            year=datetime_match.group("year"),
        )
