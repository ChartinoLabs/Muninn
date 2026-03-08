"""Parser for 'show sdwan bfd summary' command on IOS-XE."""

import re
from typing import TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowSdwanBfdSummaryResult(TypedDict):
    """Schema for 'show sdwan bfd summary' parsed output."""

    sessions_total: int
    sessions_up: int
    sessions_max: int
    sessions_flap: int
    poll_interval: int


_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^sessions-total\s+(?P<value>\d+)$"), "sessions_total"),
    (re.compile(r"^sessions-up\s+(?P<value>\d+)$"), "sessions_up"),
    (re.compile(r"^sessions-max\s+(?P<value>\d+)$"), "sessions_max"),
    (re.compile(r"^sessions-flap\s+(?P<value>\d+)$"), "sessions_flap"),
    (re.compile(r"^poll-interval\s+(?P<value>\d+)$"), "poll_interval"),
)

_REQUIRED_FIELDS = (
    "sessions_total",
    "sessions_up",
    "sessions_max",
    "sessions_flap",
    "poll_interval",
)


def _match_bfd_line(line: str, result: dict[str, int]) -> None:
    """Try matching a line against all BFD summary field patterns."""
    for pattern, field in _FIELD_PATTERNS:
        match = pattern.match(line)
        if match:
            result[field] = int(match.group("value"))
            return


@register(OS.CISCO_IOSXE, "show sdwan bfd summary")
class ShowSdwanBfdSummaryParser(BaseParser[ShowSdwanBfdSummaryResult]):
    """Parser for 'show sdwan bfd summary' command.

    Example output:
        sessions-total         4
        sessions-up            4
        sessions-max           4
        sessions-flap          4
        poll-interval          600000
    """

    @classmethod
    def parse(cls, output: str) -> ShowSdwanBfdSummaryResult:
        """Parse 'show sdwan bfd summary' output.

        Args:
            output: Raw CLI output from 'show sdwan bfd summary' command.

        Returns:
            Parsed BFD summary data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            _match_bfd_line(line, result)

        missing = [f for f in _REQUIRED_FIELDS if f not in result]
        if missing:
            msg = f"Missing BFD summary fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowSdwanBfdSummaryResult, result)
