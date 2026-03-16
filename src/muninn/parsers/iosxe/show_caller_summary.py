"""Parser for 'show caller summary' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowCallerSummaryResult(TypedDict):
    """Schema for 'show caller summary' parsed output.

    Each field represents a count of active calls or sessions
    reported by the device.
    """

    analog_calls: int
    vpdn_analog_calls: int
    isdn_calls: int
    vpdn_isdn_calls: int
    vpdn_calls: int
    pppoa_calls: int
    pppoe_calls: int
    total_unique_users_logged_in: int


_ANALOG_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+Analog\s+calls\s+\((?P<vpdn>\d+)\s+VPDN\s+Calls\)",
    re.IGNORECASE,
)
_ISDN_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+ISDN\s+calls\s+\((?P<vpdn>\d+)\s+VPDN\s+Calls\)",
    re.IGNORECASE,
)
_VPDN_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+VPDN\s+calls\s*$",
    re.IGNORECASE,
)
_PPPOA_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+PPPoA\s+calls\s*$",
    re.IGNORECASE,
)
_PPPOE_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+PPPoE\s+calls\s*$",
    re.IGNORECASE,
)
_TOTAL_USERS_PATTERN = re.compile(
    r"^\s*(?P<count>\d+)\s+Total\s+unique\s+users\s+logged\s+in\s*$",
    re.IGNORECASE,
)

# Simple patterns: (regex, result_key) - extract "count" group
_SIMPLE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_VPDN_PATTERN, "vpdn_calls"),
    (_PPPOA_PATTERN, "pppoa_calls"),
    (_PPPOE_PATTERN, "pppoe_calls"),
    (_TOTAL_USERS_PATTERN, "total_unique_users_logged_in"),
)


def _match_line(line: str, result: dict[str, int]) -> None:
    """Try to match a line against known patterns and update result dict."""
    match = _ANALOG_PATTERN.match(line)
    if match:
        result["analog_calls"] = int(match.group("count"))
        result["vpdn_analog_calls"] = int(match.group("vpdn"))
        return

    match = _ISDN_PATTERN.match(line)
    if match:
        result["isdn_calls"] = int(match.group("count"))
        result["vpdn_isdn_calls"] = int(match.group("vpdn"))
        return

    for pattern, key in _SIMPLE_PATTERNS:
        match = pattern.match(line)
        if match:
            result[key] = int(match.group("count"))
            return


@register(OS.CISCO_IOSXE, "show caller summary")
class ShowCallerSummaryParser(BaseParser[ShowCallerSummaryResult]):
    """Parser for 'show caller summary' command.

    Parses call count statistics from the summary output.

    Example output::

        show caller summary

                0   Analog calls (0 VPDN Calls)

                0   ISDN calls (0 VPDN Calls)

                0   VPDN calls

                0   PPPoA calls

                0   PPPoE calls

                0   Total unique users logged in
    """

    tags: ClassVar[frozenset[str]] = frozenset({"system"})

    @classmethod
    def parse(cls, output: str) -> ShowCallerSummaryResult:
        """Parse 'show caller summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed caller summary statistics.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            if not line.strip():
                continue
            _match_line(line, result)

        if not result:
            msg = "No caller summary data found in output"
            raise ValueError(msg)

        return ShowCallerSummaryResult(
            analog_calls=result.get("analog_calls", 0),
            vpdn_analog_calls=result.get("vpdn_analog_calls", 0),
            isdn_calls=result.get("isdn_calls", 0),
            vpdn_isdn_calls=result.get("vpdn_isdn_calls", 0),
            vpdn_calls=result.get("vpdn_calls", 0),
            pppoa_calls=result.get("pppoa_calls", 0),
            pppoe_calls=result.get("pppoe_calls", 0),
            total_unique_users_logged_in=result.get("total_unique_users_logged_in", 0),
        )
