"""Parser for 'show platform hardware throughput level' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowPlatformHardwareThroughputLevelResult(TypedDict):
    """Schema for 'show platform hardware throughput level' parsed output."""

    throughput_level: str
    throughput_kbps: NotRequired[int]


_THROUGHPUT_PATTERN = re.compile(
    r"^The\s+current\s+throughput\s+level\s+is\s+"
    r"(?P<level>(?P<kbps>\d+)\s*kb/s|unthrottled)$",
    re.IGNORECASE,
)


@register(OS.CISCO_IOSXE, "show platform hardware throughput level")
class ShowPlatformHardwareThroughputLevelParser(
    BaseParser[ShowPlatformHardwareThroughputLevelResult],
):
    """Parser for 'show platform hardware throughput level' command.

    Example output::

        The current throughput level is 250000 kb/s

    Or when boost performance license is active::

        The current throughput level is unthrottled
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformHardwareThroughputLevelResult:
        """Parse 'show platform hardware throughput level' output.

        Args:
            output: Raw CLI output from 'show platform hardware throughput level'.

        Returns:
            Parsed throughput level data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = _THROUGHPUT_PATTERN.match(line)
            if match:
                kbps_value = match.group("kbps")
                if kbps_value is not None:
                    return ShowPlatformHardwareThroughputLevelResult(
                        throughput_level=f"{kbps_value} kb/s",
                        throughput_kbps=int(kbps_value),
                    )
                return ShowPlatformHardwareThroughputLevelResult(
                    throughput_level="unthrottled",
                )

        msg = "No throughput level data found in output"
        raise ValueError(msg)
