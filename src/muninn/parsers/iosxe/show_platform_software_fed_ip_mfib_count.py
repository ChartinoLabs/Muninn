"""Parser for 'show platform software fed ip mfib count' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class MfibCount(TypedDict):
    """Schema for MFIB entry count."""

    number_of_entries: int


class ShowPlatformSoftwareFedIpMfibCountResult(TypedDict):
    """Schema for 'show platform software fed ip mfib count' parsed output."""

    mfib_count: MfibCount


@register(OS.CISCO_IOSXE, "show platform software fed ip mfib count")
class ShowPlatformSoftwareFedIpMfibCountParser(
    BaseParser[ShowPlatformSoftwareFedIpMfibCountResult]
):
    """Parser for 'show platform software fed ip mfib count' command."""

    _COUNT_PATTERN = re.compile(r"^Number\s+of\s+entries\s*=\s*(?P<count>\d+)$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareFedIpMfibCountResult:
        """Parse output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MFIB count.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._COUNT_PATTERN.match(line)
            if match:
                return ShowPlatformSoftwareFedIpMfibCountResult(
                    mfib_count={"number_of_entries": int(match.group("count"))}
                )

        msg = "No MFIB count found"
        raise ValueError(msg)
