"""Parser for 'show platform software fed ip mfib vrf count' command on IOS-XE."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class MfibVrfCount(TypedDict):
    """Schema for MFIB VRF entry count."""

    number_of_entries: int


class ShowPlatformSoftwareFedIpMfibVrfCountResult(TypedDict):
    """Schema for 'show platform software fed ip mfib vrf count' parsed output."""

    mfib_count: MfibVrfCount


@register(OS.CISCO_IOSXE, "show platform software fed ip mfib vrf count")
class ShowPlatformSoftwareFedIpMfibVrfCountParser(
    BaseParser[ShowPlatformSoftwareFedIpMfibVrfCountResult]
):
    """Parser for 'show platform software fed ip mfib vrf count' command."""

    _COUNT_PATTERN = re.compile(r"^Number\s+of\s+entries\s*=\s*(?P<count>\d+)$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareFedIpMfibVrfCountResult:
        """Parse output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed MFIB VRF count.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._COUNT_PATTERN.match(line)
            if match:
                return ShowPlatformSoftwareFedIpMfibVrfCountResult(
                    mfib_count={"number_of_entries": int(match.group("count"))}
                )

        msg = "No MFIB VRF count found"
        raise ValueError(msg)
