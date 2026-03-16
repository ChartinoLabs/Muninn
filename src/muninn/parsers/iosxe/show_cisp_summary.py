"""Parser for 'show cisp summary' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class CispStatus(TypedDict):
    """Schema for CISP status."""

    enabled: bool
    running: bool


class ShowCispSummaryResult(TypedDict):
    """Schema for 'show cisp summary' parsed output."""

    cisp: CispStatus


@register(OS.CISCO_IOSXE, "show cisp summary")
class ShowCispSummaryParser(BaseParser[ShowCispSummaryResult]):
    """Parser for 'show cisp summary' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"security"})

    _NOT_ENABLED_PATTERN = re.compile(r"^CISP\s+not\s+enabled$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowCispSummaryResult:
        """Parse 'show cisp summary' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CISP summary.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if cls._NOT_ENABLED_PATTERN.match(line):
                return ShowCispSummaryResult(cisp={"enabled": False, "running": False})

        msg = "No CISP summary line found"
        raise ValueError(msg)
