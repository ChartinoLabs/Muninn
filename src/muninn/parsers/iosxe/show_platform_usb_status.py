"""Parser for 'show platform usb status' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowPlatformUsbStatusResult(TypedDict):
    """Schema for 'show platform usb status' parsed output."""

    status: str


@register(OS.CISCO_IOSXE, "show platform usb status")
class ShowPlatformUsbStatusParser(BaseParser[ShowPlatformUsbStatusResult]):
    """Parser for 'show platform usb status' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"platform", "system"})

    _STATUS_PATTERN = re.compile(r"^USB\s+(?P<status>\S+)$", re.I)

    @classmethod
    def parse(cls, output: str) -> ShowPlatformUsbStatusResult:
        """Parse 'show platform usb status' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed USB status.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._STATUS_PATTERN.match(line)
            if match:
                return ShowPlatformUsbStatusResult(status=match.group("status").lower())

        msg = "No USB status line found"
        raise ValueError(msg)
