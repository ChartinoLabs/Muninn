"""Parser for 'show boot mode' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowBootModeResult(TypedDict):
    """Schema for 'show boot mode' parsed output."""

    bootmode: str


@register(OS.CISCO_NXOS, "show boot mode")
class ShowBootModeParser(BaseParser[ShowBootModeResult]):
    """Parser for 'show boot mode' command.

    Example output:
        Current mode is native
    """

    _PATTERN = re.compile(r"^Current\s+mode\s+is\s+(?P<mode>\w+)$", re.IGNORECASE)

    @classmethod
    def parse(cls, output: str) -> ShowBootModeResult:
        """Parse 'show boot mode' output.

        Args:
            output: Raw CLI output from 'show boot mode' command.

        Returns:
            Parsed boot mode data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._PATTERN.match(line)
            if match:
                return ShowBootModeResult(bootmode=match.group("mode"))

        msg = "No matching boot mode line found"
        raise ValueError(msg)
