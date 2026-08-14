"""Parser for 'show xlate count' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowXlateCountResult(TypedDict):
    """Schema for 'show xlate count' parsed output on Cisco FTD."""

    in_use: int
    most_used: int


@register(OS.CISCO_FTD, "show xlate count")
class ShowXlateCountParser(BaseParser[ShowXlateCountResult]):
    """Parser for 'show xlate count' command on Cisco FTD.

    Parses NAT translation count showing current active translations
    and the historical peak usage.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.NAT})

    _XLATE_COUNT_PATTERN = re.compile(
        r"^(?P<in_use>\d+)\s+in\s+use,\s+(?P<most_used>\d+)\s+most\s+used$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowXlateCountResult:
        """Parse 'show xlate count' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed translation count with current and peak usage.

        Raises:
            ValueError: If output cannot be parsed.
        """
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._XLATE_COUNT_PATTERN.match(line)
            if match:
                return ShowXlateCountResult(
                    in_use=int(match.group("in_use")),
                    most_used=int(match.group("most_used")),
                )

        msg = "Could not parse xlate count from output"
        raise ValueError(msg)
