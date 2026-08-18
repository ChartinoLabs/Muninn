"""Parser for 'show conn count' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PreserveConnectionStats(TypedDict):
    """Schema for Snort preserve-connection statistics."""

    enabled: int
    in_effect: int
    most_enabled: int
    most_in_effect: int


class ShowConnCountResult(TypedDict):
    """Schema for 'show conn count' parsed output on Cisco FTD."""

    in_use: int
    most_used: int
    preserve_connection: NotRequired[PreserveConnectionStats]


@register(OS.CISCO_FTD, "show conn count")
class ShowConnCountParser(BaseParser[ShowConnCountResult]):
    """Parser for 'show conn count' command on Cisco FTD.

    Parses connection count summary showing current and peak connection
    usage, along with optional Snort inspect preserve-connection statistics.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CONNECTIVITY})

    _CONN_COUNT_PATTERN = re.compile(
        r"^(?P<in_use>\d+)\s+in use,\s+(?P<most_used>\d+)\s+most used$"
    )

    _PRESERVE_CONN_PATTERN = re.compile(
        r"preserve-connection:\s+"
        r"(?P<enabled>\d+)\s+enabled,\s+"
        r"(?P<in_effect>\d+)\s+in effect,\s+"
        r"(?P<most_enabled>\d+)\s+most enabled,\s+"
        r"(?P<most_in_effect>\d+)\s+most in effect"
    )

    @classmethod
    def parse(cls, output: str) -> ShowConnCountResult:
        """Parse 'show conn count' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed connection count with optional preserve-connection stats.

        Raises:
            ValueError: If connection count line is not found.
        """
        result: ShowConnCountResult | None = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            conn_match = cls._CONN_COUNT_PATTERN.match(line)
            if conn_match:
                result = ShowConnCountResult(
                    in_use=int(conn_match.group("in_use")),
                    most_used=int(conn_match.group("most_used")),
                )
                continue

            preserve_match = cls._PRESERVE_CONN_PATTERN.search(line)
            if preserve_match and result is not None:
                result["preserve_connection"] = PreserveConnectionStats(
                    enabled=int(preserve_match.group("enabled")),
                    in_effect=int(preserve_match.group("in_effect")),
                    most_enabled=int(preserve_match.group("most_enabled")),
                    most_in_effect=int(preserve_match.group("most_in_effect")),
                )

        if result is None:
            msg = "No connection count found in output"
            raise ValueError(msg)

        return result
