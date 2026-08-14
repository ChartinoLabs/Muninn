"""Parser for 'show memory' command on Cisco FTD."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowMemoryResult(TypedDict):
    """Schema for 'show memory' parsed output on Cisco FTD."""

    free_bytes: int
    free_pct: int
    used_bytes: int
    used_pct: int
    total_bytes: int


@register(OS.CISCO_FTD, "show memory")
class ShowMemoryParser(BaseParser[ShowMemoryResult]):
    """Parser for 'show memory' command on Cisco FTD.

    Parses memory utilization output showing free, used, and total
    memory in bytes with percentage utilization.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    _MEMORY_LINE = re.compile(
        r"^(?P<label>Free|Used|Total)\s+memory:\s+"
        r"(?P<bytes>\d+)\s+bytes\s+"
        r"\((?P<pct>\d+)%\)",
        re.MULTILINE,
    )

    @classmethod
    def parse(cls, output: str) -> ShowMemoryResult:
        """Parse 'show memory' output on Cisco FTD.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed memory utilization with free, used, and total bytes
            plus percentages.

        Raises:
            ValueError: If required memory lines are not found.
        """
        parsed: dict[str, int] = {}

        for match in cls._MEMORY_LINE.finditer(output):
            label = match.group("label").lower()
            parsed[f"{label}_bytes"] = int(match.group("bytes"))
            parsed[f"{label}_pct"] = int(match.group("pct"))

        required_keys = {
            "free_bytes",
            "free_pct",
            "used_bytes",
            "used_pct",
            "total_bytes",
        }
        missing = required_keys - parsed.keys()
        if missing:
            msg = f"Missing required memory fields: {sorted(missing)}"
            raise ValueError(msg)

        return ShowMemoryResult(
            free_bytes=parsed["free_bytes"],
            free_pct=parsed["free_pct"],
            used_bytes=parsed["used_bytes"],
            used_pct=parsed["used_pct"],
            total_bytes=parsed["total_bytes"],
        )
