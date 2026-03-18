"""Parser for 'show power supplies' command on IOS."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowPowerSuppliesResult(TypedDict):
    """Schema for 'show power supplies' parsed output."""

    needed: int
    available: int


_NEEDED_RE = re.compile(
    r"^Power\s+supplies\s+needed\s+by\s+system\s*:\s*(?P<value>\d+)$"
)
_AVAILABLE_RE = re.compile(
    r"^Power\s+supplies\s+currently\s+available\s*:\s*(?P<value>\d+)$"
)

_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (_NEEDED_RE, "needed"),
    (_AVAILABLE_RE, "available"),
)


def _match_field(line: str, result: dict[str, int]) -> None:
    """Try to match a line against known field patterns and update result."""
    for pattern, field in _FIELD_PATTERNS:
        match = pattern.match(line)
        if match:
            result[field] = int(match.group("value"))
            return


@register(OS.CISCO_IOS, "show power supplies")
class ShowPowerSuppliesParser(BaseParser[ShowPowerSuppliesResult]):
    """Parser for 'show power supplies' command.

    Example output:
        Power supplies needed by system    : 1
        Power supplies currently available : 2
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPowerSuppliesResult:
        """Parse 'show power supplies' output.

        Args:
            output: Raw CLI output from 'show power supplies' command.

        Returns:
            Parsed data with needed and available power supply counts.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            _match_field(line, result)

        missing = [f for f in ("needed", "available") if f not in result]
        if missing:
            msg = f"Missing required fields: {', '.join(missing)}"
            raise ValueError(msg)

        return ShowPowerSuppliesResult(
            needed=result["needed"],
            available=result["available"],
        )
