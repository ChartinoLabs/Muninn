"""Parser for 'show ip arp summary' command on NX-OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ShowIpArpSummaryResult(TypedDict):
    """Schema for 'show ip arp summary' parsed output."""

    resolved: int
    incomplete: int
    throttled: int
    unknown: int
    total: int


_RESOLVED_PATTERN = re.compile(r"^Resolved\s*:\s*(?P<value>\d+)$", re.I)
_INCOMPLETE_PATTERN = re.compile(
    r"^Incomplete\s*:\s*(?P<value>\d+)\s*\(Throttled\s*:\s*(?P<throttled>\d+)\)$",
    re.I,
)
_UNKNOWN_PATTERN = re.compile(r"^Unknown\s*:\s*(?P<value>\d+)$", re.I)
_TOTAL_PATTERN = re.compile(r"^Total\s*:\s*(?P<value>\d+)$", re.I)

# Maps each pattern to a list of (group_name, result_key) pairs to extract
_FIELD_PATTERNS: list[tuple[re.Pattern[str], list[tuple[str, str]]]] = [
    (_RESOLVED_PATTERN, [("value", "resolved")]),
    (_INCOMPLETE_PATTERN, [("value", "incomplete"), ("throttled", "throttled")]),
    (_UNKNOWN_PATTERN, [("value", "unknown")]),
    (_TOTAL_PATTERN, [("value", "total")]),
]


def _match_arp_line(line: str, result: dict[str, int]) -> None:
    """Try matching a line against all ARP summary patterns."""
    for pattern, fields in _FIELD_PATTERNS:
        m = pattern.match(line)
        if m:
            for group_name, key in fields:
                result[key] = int(m.group(group_name))
            return


@register(OS.CISCO_NXOS, "show ip arp summary")
class ShowIpArpSummaryParser(BaseParser[ShowIpArpSummaryResult]):
    """Parser for 'show ip arp summary' command."""

    tags: ClassVar[frozenset[str]] = frozenset({"arp"})

    @classmethod
    def parse(cls, output: str) -> ShowIpArpSummaryResult:
        """Parse 'show ip arp summary' output.

        Args:
            output: Raw CLI output from 'show ip arp summary' command.

        Returns:
            Parsed ARP summary data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            _match_arp_line(line, result)

        required = ("resolved", "incomplete", "throttled", "unknown", "total")
        missing = [key for key in required if key not in result]
        if missing:
            msg = f"Missing ARP summary fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowIpArpSummaryResult, result)
