"""Parser for 'show ip arp summary' command on NX-OS."""

import re
from typing import TypedDict, cast

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


@register(OS.CISCO_NXOS, "show ip arp summary")
class ShowIpArpSummaryParser(BaseParser[ShowIpArpSummaryResult]):
    """Parser for 'show ip arp summary' command."""

    _RESOLVED_PATTERN = re.compile(r"^Resolved\s*:\s*(?P<value>\d+)$", re.I)
    _INCOMPLETE_PATTERN = re.compile(
        r"^Incomplete\s*:\s*(?P<value>\d+)\s*\(Throttled\s*:\s*(?P<throttled>\d+)\)$",
        re.I,
    )
    _UNKNOWN_PATTERN = re.compile(r"^Unknown\s*:\s*(?P<value>\d+)$", re.I)
    _TOTAL_PATTERN = re.compile(r"^Total\s*:\s*(?P<value>\d+)$", re.I)

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

            match = cls._RESOLVED_PATTERN.match(line)
            if match:
                result["resolved"] = int(match.group("value"))
                continue

            match = cls._INCOMPLETE_PATTERN.match(line)
            if match:
                result["incomplete"] = int(match.group("value"))
                result["throttled"] = int(match.group("throttled"))
                continue

            match = cls._UNKNOWN_PATTERN.match(line)
            if match:
                result["unknown"] = int(match.group("value"))
                continue

            match = cls._TOTAL_PATTERN.match(line)
            if match:
                result["total"] = int(match.group("value"))
                continue

        required = ("resolved", "incomplete", "throttled", "unknown", "total")
        missing = [key for key in required if key not in result]
        if missing:
            msg = f"Missing ARP summary fields: {', '.join(missing)}"
            raise ValueError(msg)

        return cast(ShowIpArpSummaryResult, result)
