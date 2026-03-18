"""Parser for 'show ip dhcp snooping statistics' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ShowIpDhcpSnoopingStatisticsResult(TypedDict):
    """Schema for 'show ip dhcp snooping statistics' parsed output."""

    packets_forwarded: int
    packets_dropped: int
    packets_dropped_from_untrusted_ports: int


@register(OS.CISCO_IOSXE, "show ip dhcp snooping statistics")
class ShowIpDhcpSnoopingStatisticsParser(
    BaseParser[ShowIpDhcpSnoopingStatisticsResult]
):
    """Parser for 'show ip dhcp snooping statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.DHCP,
            ParserTag.SWITCHING,
        }
    )

    _STAT_PATTERN = re.compile(r"^(?P<key>[\w\s]+?)\s*=\s*(?P<value>\d+)$")

    @classmethod
    def parse(cls, output: str) -> ShowIpDhcpSnoopingStatisticsResult:
        """Parse 'show ip dhcp snooping statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed DHCP snooping statistics counters.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        result: dict[str, int] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cls._STAT_PATTERN.match(line)
            if match:
                key = match.group("key").strip().lower().replace(" ", "_")
                result[key] = int(match.group("value"))

        if not result:
            msg = "No DHCP snooping statistics found in output"
            raise ValueError(msg)

        return ShowIpDhcpSnoopingStatisticsResult(
            packets_forwarded=result.get("packets_forwarded", 0),
            packets_dropped=result.get("packets_dropped", 0),
            packets_dropped_from_untrusted_ports=result.get(
                "packets_dropped_from_untrusted_ports", 0
            ),
        )
