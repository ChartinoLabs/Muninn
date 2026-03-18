"""Parser for 'show platform software dns-umbrella statistics' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class UmbrellaStatistics(TypedDict):
    """Schema for DNS Umbrella statistics counters."""

    total_packets: int
    dnscrypt_queries: int
    dnscrypt_responses: int
    dns_queries: int
    dns_bypassed_queries_regex: int
    dns_responses_umbrella: int
    dns_responses_other: int
    aged_queries: int
    dropped_packets: int
    dns_bypass_fqdn: NotRequired[int]
    dns_bypass_ip: NotRequired[int]


class ShowPlatformSoftwareDnsUmbrellaStatisticsResult(TypedDict):
    """Schema for 'show platform software dns-umbrella statistics' parsed output."""

    umbrella_statistics: UmbrellaStatistics


# Map display labels to dict keys
_COUNTER_MAP: dict[str, str] = {
    "Total Packets": "total_packets",
    "DNSCrypt queries": "dnscrypt_queries",
    "DNSCrypt responses": "dnscrypt_responses",
    "DNS queries": "dns_queries",
    "DNS bypassed queries(Regex)": "dns_bypassed_queries_regex",
    "DNS responses(Umbrella)": "dns_responses_umbrella",
    "DNS responses(Other)": "dns_responses_other",
    "Aged queries": "aged_queries",
    "Dropped pkts": "dropped_packets",
    "DNS bypass(FQDN)": "dns_bypass_fqdn",
    "DNS bypass(IP)": "dns_bypass_ip",
}

# Pattern: label followed by colon and integer value
_COUNTER_LINE = re.compile(r"^\s*(?P<label>.+?)\s*:\s*(?P<value>\d+)\s*$")


@register(OS.CISCO_IOSXE, "show platform software dns-umbrella statistics")
class ShowPlatformSoftwareDnsUmbrellaStatisticsParser(
    BaseParser[ShowPlatformSoftwareDnsUmbrellaStatisticsResult]
):
    """Parser for 'show platform software dns-umbrella statistics' command.

    Example output::

        ========================================
                  Umbrella Statistics
        ========================================
         Total Packets               : 57057
         DNSCrypt queries            : 0
         DNSCrypt responses          : 0
         DNS queries                 : 32321
         DNS bypassed queries(Regex) : 0
         DNS responses(Umbrella)     : 24693
         DNS responses(Other)        : 37
         Aged queries                : 7628
         Dropped pkts                : 0
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.PLATFORM,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowPlatformSoftwareDnsUmbrellaStatisticsResult:
        """Parse 'show platform software dns-umbrella statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed DNS Umbrella statistics.

        Raises:
            ValueError: If no statistics counters are found in the output.
        """
        stats: dict[str, int] = {}

        for line in output.splitlines():
            match = _COUNTER_LINE.match(line)
            if not match:
                continue

            label = match.group("label")
            key = _COUNTER_MAP.get(label)
            if key is not None:
                stats[key] = int(match.group("value"))

        if not stats:
            msg = "No DNS Umbrella statistics found in output"
            raise ValueError(msg)

        return ShowPlatformSoftwareDnsUmbrellaStatisticsResult(
            umbrella_statistics=UmbrellaStatistics(**stats),  # type: ignore[typeddict-item]
        )
