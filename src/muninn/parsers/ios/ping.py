"""Parser for 'ping' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PingPacketData(TypedDict):
    """Per-packet ping result."""

    result: str


class PingResult(TypedDict):
    """Schema for 'ping' parsed output.

    RTT fields are only present when at least one reply was received.
    """

    packets_sent: int
    packets_received: int
    success_rate_percent: int
    packet_data: dict[str, PingPacketData]
    rtt_min_ms: NotRequired[int]
    rtt_avg_ms: NotRequired[int]
    rtt_max_ms: NotRequired[int]


# --- Regex patterns ---

# Success rate line:
#   Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/10 ms
#   Success rate is 0 percent (0/5)
_SUCCESS_RATE_RE = re.compile(
    r"Success rate is (?P<success_rate>\d+) percent"
    r" \((?P<received>\d+)/(?P<sent>\d+)\)"
    r"(?:,\s*round-trip min/avg/max\s*=\s*"
    r"(?P<rtt_min>\d+)/(?P<rtt_avg>\d+)/(?P<rtt_max>\d+)\s*ms)?"
)

_PACKET_LINE_RE = re.compile(r"^[!.UQM&?]+$")


_PACKET_RESULT_MAP = {
    "!": "successful",
    ".": "failed",
    "U": "unreachable",
    "Q": "source_quench",
    "M": "cannot_fragment",
    "&": "time_exceeded",
    "?": "unknown",
}


@register(OS.CISCO_IOS, "ping")
class PingParser(BaseParser["PingResult"]):
    """Parser for 'ping' command.

    Example output:
        Type escape sequence to abort.
        Sending 5, 100-byte ICMP Echos to 192.168.0.1, timeout is 2 seconds:
        !!!!!
        Success rate is 100 percent (5/5), round-trip min/avg/max = 1/2/10 ms
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CONNECTIVITY})

    @classmethod
    def parse(cls, output: str) -> PingResult:
        """Parse 'ping' output into structured data.

        Args:
            output: Raw CLI output from 'ping' command.

        Returns:
            Parsed ping result with success rate, packet counts,
            and optional RTT statistics.

        Raises:
            ValueError: If no success rate line is found in the output.
        """
        packet_symbols: list[str] = []

        for line in output.splitlines():
            match = _SUCCESS_RATE_RE.search(line)
            if match:
                result: PingResult = {
                    "success_rate_percent": int(match.group("success_rate")),
                    "packets_received": int(match.group("received")),
                    "packets_sent": int(match.group("sent")),
                    "packet_data": {
                        str(index): {
                            "result": _PACKET_RESULT_MAP.get(symbol, "unknown")
                        }
                        for index, symbol in enumerate(packet_symbols, start=1)
                    },
                }

                if match.group("rtt_min") is not None:
                    result["rtt_min_ms"] = int(match.group("rtt_min"))
                    result["rtt_avg_ms"] = int(match.group("rtt_avg"))
                    result["rtt_max_ms"] = int(match.group("rtt_max"))

                return result

            stripped = line.strip()
            if _PACKET_LINE_RE.fullmatch(stripped):
                packet_symbols.extend(stripped)

        msg = "No success rate line found in ping output"
        raise ValueError(msg)
