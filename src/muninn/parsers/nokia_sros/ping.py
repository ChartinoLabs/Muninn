"""Parser for 'ping' command on Nokia SR OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PingPacketData(TypedDict):
    """Per-packet ping result.

    For verbose-mode pings the parser captures the full reply line
    (bytes, icmp_seq, ttl, time_ms). For rapid-mode pings only the
    symbolic ``result`` is available, mapped from the ``!``/``.``/
    ``U`` characters streamed by the device.
    """

    result: str
    bytes: NotRequired[int]
    icmp_seq: NotRequired[int]
    ttl: NotRequired[int]
    time_ms: NotRequired[float]


class PingResult(TypedDict):
    """Schema for 'ping' parsed output on Nokia SR OS.

    Common keys (``packets_sent``/``packets_received``/
    ``success_rate_percent``/``packet_data``/``rtt_*``) mirror the
    sibling Cisco parsers' shapes; Nokia-specific keys such as
    ``packets_bounced``, ``duplicate_count``, ``rtt_stddev_ms``,
    ``destination``, and ``packet_size_bytes`` are added as optional.
    """

    packets_sent: int
    packets_received: int
    success_rate_percent: int
    packet_data: dict[str, PingPacketData]
    destination: NotRequired[str]
    packet_size_bytes: NotRequired[int]
    loss_percent: NotRequired[float]
    packets_bounced: NotRequired[int]
    duplicate_count: NotRequired[int]
    rtt_min_ms: NotRequired[float]
    rtt_avg_ms: NotRequired[float]
    rtt_max_ms: NotRequired[float]
    rtt_stddev_ms: NotRequired[float]


# --- Regex patterns ---

# Header line:
#   PING 10.252.117.158 56 data bytes
_PING_HEADER_RE = re.compile(
    r"^PING\s+(?P<destination>\S+)\s+(?P<size>\d+)\s+data\s+bytes\s*$"
)

# Per-packet reply line (verbose ping):
#   64 bytes from 10.252.117.158: icmp_seq=1 ttl=255 time=1.93ms.
_REPLY_RE = re.compile(
    r"^(?P<bytes>\d+)\s+bytes\s+from\s+\S+:\s+"
    r"icmp_seq=(?P<icmp_seq>\d+)\s+"
    r"ttl=(?P<ttl>\d+)\s+"
    r"time=(?P<time>[\d.]+)\s*ms\.?\s*$"
)

# Per-packet failure indicators (verbose ping):
#   Request timed out. icmp_seq=1.
_TIMEOUT_RE = re.compile(
    r"^Request\s+timed\s+out\.\s*(?:icmp_seq=(?P<icmp_seq>\d+)\.?)?\s*$"
)

# Per-packet send-failure indicator (verbose ping):
#   Send failed. Source IP address is not local to the system
_SEND_FAIL_RE = re.compile(r"^Send\s+failed\.")

# Rapid-mode symbolic stream (lone line of ``!``/``.``/``U``/etc.):
_RAPID_STREAM_RE = re.compile(r"^[!.UQM&?]+$")

# Statistics summary:
#   5 packets transmitted, 5 packets received, 0.00% packet loss
#   5 packets transmitted, 5 packets bounced, 0 packets received, 100% packet loss
#   5 packets transmitted, 0 packets received, 3 duplicates
_STATS_RE = re.compile(
    r"^(?P<sent>\d+)\s+packets\s+transmitted,"
    r"(?:\s+(?P<bounced>\d+)\s+packets\s+bounced,)?"
    r"\s+(?P<received>\d+)\s+packets\s+received"
    r"(?:,\s+(?P<loss>[\d.]+)%\s+packet\s+loss)?"
    r"(?:,\s+(?P<duplicates>\d+)\s+duplicates)?"
    r"\s*$"
)

# RTT summary:
#   round-trip min = 1.70ms, avg = 1.83ms, max = 1.93ms, stddev = 0.079ms
_RTT_RE = re.compile(
    r"^round-trip\s+min\s*=\s*(?P<min>[\d.]+)\s*ms,\s*"
    r"avg\s*=\s*(?P<avg>[\d.]+)\s*ms,\s*"
    r"max\s*=\s*(?P<max>[\d.]+)\s*ms"
    r"(?:,\s*stddev\s*=\s*(?P<stddev>[\d.]+)\s*ms)?\s*$"
)


_RAPID_RESULT_MAP: dict[str, str] = {
    "!": "successful",
    ".": "failed",
    "U": "unreachable",
    "Q": "source_quench",
    "M": "cannot_fragment",
    "&": "time_exceeded",
    "?": "unknown",
}


@register(OS.NOKIA_SROS, "ping")
class PingParser(BaseParser[PingResult]):
    """Parser for ``ping`` on Nokia SR OS.

    Handles both verbose pings (one ``64 bytes from ...`` line per
    reply, ``Request timed out.`` / ``Send failed.`` lines per
    failure) and rapid-mode pings (a single ``!!!!!``/``.....``/
    ``...!!.!.`` stream followed by the statistics block).

    Example verbose output::

        PING 10.252.117.158 56 data bytes
        64 bytes from 10.252.117.158: icmp_seq=1 ttl=255 time=1.93ms.
        ...
        ---- 10.252.117.158 PING Statistics ----
        5 packets transmitted, 5 packets received, 0.00% packet loss
        round-trip min = 1.70ms, avg = 1.83ms, max = 1.93ms, stddev = 0.079ms
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.CONNECTIVITY})

    @classmethod
    def parse(cls, output: str) -> PingResult:
        """Parse ``ping`` output into a structured result.

        Args:
            output: Raw CLI output from the ``ping`` command.

        Returns:
            Parsed ping result with packet counts, success rate, per-packet
            data, and optional RTT statistics.

        Raises:
            ValueError: If no statistics summary line is found.
        """
        result: dict = {}
        packet_data: dict[str, PingPacketData] = {}
        rapid_symbols: list[str] = []
        seen_stats = False

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if cls._dispatch_line(stripped, result, packet_data, rapid_symbols):
                seen_stats = seen_stats or "packets_sent" in result

        if not seen_stats:
            msg = "No statistics summary line found in ping output"
            raise ValueError(msg)

        cls._finalize(result, packet_data, rapid_symbols)
        return cast(PingResult, result)

    @classmethod
    def _dispatch_line(
        cls,
        line: str,
        result: dict,
        packet_data: dict[str, PingPacketData],
        rapid_symbols: list[str],
    ) -> bool:
        """Route a single stripped line to its handler. Returns True if handled."""
        if cls._try_header(line, result):
            return True
        if cls._try_verbose_packet(line, packet_data):
            return True
        if not packet_data and _RAPID_STREAM_RE.fullmatch(line):
            rapid_symbols.extend(line)
            return True
        if cls._try_stats(line, result):
            return True
        return cls._try_rtt(line, result)

    @classmethod
    def _try_verbose_packet(
        cls,
        line: str,
        packet_data: dict[str, PingPacketData],
    ) -> bool:
        """Try parsing line as a verbose reply or failure indicator."""
        verbose_index = len(packet_data)
        if cls._try_verbose_reply(line, packet_data, verbose_index):
            return True
        return cls._try_verbose_failure(line, packet_data, verbose_index)

    @staticmethod
    def _finalize(
        result: dict,
        packet_data: dict[str, PingPacketData],
        rapid_symbols: list[str],
    ) -> None:
        """Materialize packet_data and derive success_rate_percent."""
        if not packet_data and rapid_symbols:
            packet_data = {
                str(index): {
                    "result": _RAPID_RESULT_MAP.get(symbol, "unknown"),
                }
                for index, symbol in enumerate(rapid_symbols, start=1)
            }
        sent = cast(int, result["packets_sent"])
        received = cast(int, result["packets_received"])
        result["packet_data"] = packet_data
        result["success_rate_percent"] = (
            int(round(received / sent * 100)) if sent else 0
        )

    @staticmethod
    def _try_header(line: str, result: dict) -> bool:
        match = _PING_HEADER_RE.match(line)
        if not match:
            return False
        result["destination"] = match.group("destination")
        result["packet_size_bytes"] = int(match.group("size"))
        return True

    @staticmethod
    def _try_verbose_reply(
        line: str,
        packet_data: dict[str, PingPacketData],
        verbose_index: int,
    ) -> bool:
        match = _REPLY_RE.match(line)
        if not match:
            return False
        index = verbose_index + 1
        packet_data[str(index)] = {
            "result": "successful",
            "bytes": int(match.group("bytes")),
            "icmp_seq": int(match.group("icmp_seq")),
            "ttl": int(match.group("ttl")),
            "time_ms": float(match.group("time")),
        }
        return True

    @staticmethod
    def _try_verbose_failure(
        line: str,
        packet_data: dict[str, PingPacketData],
        verbose_index: int,
    ) -> bool:
        timeout = _TIMEOUT_RE.match(line)
        if timeout:
            index = verbose_index + 1
            entry: PingPacketData = {"result": "timeout"}
            seq = timeout.group("icmp_seq")
            if seq is not None:
                entry["icmp_seq"] = int(seq)
            packet_data[str(index)] = entry
            return True
        if _SEND_FAIL_RE.match(line):
            index = verbose_index + 1
            packet_data[str(index)] = {"result": "send_failed"}
            return True
        return False

    @staticmethod
    def _try_stats(line: str, result: dict) -> bool:
        match = _STATS_RE.match(line)
        if not match:
            return False
        result["packets_sent"] = int(match.group("sent"))
        result["packets_received"] = int(match.group("received"))
        bounced = match.group("bounced")
        if bounced is not None:
            result["packets_bounced"] = int(bounced)
        loss = match.group("loss")
        if loss is not None:
            result["loss_percent"] = float(loss)
        duplicates = match.group("duplicates")
        if duplicates is not None:
            result["duplicate_count"] = int(duplicates)
        return True

    @staticmethod
    def _try_rtt(line: str, result: dict) -> bool:
        match = _RTT_RE.match(line)
        if not match:
            return False
        result["rtt_min_ms"] = float(match.group("min"))
        result["rtt_avg_ms"] = float(match.group("avg"))
        result["rtt_max_ms"] = float(match.group("max"))
        stddev = match.group("stddev")
        if stddev is not None:
            result["rtt_stddev_ms"] = float(stddev)
        return True
