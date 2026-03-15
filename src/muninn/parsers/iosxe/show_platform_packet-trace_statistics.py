"""Parser for 'show platform packet-trace statistics' command on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class ProtocolCounters(TypedDict):
    """Per-protocol directional counters."""

    dropped: int
    consumed: int
    forwarded: int


class DirectionCounters(TypedDict):
    """Counters for a single packet direction (PKT_DIR_IN/PKT_DIR_OUT)."""

    infra: ProtocolCounters
    tcp: ProtocolCounters
    udp: ProtocolCounters
    ip: ProtocolCounters
    ipv6: ProtocolCounters
    arp: ProtocolCounters


class PuntCause(TypedDict):
    """A single punt or drop cause entry."""

    count: int
    code: int
    cause: str


class PacketsSummary(TypedDict):
    """Packets Summary section."""

    matched: NotRequired[int]
    traced: int


class PacketsReceived(TypedDict):
    """Packets Received section."""

    ingress: int
    inject: int


class PacketsProcessed(TypedDict):
    """Packets Processed section."""

    forward: int
    punt: int
    punt_causes: NotRequired[list[PuntCause]]
    drop: int
    drop_causes: NotRequired[list[PuntCause]]
    consume: int


class ShowPlatformPacketTraceStatisticsResult(TypedDict):
    """Schema for 'show platform packet-trace statistics' output."""

    packets_summary: PacketsSummary
    packets_received: PacketsReceived
    packets_processed: PacketsProcessed
    pkt_dir_in: NotRequired[DirectionCounters]
    pkt_dir_out: NotRequired[DirectionCounters]


_ZERO_COUNTERS = ProtocolCounters(dropped=0, consumed=0, forwarded=0)

_PROTOCOL_NAMES = ("infra", "tcp", "udp", "ip", "ipv6", "arp")

# Counter patterns keyed by field name
_COUNTER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("matched", re.compile(r"^\s*Matched\s+(?P<v>\d+)\s*$", re.I)),
    (
        "traced",
        re.compile(r"^\s*(?:Packets\s+)?Traced:?\s+(?P<v>\d+)\s*$", re.I),
    ),
    ("ingress", re.compile(r"^\s*Ingress\s+(?P<v>\d+)\s*$", re.I)),
    ("inject", re.compile(r"^\s*Inject\s+(?P<v>\d+)\s*$", re.I)),
    ("forward", re.compile(r"^\s*Forward\s+(?P<v>\d+)\s*$", re.I)),
    ("punt", re.compile(r"^\s*Punt\s+(?P<v>\d+)\s*$", re.I)),
    ("drop", re.compile(r"^\s*Drop\s+(?P<v>\d+)\s*$", re.I)),
    ("consume", re.compile(r"^\s*Consume\s+(?P<v>\d+)\s*$", re.I)),
]

_CAUSE_RE = re.compile(
    r"^\s*(?P<count>\d+)\s+(?P<code>\d+)\s+(?P<cause>.+?)\s*$",
)

_DIRECTION_RE = re.compile(r"^\s*(?P<direction>PKT_DIR_IN|PKT_DIR_OUT)\s*$", re.I)

_DIRECTION_ROW_RE = re.compile(
    r"^\s*(?P<protocol>INFRA|TCP|UDP|IP|IPV6|ARP)"
    r"\s+(?P<dropped>\d+)"
    r"\s+(?P<consumed>\d+)"
    r"\s+(?P<forwarded>\d+)\s*$",
    re.I,
)

_PACKETS_SUMMARY_RE = re.compile(r"^\s*Packets\s+Summary\s*$", re.I)


def _build_direction_counters(
    counters: dict[str, ProtocolCounters],
) -> DirectionCounters:
    """Build DirectionCounters with defaults for missing protocols."""
    return DirectionCounters(
        infra=counters.get("infra", _ZERO_COUNTERS),
        tcp=counters.get("tcp", _ZERO_COUNTERS),
        udp=counters.get("udp", _ZERO_COUNTERS),
        ip=counters.get("ip", _ZERO_COUNTERS),
        ipv6=counters.get("ipv6", _ZERO_COUNTERS),
        arp=counters.get("arp", _ZERO_COUNTERS),
    )


def _parse_direction_block(
    lines: list[str],
    start: int,
) -> DirectionCounters:
    """Parse a PKT_DIR_IN or PKT_DIR_OUT block."""
    counters: dict[str, ProtocolCounters] = {}
    idx = start
    while idx < len(lines):
        line = lines[idx]
        row_match = _DIRECTION_ROW_RE.match(line)
        if row_match:
            protocol = row_match.group("protocol").lower()
            counters[protocol] = ProtocolCounters(
                dropped=int(row_match.group("dropped")),
                consumed=int(row_match.group("consumed")),
                forwarded=int(row_match.group("forwarded")),
            )
            idx += 1
            continue
        stripped = line.strip()
        if not stripped or "Dropped" in stripped:
            idx += 1
            continue
        break

    return _build_direction_counters(counters)


def _collect_causes(
    lines: list[str],
    start: int,
) -> tuple[list[PuntCause], int]:
    """Collect cause lines starting at the given index.

    Returns:
        Tuple of (causes list, index after last cause line).
    """
    causes: list[PuntCause] = []
    idx = start
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.lower().startswith("count"):
            idx += 1
            continue
        cause_match = _CAUSE_RE.match(lines[idx])
        if cause_match:
            causes.append(
                PuntCause(
                    count=int(cause_match.group("count")),
                    code=int(cause_match.group("code")),
                    cause=cause_match.group("cause"),
                )
            )
            idx += 1
            continue
        break
    return causes, idx


def _match_counter(
    line: str,
) -> tuple[str, int] | None:
    """Try to match a counter line, returning (name, value) or None."""
    for name, pattern in _COUNTER_PATTERNS:
        match = pattern.match(line)
        if match:
            return name, int(match.group("v"))
    return None


def _counter_or_zero(
    counters: dict[str, int | None],
    key: str,
) -> int:
    """Return a counter value, defaulting to 0 if None."""
    value = counters.get(key)
    return value if value is not None else 0


def _build_summary(
    counters: dict[str, int | None],
) -> PacketsSummary:
    """Build the PacketsSummary from parsed counters."""
    if counters["traced"] is None:
        msg = "No 'Traced' counter found in output"
        raise ValueError(msg)

    summary = PacketsSummary(traced=counters["traced"])
    if counters.get("matched") is not None:
        summary["matched"] = counters["matched"]  # type: ignore[assignment]
    return summary


def _build_processed(
    counters: dict[str, int | None],
    punt_causes: list[PuntCause],
    drop_causes: list[PuntCause],
) -> PacketsProcessed:
    """Build the PacketsProcessed from parsed counters and causes."""
    processed = PacketsProcessed(
        forward=_counter_or_zero(counters, "forward"),
        punt=_counter_or_zero(counters, "punt"),
        drop=_counter_or_zero(counters, "drop"),
        consume=_counter_or_zero(counters, "consume"),
    )
    if punt_causes:
        processed["punt_causes"] = punt_causes
    if drop_causes:
        processed["drop_causes"] = drop_causes
    return processed


def _build_result(
    counters: dict[str, int | None],
    punt_causes: list[PuntCause],
    drop_causes: list[PuntCause],
    pkt_dir_in: DirectionCounters | None,
    pkt_dir_out: DirectionCounters | None,
) -> ShowPlatformPacketTraceStatisticsResult:
    """Assemble the final result dict from parsed components."""
    result = ShowPlatformPacketTraceStatisticsResult(
        packets_summary=_build_summary(counters),
        packets_received=PacketsReceived(
            ingress=_counter_or_zero(counters, "ingress"),
            inject=_counter_or_zero(counters, "inject"),
        ),
        packets_processed=_build_processed(
            counters,
            punt_causes,
            drop_causes,
        ),
    )

    if pkt_dir_in is not None:
        result["pkt_dir_in"] = pkt_dir_in
    if pkt_dir_out is not None:
        result["pkt_dir_out"] = pkt_dir_out

    return result


def _skip_direction_rows(lines: list[str], idx: int) -> int:
    """Advance past direction block rows and headers."""
    while idx < len(lines):
        stripped = lines[idx].strip()
        if not stripped or "Dropped" in stripped:
            idx += 1
            continue
        if _DIRECTION_ROW_RE.match(lines[idx]):
            idx += 1
            continue
        break
    return idx


def _handle_counter_line(
    lines: list[str],
    idx: int,
    name: str,
    value: int,
    counters: dict[str, int | None],
    cause_map: dict[str, list[PuntCause]],
) -> int:
    """Store a counter value and collect trailing causes if applicable."""
    counters[name] = value
    idx += 1
    if name in ("punt", "drop"):
        causes, idx = _collect_causes(lines, idx)
        if causes:
            cause_map[name] = causes
    return idx


def _handle_direction_line(
    lines: list[str],
    idx: int,
    direction: str,
    dir_map: dict[str, DirectionCounters],
) -> int:
    """Parse a direction block and advance past it."""
    idx += 1
    dir_map[direction] = _parse_direction_block(lines, idx)
    return _skip_direction_rows(lines, idx)


def _parse_lines(
    lines: list[str],
) -> ShowPlatformPacketTraceStatisticsResult:
    """Parse output lines into structured result."""
    counters: dict[str, int | None] = {name: None for name, _ in _COUNTER_PATTERNS}
    cause_map: dict[str, list[PuntCause]] = {}
    dir_map: dict[str, DirectionCounters] = {}

    idx = 0
    while idx < len(lines):
        line = lines[idx]

        counter_result = _match_counter(line)
        if counter_result is not None:
            name, value = counter_result
            idx = _handle_counter_line(
                lines,
                idx,
                name,
                value,
                counters,
                cause_map,
            )
            continue

        dir_match = _DIRECTION_RE.match(line)
        if dir_match:
            direction = dir_match.group("direction").upper()
            idx = _handle_direction_line(
                lines,
                idx,
                direction,
                dir_map,
            )
            continue

        idx += 1

    return _build_result(
        counters,
        cause_map.get("punt", []),
        cause_map.get("drop", []),
        dir_map.get("PKT_DIR_IN"),
        dir_map.get("PKT_DIR_OUT"),
    )


@register(OS.CISCO_IOSXE, "show platform packet-trace statistics")
class ShowPlatformPacketTraceStatisticsParser(
    BaseParser[ShowPlatformPacketTraceStatisticsResult],
):
    """Parser for 'show platform packet-trace statistics' command.

    Supports both the older (pre-16.12) and newer (16.12+/17) formats.

    Older format example::

        Packets Traced: 5
          Ingress  5
          Inject   0
          Forward  5
          Punt     0
          Drop     0
          Consume  0

    Newer format example::

        Packets Summary
          Matched  3
          Traced   3
        Packets Received
          Ingress  0
          Inject   0
        Packets Processed
          Forward  0
          Punt     3
            Count       Code  Cause
            3           56    RP injected for-us control
          Drop     0
          Consume  0
    """

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowPlatformPacketTraceStatisticsResult:
        """Parse 'show platform packet-trace statistics' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed packet trace statistics.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        return _parse_lines(output.splitlines())
