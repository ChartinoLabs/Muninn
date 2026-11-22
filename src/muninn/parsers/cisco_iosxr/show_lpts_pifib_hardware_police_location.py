"""Parser for 'show lpts pifib hardware police location' on Cisco IOS-XR.

Displays per-flow-type LPTS (Local Packet Transport Services) policer
statistics from the hardware PIFIB (Pre-IFIB) table on a given line card.

Each flow type has a policer with a current rate, default rate, and
accepted/dropped packet counters.  The output also includes summary
statistics for deleted entries.
"""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FlowTypeEntry(TypedDict):
    """Schema for a single LPTS flow type policer entry."""

    policer_type: int
    type: str
    current_rate: int
    default_rate: int
    accepted: int
    dropped: int
    tos_value: str


class StatisticsEntry(TypedDict):
    """Schema for the summary statistics block."""

    packets_accepted_by_deleted_entries: int
    packets_dropped_by_deleted_entries: int
    run_out_of_statistics_counter_errors: int


class ShowLptsPifibHardwarePoliceLocationResult(TypedDict):
    """Schema for 'show lpts pifib hardware police location' parsed output."""

    node: str
    burst_ms: int
    flow_types: dict[str, FlowTypeEntry]
    statistics: NotRequired[StatisticsEntry]


# Header: "Node 0/7/CPU0:"
_NODE_RE = re.compile(r"^\s*Node\s+(?P<node>\S+?):\s*$")

# Burst line: "Burst = 100ms for all flow types"
_BURST_RE = re.compile(r"^\s*Burst\s*=\s*(?P<burst>\d+)ms\b")

# Flow type data line — columns are whitespace-separated:
# FlowType  PolicerNum  PolicerType  CurRate  DefRate  Accepted  Dropped  TOS
_FLOW_RE = re.compile(
    r"^(?P<flow>\S+)"
    r"\s+(?P<policer_type>\d+)"
    r"\s+(?P<type>Static|Dynamic)"
    r"\s+(?P<cur_rate>\d+)"
    r"\s+(?P<def_rate>\d+)"
    r"\s+(?P<accepted>\d+)"
    r"\s+(?P<dropped>\d+)"
    r"\s+(?P<tos>\S+)\s*$",
    re.I,
)

# Statistics lines
_STAT_ACCEPTED_RE = re.compile(r"^Packets accepted by deleted entries:\s*(?P<val>\d+)")
_STAT_DROPPED_RE = re.compile(r"^Packets dropped by deleted entries:\s*(?P<val>\d+)")
_STAT_COUNTER_ERR_RE = re.compile(
    r"^Run out of statistics counter errors:\s*(?P<val>\d+)"
)


_STAT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_STAT_ACCEPTED_RE, "packets_accepted_by_deleted_entries"),
    (_STAT_DROPPED_RE, "packets_dropped_by_deleted_entries"),
    (_STAT_COUNTER_ERR_RE, "run_out_of_statistics_counter_errors"),
]


def _parse_flow_entry(stripped: str, flow_types: dict[str, FlowTypeEntry]) -> bool:
    """Try to parse a flow type data line and add it to *flow_types*.

    Returns True if the line was consumed.
    """
    m = _FLOW_RE.match(stripped)
    if not m:
        return False
    flow_types[m.group("flow")] = FlowTypeEntry(
        policer_type=int(m.group("policer_type")),
        type=m.group("type"),
        current_rate=int(m.group("cur_rate")),
        default_rate=int(m.group("def_rate")),
        accepted=int(m.group("accepted")),
        dropped=int(m.group("dropped")),
        tos_value=m.group("tos"),
    )
    return True


def _parse_statistics_line(
    stripped: str,
    statistics: dict[str, int],
) -> bool:
    """Try to parse a statistics line and update *statistics*.

    Returns True if the line was consumed.
    """
    for pattern, key in _STAT_PATTERNS:
        m = pattern.match(stripped)
        if m:
            statistics[key] = int(m.group("val"))
            return True
    return False


@register(
    OS.CISCO_IOSXR,
    r"show lpts pifib hardware police location (?P<location>\S+)",
)
class ShowLptsPifibHardwarePoliceLocationParser(
    BaseParser["ShowLptsPifibHardwarePoliceLocationResult"],
):
    """Parser for 'show lpts pifib hardware police location' on IOS-XR.

    Parses per-flow-type LPTS policer entries and summary statistics
    from the hardware PIFIB table.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def _parse_header(cls, lines: list[str]) -> tuple[str, int]:
        """Extract node identifier and burst value from header lines.

        Returns:
            Tuple of (node, burst_ms).

        Raises:
            ValueError: If node or burst cannot be found.
        """
        node: str | None = None
        burst_ms: int | None = None

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if node is None:
                if m := _NODE_RE.match(stripped):
                    node = m.group("node")
                    continue
            if burst_ms is None:
                if m := _BURST_RE.match(stripped):
                    burst_ms = int(m.group("burst"))
                    break

        if node is None:
            msg = "No node identifier found in output"
            raise ValueError(msg)
        if burst_ms is None:
            msg = "No burst value found in output"
            raise ValueError(msg)

        return node, burst_ms

    @classmethod
    def parse(cls, output: str) -> ShowLptsPifibHardwarePoliceLocationResult:
        """Parse LPTS PIFIB hardware police location output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed LPTS policer information keyed by flow type name.

        Raises:
            ValueError: If required fields (node, burst) cannot be parsed.
        """
        lines = output.splitlines()
        node, burst_ms = cls._parse_header(lines)

        flow_types: dict[str, FlowTypeEntry] = {}
        statistics: dict[str, int] = {
            "packets_accepted_by_deleted_entries": 0,
            "packets_dropped_by_deleted_entries": 0,
            "run_out_of_statistics_counter_errors": 0,
        }
        has_statistics = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if _parse_flow_entry(stripped, flow_types):
                continue
            if _parse_statistics_line(stripped, statistics):
                has_statistics = True

        if not flow_types:
            msg = "No flow type entries found in output"
            raise ValueError(msg)

        result: ShowLptsPifibHardwarePoliceLocationResult = {
            "node": node,
            "burst_ms": burst_ms,
            "flow_types": flow_types,
        }

        if has_statistics:
            result["statistics"] = cast(StatisticsEntry, statistics)

        return result
