"""Parser for 'show high-availability path-monitoring' command on Palo Alto PAN-OS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_RE
from muninn.registry import register
from muninn.tags import ParserTag


class PathMonitoringEntry(TypedDict):
    """Schema for a single path monitoring destination entry."""

    group: str
    name: str
    type: str
    destination: str
    success: int
    total: int
    rtt_min_ms: float
    rtt_max_ms: float
    rtt_avg_ms: float
    probe_count: int
    probe_interval_ms: int


class ShowHighAvailabilityPathMonitoringResult(TypedDict):
    """Schema for 'show high-availability path-monitoring' parsed output."""

    total_paths_monitored: int
    hold_time_ms: int
    paths: dict[str, PathMonitoringEntry]


# Total paths monitored
_TOTAL_PATHS = re.compile(r"^total paths monitored\s*:\s*(\d+)")

# Hold time in ms
_HOLD_TIME = re.compile(r"^hold time to send probe packets\s*:\s*(\d+)\s*ms")

# Data line: grp/name/type destination suc/total rtt probe_cnt/interval
_DATA_LINE = re.compile(
    r"^(?P<group>\S+)/(?P<name>\S+)/(?P<type>\S+)\s+"
    r"(?P<destination>\S+)\s+"
    r"(?P<success>\d+)/(?P<total>\d+)\s+"
    r"(?P<rtt_min>[\d.]+)/(?P<rtt_max>[\d.]+)/(?P<rtt_avg>[\d.]+)\s+"
    r"(?P<probe_count>\d+)/(?P<probe_interval>\d+)"
)


def _build_entry(match: re.Match[str]) -> PathMonitoringEntry:
    """Build a PathMonitoringEntry from a regex match."""
    return PathMonitoringEntry(
        group=match.group("group"),
        name=match.group("name"),
        type=match.group("type"),
        destination=match.group("destination"),
        success=int(match.group("success")),
        total=int(match.group("total")),
        rtt_min_ms=float(match.group("rtt_min")),
        rtt_max_ms=float(match.group("rtt_max")),
        rtt_avg_ms=float(match.group("rtt_avg")),
        probe_count=int(match.group("probe_count")),
        probe_interval_ms=int(match.group("probe_interval")),
    )


def _validate_required(
    total_paths: int | None,
    hold_time: int | None,
) -> tuple[int, int]:
    """Validate that required header fields were parsed."""
    if total_paths is None:
        msg = "Could not parse total paths monitored from output"
        raise ValueError(msg)
    if hold_time is None:
        msg = "Could not parse hold time from output"
        raise ValueError(msg)
    return total_paths, hold_time


@register(OS.PALOALTO_PANOS, "show high-availability path-monitoring")
class ShowHighAvailabilityPathMonitoringParser(
    BaseParser[ShowHighAvailabilityPathMonitoringResult],
):
    """Parser for 'show high-availability path-monitoring' on PAN-OS.

    Parses path monitoring status including monitored destinations,
    success/failure counts, RTT statistics, and probe configuration.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.REDUNDANCY})

    @classmethod
    def parse(cls, output: str) -> ShowHighAvailabilityPathMonitoringResult:
        """Parse 'show high-availability path-monitoring' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed path monitoring information.

        Raises:
            ValueError: If required fields cannot be parsed.
        """
        total_paths: int | None = None
        hold_time: int | None = None
        paths: dict[str, PathMonitoringEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()

            if not stripped or SEPARATOR_DASH_RE.match(stripped):
                continue

            total_match = _TOTAL_PATHS.match(stripped)
            if total_match:
                total_paths = int(total_match.group(1))
                continue

            hold_match = _HOLD_TIME.match(stripped)
            if hold_match:
                hold_time = int(hold_match.group(1))
                continue

            data_match = _DATA_LINE.match(stripped)
            if data_match:
                entry = _build_entry(data_match)
                paths[entry["destination"]] = entry

        total, hold = _validate_required(total_paths, hold_time)

        return cast(
            ShowHighAvailabilityPathMonitoringResult,
            {
                "total_paths_monitored": total,
                "hold_time_ms": hold,
                "paths": paths,
            },
        )
