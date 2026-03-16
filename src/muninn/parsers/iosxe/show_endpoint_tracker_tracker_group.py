"""Parser for 'show endpoint-tracker tracker-group' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class TrackerGroupEntry(TypedDict):
    """Schema for a single tracker group entry."""

    element_trackers: list[str]
    status: str
    rtt_in_msec: list[str]
    probe_ids: list[int]


class ShowEndpointTrackerTrackerGroupResult(TypedDict):
    """Schema for 'show endpoint-tracker tracker-group' parsed output."""

    tracker_groups: dict[str, TrackerGroupEntry]


@register(OS.CISCO_IOSXE, "show endpoint-tracker tracker-group")
class ShowEndpointTrackerTrackerGroupParser(
    BaseParser[ShowEndpointTrackerTrackerGroupResult],
):
    """Parser for 'show endpoint-tracker tracker-group' command.

    Example output:
        Tracker Name       Element trackers name  Status
        group-udp-tcp      tcp-10002, udp-10002   UP(UP OR UP)
        group2             track1, track2         UP(UP OR UP)
    """

    tags: ClassVar[frozenset[str]] = frozenset({"sdwan"})

    _ROW_PATTERN = re.compile(
        r"^(?P<name>\S+)\s+"
        r"(?P<trackers>.+?)\s{2,}"
        r"(?P<status>\S+\([^)]+\))\s+"
        r"(?P<rtt>.+?)\s{2,}"
        r"(?P<probe_ids>[\d,\s]+)$"
    )

    @classmethod
    def _is_skip_line(cls, line: str) -> bool:
        """Check if a line should be skipped."""
        stripped = line.strip()
        if not stripped:
            return True
        if "Tracker Name" in line or "Element trackers" in line:
            return True
        if "show endpoint" in line or stripped.startswith("#"):
            return True
        return "#" in line and "show" in line

    @classmethod
    def _parse_csv_list(cls, value: str) -> list[str]:
        """Parse a comma-separated string into a list of stripped values."""
        return [v.strip() for v in value.split(",")]

    @classmethod
    def parse(cls, output: str) -> ShowEndpointTrackerTrackerGroupResult:
        """Parse 'show endpoint-tracker tracker-group' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed tracker group data keyed by tracker name.

        Raises:
            ValueError: If no tracker groups found.
        """
        tracker_groups: dict[str, TrackerGroupEntry] = {}

        for line in output.splitlines():
            if cls._is_skip_line(line):
                continue

            match = cls._ROW_PATTERN.match(line.strip())
            if match:
                name = match.group("name")
                tracker_groups[name] = TrackerGroupEntry(
                    element_trackers=cls._parse_csv_list(match.group("trackers")),
                    status=match.group("status"),
                    rtt_in_msec=cls._parse_csv_list(match.group("rtt")),
                    probe_ids=[
                        int(p) for p in cls._parse_csv_list(match.group("probe_ids"))
                    ],
                )

        if not tracker_groups:
            msg = "No tracker groups found in output"
            raise ValueError(msg)

        return ShowEndpointTrackerTrackerGroupResult(tracker_groups=tracker_groups)
