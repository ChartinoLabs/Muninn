"""Parser for 'show track' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class DelayedInfo(TypedDict):
    """Schema for delayed state information."""

    delayed_state: str
    secs_remaining: NotRequired[int]
    connection_state: NotRequired[str]


class TrackedByEntry(TypedDict):
    """Schema for a single tracked-by entry."""

    name: str
    interface: NotRequired[str]
    group_id: NotRequired[int]


class TrackEntry(TypedDict):
    """Schema for a single track entry."""

    track_type: str
    state: str
    change_count: int
    last_change: str
    object_name: NotRequired[str]
    address: NotRequired[str]
    mask: NotRequired[str]
    parameter: NotRequired[str]
    state_description: NotRequired[str]
    delayed: NotRequired[DelayedInfo]
    delay_up_secs: NotRequired[int]
    delay_down_secs: NotRequired[int]
    first_hop_interface_state: NotRequired[str]
    prev_first_hop_interface: NotRequired[str]
    threshold_down: NotRequired[int]
    threshold_up: NotRequired[int]
    latest_op_return_code: NotRequired[str]
    latest_rtt_ms: NotRequired[int]
    tracked_by: NotRequired[list[TrackedByEntry]]


class ShowTrackResult(TypedDict):
    """Schema for 'show track' parsed output."""

    tracks: dict[str, TrackEntry]


# --- Compiled regex patterns ---

_TRACK_HEADER = re.compile(r"^Track\s+(?P<track_id>\d+)\s*$")

_INTERFACE_LINE = re.compile(r"^Interface\s+(?P<name>\S+)\s+(?P<parameter>.+)$")

_IP_ROUTE_LINE = re.compile(
    r"^IP\s+route\s+(?P<address>[\d.]+)\s+(?P<mask>[\d.]+)\s+(?P<parameter>.+)$"
)

_IP_SLA_LINE = re.compile(r"^IP\s+SLA\s+(?P<sla_id>\d+)\s+(?P<parameter>.+)$")

_STATE_LINE = re.compile(
    r"^(?P<parameter>[\w ]+?)\s+is\s+(?P<state>Up|Down)"
    r"(?:\s+\((?P<state_description>[^)]+)\)"
    r"(?:,\s*delayed\s+(?P<delayed_state>Up|Down)"
    r"\s+\((?P<secs_remaining>\d+)\s+sec\s+remaining\)"
    r"(?:\s+\((?P<connection_state>\w+)\))?)?)?"
)

_CHANGE_LINE = re.compile(
    r"^(?P<change_count>\d+)\s+changes?,\s+last\s+change\s+(?P<last_change>\S+)$"
)

_DELAY_LINE = re.compile(
    r"^Delay\s+up\s+(?P<delay_up>\d+)\s+secs?,\s*down\s+(?P<delay_down>\d+)\s+secs?$"
)

_FIRST_HOP_LINE = re.compile(
    r"^First-hop\s+interface\s+is\s+(?P<state>\w+)"
    r"(?:\s+\(was\s+(?P<prev_interface>\S+)\))?$"
)

_THRESHOLD_LINE = re.compile(
    r"^Metric\s+threshold\s+down\s+(?P<down>\d+)\s+up\s+(?P<up>\d+)$"
)

_TRACKED_BY_ENTRY = re.compile(
    r"^(?P<name>[A-Za-z]{3,4})\s+(?P<interface>\S+)\s+(?P<group_id>\d+)$"
)

_RETURN_CODE_LINE = re.compile(r"^Latest\s+operation\s+return\s+code:\s+(?P<code>\w+)$")

_RTT_LINE = re.compile(r"^Latest\s+RTT\s+\(?millisecs\)?\s+(?P<rtt>\d+)$")


def _parse_type_line(line: str, entry: TrackEntry) -> bool:
    """Parse a track type line (Interface, IP route, IP SLA).

    Returns True if the line matched a type pattern.
    """
    match = _INTERFACE_LINE.match(line)
    if match:
        entry["track_type"] = "Interface"
        entry["object_name"] = canonical_interface_name(match.group("name"))
        entry["parameter"] = match.group("parameter")
        return True

    match = _IP_ROUTE_LINE.match(line)
    if match:
        entry["track_type"] = "IP route"
        entry["address"] = match.group("address")
        entry["mask"] = match.group("mask")
        entry["parameter"] = match.group("parameter")
        return True

    match = _IP_SLA_LINE.match(line)
    if match:
        entry["track_type"] = "IP SLA"
        entry["object_name"] = match.group("sla_id")
        entry["parameter"] = match.group("parameter")
        return True

    return False


def _parse_state_line(line: str, entry: TrackEntry) -> bool:
    """Parse a state line. Returns True if the line matched."""
    match = _STATE_LINE.match(line)
    if not match:
        return False

    entry["state"] = match.group("state")

    if match.group("state_description"):
        entry["state_description"] = match.group("state_description")

    if match.group("delayed_state"):
        delayed: DelayedInfo = {"delayed_state": match.group("delayed_state")}
        if match.group("secs_remaining"):
            delayed["secs_remaining"] = int(match.group("secs_remaining"))
        if match.group("connection_state"):
            delayed["connection_state"] = match.group("connection_state")
        entry["delayed"] = delayed

    return True


def _parse_detail_line(line: str, entry: TrackEntry) -> bool:
    """Parse detail lines (change, delay, threshold, etc.).

    Returns True if the line matched a known detail pattern.
    """
    match = _CHANGE_LINE.match(line)
    if match:
        entry["change_count"] = int(match.group("change_count"))
        entry["last_change"] = match.group("last_change")
        return True

    match = _DELAY_LINE.match(line)
    if match:
        entry["delay_up_secs"] = int(match.group("delay_up"))
        entry["delay_down_secs"] = int(match.group("delay_down"))
        return True

    match = _FIRST_HOP_LINE.match(line)
    if match:
        entry["first_hop_interface_state"] = match.group("state")
        if match.group("prev_interface"):
            entry["prev_first_hop_interface"] = canonical_interface_name(
                match.group("prev_interface")
            )
        return True

    match = _THRESHOLD_LINE.match(line)
    if match:
        entry["threshold_down"] = int(match.group("down"))
        entry["threshold_up"] = int(match.group("up"))
        return True

    match = _RETURN_CODE_LINE.match(line)
    if match:
        entry["latest_op_return_code"] = match.group("code")
        return True

    match = _RTT_LINE.match(line)
    if match:
        entry["latest_rtt_ms"] = int(match.group("rtt"))
        return True

    return False


def _parse_tracked_by_line(line: str, entry: TrackEntry) -> bool:
    """Parse a tracked-by entry line. Returns True if matched."""
    match = _TRACKED_BY_ENTRY.match(line)
    if not match:
        return False

    tracked_entry: TrackedByEntry = {"name": match.group("name")}
    if match.group("interface"):
        tracked_entry["interface"] = canonical_interface_name(match.group("interface"))
    if match.group("group_id"):
        tracked_entry["group_id"] = int(match.group("group_id"))

    tracked_by = entry.setdefault("tracked_by", [])
    tracked_by.append(tracked_entry)
    return True


def _parse_entry_line(line: str, entry: TrackEntry, in_tracked_by: bool) -> bool:
    """Dispatch a single line to the appropriate entry-level parser.

    Returns the updated ``in_tracked_by`` flag.
    """
    if line == "Tracked by:":
        return True

    if in_tracked_by:
        if _parse_tracked_by_line(line, entry):
            return True
        # Fall through — line doesn't belong to tracked-by section

    if _parse_type_line(line, entry):
        return False

    if _parse_state_line(line, entry):
        return False

    _parse_detail_line(line, entry)
    return False


@register(OS.CISCO_IOSXE, "show track")
class ShowTrackParser(BaseParser[ShowTrackResult]):
    """Parser for 'show track' command.

    Example output:
        Track 1
          Interface GigabitEthernet3.420 line-protocol
          Line protocol is Up
            1 change, last change 00:00:27
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.TRACKING})

    @classmethod
    def parse(cls, output: str) -> ShowTrackResult:
        """Parse 'show track' output.

        Args:
            output: Raw CLI output from 'show track' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        tracks: dict[str, TrackEntry] = {}
        current_entry: TrackEntry | None = None
        in_tracked_by = False

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check for new track header
            match = _TRACK_HEADER.match(line)
            if match:
                track_id = match.group("track_id")
                current_entry = TrackEntry(
                    track_type="", state="", change_count=0, last_change=""
                )
                tracks[track_id] = current_entry
                in_tracked_by = False
                continue

            if current_entry is None:
                continue

            in_tracked_by = _parse_entry_line(line, current_entry, in_tracked_by)

        if not tracks:
            msg = "No track entries found in output"
            raise ValueError(msg)

        return ShowTrackResult(tracks=tracks)
