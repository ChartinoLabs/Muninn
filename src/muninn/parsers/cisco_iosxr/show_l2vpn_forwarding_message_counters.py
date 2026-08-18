"""Parser for 'show l2vpn forwarding message counters private location'.

Targets Cisco IOS-XR.
"""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class MessageCounterEntry(TypedDict):
    """Schema for a single message counter entry.

    Attributes:
        count: The message count value.
        info1: First info field (hex string).
        info2: Second info field (hex string).
        time: Timestamp of last occurrence, if present.
    """

    count: int
    info1: str
    info2: str
    time: NotRequired[str]


class EventTraceEntry(TypedDict):
    """Schema for a single event trace history entry.

    Attributes:
        time: Timestamp of the event.
        event: Event name.
        info1: First info field (hex string).
        info2: Second info field (hex string).
    """

    time: str
    event: str
    info1: str
    info2: str


class RoundTripDelayEntry(TypedDict):
    """Schema for a round-trip delay statistics row.

    Attributes:
        minimum: Minimum delay value.
        maximum: Maximum delay value.
        average: Average delay value.
        count: Number of samples.
        zeros: Number of zero-delay samples.
        object: Object type, if present.
        action: Action type, if present.
    """

    minimum: int
    maximum: int
    average: int
    count: int
    zeros: int
    object: NotRequired[str]
    action: NotRequired[str]


class RoundTripDelayTable(TypedDict):
    """Schema for a round-trip delay statistics table.

    Attributes:
        unit: The unit of measurement (us or ns).
        entries: Dict of entry key to delay row. Keys are derived from
            the object/action columns when present, or a sequential
            index string otherwise.
    """

    unit: str
    entries: dict[str, RoundTripDelayEntry]


class ShowL2vpnForwardingMessageCountersResult(TypedDict):
    """Schema for parsed 'show l2vpn forwarding message counters' output.

    Attributes:
        message_counters: Dict of message name to counter entry.
        event_trace_history: List of event trace entries in chronological order.
        event_trace_total_events: Total event count from the header.
        round_trip_delays: Dict of table name to delay statistics.
    """

    message_counters: dict[str, MessageCounterEntry]
    event_trace_history: list[EventTraceEntry]
    event_trace_total_events: int
    round_trip_delays: dict[str, RoundTripDelayTable]


# Line 1 of a counter entry: "     message name:   count   info1"
_COUNTER_LINE1 = re.compile(
    r"^\s{4,}(?P<message>.+?):\s+(?P<count>\d+)\s+(?P<info1>0x[0-9a-fA-F]+)\s*$"
)

# Line 2 of a counter entry: "info2   [optional timestamp]"
_COUNTER_LINE2 = re.compile(
    r"^(?P<info2>0x[0-9a-fA-F]+)"
    r"(?:\s+(?P<time>\w+\s+\d+\s+\d+:\d+:\d+\.\d+))?\s*$"
)

# Some messages lack a colon
# (e.g., "l2vpn dynamic mac remote learning messages received")
# Line 1 alternative without colon: "     message name   count   info1"
_COUNTER_LINE1_NO_COLON = re.compile(
    r"^\s{4,}(?P<message>[a-zA-Z][\w\s/\-:=]+\S)\s+(?P<count>\d+)\s+(?P<info1>0x[0-9a-fA-F]+)\s*$"
)

# Event trace history header
_EVENT_TRACE_HEADER = re.compile(
    r"^\s*Event Trace History \[Total events:\s*(?P<total>\d+)\]\s*$"
)

# Event trace entry line:
# "     Jun  2 15:48:41.216 AIB RESTART          0x0          0x0          -  -"
_EVENT_TRACE_LINE = re.compile(
    r"^\s+(?P<time>\w+\s+\d+\s+\d+:\d+:\d+\.\d+)\s+"
    r"(?P<event>\S+(?:\s+\S+)*?)\s+"
    r"(?P<info1>0x[0-9a-fA-F]+)\s+"
    r"(?P<info2>0x[0-9a-fA-F]+)"
    r"\s+.*$"
)

# Round-trip delay section header
_RTD_HEADER = re.compile(
    r"^\s+(?P<name>.+?)\s+round-trip delay\s+\((?P<unit>\w+)\)\s*$"
)

# PUNTING rate header (different naming pattern)
_PUNTING_HEADER = re.compile(r"^\s+(?P<name>PUNTING rate)\s+\((?P<unit>\w+).*?\)\s*$")

# Numeric data line for delay tables (5+ columns)
_RTD_DATA_LINE = re.compile(
    r"^\s+(?P<minimum>\d+)\s+"
    r"(?P<maximum>\d+)\s+"
    r"(?P<average>\d+)\s+"
    r"(?P<count>\d+)\s+"
    r"(?P<zeros>\d+)"
    r"(?:\s+(?P<object_action>.+?))?\s*$"
)

# Separator line
_SEPARATOR_LINE = re.compile(r"^\s*-{10,}\s*$")


def _is_section_boundary(line: str) -> bool:
    """Return True if line marks the end of a counter section."""
    if _EVENT_TRACE_HEADER.search(line):
        return True
    return bool(_RTD_HEADER.match(line) or _PUNTING_HEADER.match(line))


def _try_counter_line1(line: str) -> tuple[str, int, str] | None:
    """Try both line-1 counter patterns. Returns (message, count, info1) or None."""
    m = _COUNTER_LINE1.match(line)
    if m:
        return m.group("message").strip(), int(m.group("count")), m.group("info1")
    m = _COUNTER_LINE1_NO_COLON.match(line)
    if m:
        return m.group("message").strip(), int(m.group("count")), m.group("info1")
    return None


def _try_counter_line2(
    line: str,
    pending_message: str,
    pending_count: int,
    pending_info1: str,
    counters: dict[str, MessageCounterEntry],
) -> bool:
    """Try line-2 pattern and finalize the counter entry. Returns True if matched."""
    m2 = _COUNTER_LINE2.match(line)
    if not m2:
        return False
    entry: MessageCounterEntry = {
        "count": pending_count,
        "info1": pending_info1,
        "info2": m2.group("info2"),
    }
    if m2.group("time"):
        entry["time"] = m2.group("time")
    counters[pending_message] = entry
    return True


def _parse_counter_section(
    lines: list[str],
    start: int,
) -> tuple[dict[str, MessageCounterEntry], int]:
    """Parse the message counters section.

    Returns the counters dict and the index where parsing stopped.
    """
    counters: dict[str, MessageCounterEntry] = {}
    i = start
    pending_message: str | None = None
    pending_count: int = 0
    pending_info1: str = ""

    while i < len(lines):
        line = lines[i]

        if _is_section_boundary(line):
            break

        # Try line 1 pattern (with or without colon)
        line1_result = _try_counter_line1(line)
        if line1_result and pending_message is None:
            pending_message, pending_count, pending_info1 = line1_result
            i += 1
            continue
        if line1_result and pending_message is not None:
            # New counter line resets previous pending
            pending_message, pending_count, pending_info1 = line1_result
            i += 1
            continue

        # Try line 2 pattern (info2 + optional time)
        if pending_message is not None:
            if _try_counter_line2(
                line, pending_message, pending_count, pending_info1, counters
            ):
                pending_message = None
                i += 1
                continue

        # Reset pending if line doesn't match expected continuation
        pending_message = None
        i += 1

    return counters, i


def _parse_event_trace(
    lines: list[str],
    start: int,
    total_events: int,
) -> tuple[list[EventTraceEntry], int]:
    """Parse the event trace history section.

    Returns events as a list in chronological order and the line index
    where parsing stopped.
    """
    events: list[EventTraceEntry] = []
    i = start
    found_data_separator = False

    while i < len(lines):
        line = lines[i]

        # The section ends with a separator line after the data rows
        if _SEPARATOR_LINE.match(line):
            if found_data_separator:
                # This is the closing separator
                i += 1
                break
            # First separator after header row
            found_data_separator = True
            i += 1
            continue

        evt_match = _EVENT_TRACE_LINE.match(line)
        if evt_match:
            found_data_separator = True
            events.append(
                EventTraceEntry(
                    time=evt_match.group("time"),
                    event=evt_match.group("event"),
                    info1=evt_match.group("info1"),
                    info2=evt_match.group("info2"),
                )
            )

        i += 1

    return events, i


_ACTION_KEYWORDS = frozenset(("CREATE", "MODIFY", "DELETE", "BIND", "UNBIND"))


def _parse_obj_action(
    raw: str,
    entry: RoundTripDelayEntry,
) -> str | None:
    """Parse object/action text and populate entry fields.

    Returns the current pending object name.
    """
    text = raw.strip()
    parts = text.rsplit(None, 1)
    if len(parts) == 2 and parts[1] in _ACTION_KEYWORDS:  # noqa: PLR2004
        entry["object"] = parts[0]
        entry["action"] = parts[1]
        return parts[0]
    entry["object"] = text
    return text


def _match_rtd_header(line: str) -> re.Match[str] | None:
    """Match a round-trip delay table header line."""
    m = _RTD_HEADER.match(line)
    if m:
        return m
    return _PUNTING_HEADER.match(line)


def _rtd_entry_key(entry: RoundTripDelayEntry, idx: int) -> str:
    """Derive a dict key for an RTD entry.

    Uses object/action when available, falls back to index.
    """
    obj = entry.get("object")
    action = entry.get("action")
    if obj and action:
        return f"{obj}/{action}"
    if obj:
        return obj
    return str(idx)


def _process_rtd_data_line(
    line: str,
    entries: list[RoundTripDelayEntry],
    pending_object: str | None,
) -> tuple[bool, str | None]:
    """Process a potential RTD data or control line.

    Returns (consumed, updated_pending_object).
    """
    data_match = _RTD_DATA_LINE.match(line)
    if data_match:
        entry_rtd: RoundTripDelayEntry = {
            "minimum": int(data_match.group("minimum")),
            "maximum": int(data_match.group("maximum")),
            "average": int(data_match.group("average")),
            "count": int(data_match.group("count")),
            "zeros": int(data_match.group("zeros")),
        }
        obj_action = data_match.group("object_action")
        if obj_action:
            pending_object = _parse_obj_action(obj_action, entry_rtd)
        entries.append(entry_rtd)
        return True, pending_object

    if _SEPARATOR_LINE.match(line):
        return True, None

    stripped = line.strip()
    if stripped in _ACTION_KEYWORDS:
        if entries and "action" not in entries[-1]:
            entries[-1]["action"] = stripped
            if pending_object and "object" not in entries[-1]:
                entries[-1]["object"] = pending_object
        return True, pending_object

    return False, pending_object


def _entries_to_dict(
    entries: list[RoundTripDelayEntry],
) -> dict[str, RoundTripDelayEntry]:
    """Convert entry list to keyed dict."""
    return {_rtd_entry_key(e, idx): e for idx, e in enumerate(entries)}


def _parse_rtd_tables(
    lines: list[str],
    start: int,
) -> dict[str, RoundTripDelayTable]:
    """Parse all round-trip delay tables.

    Returns dict of table name to delay table.
    """
    tables: dict[str, RoundTripDelayTable] = {}
    i = start
    current_name: str | None = None
    current_unit: str | None = None
    current_entries: list[RoundTripDelayEntry] = []
    pending_object: str | None = None

    while i < len(lines):
        line = lines[i]

        rtd_match = _match_rtd_header(line)
        if rtd_match:
            if current_name is not None and current_unit is not None:
                tables[current_name] = RoundTripDelayTable(
                    unit=current_unit,
                    entries=_entries_to_dict(current_entries),
                )
            current_name = rtd_match.group("name")
            current_unit = rtd_match.group("unit")
            current_entries = []
            pending_object = None
            i += 1
            continue

        if current_name is not None:
            consumed, pending_object = _process_rtd_data_line(
                line, current_entries, pending_object
            )
            if consumed:
                i += 1
                continue

        i += 1

    if current_name is not None and current_unit is not None:
        tables[current_name] = RoundTripDelayTable(
            unit=current_unit,
            entries=_entries_to_dict(current_entries),
        )

    return tables


@register(
    OS.CISCO_IOSXR,
    r"show l2vpn forwarding message counters private location (?P<location>\S+)",
)
class ShowL2vpnForwardingMessageCountersParser(
    BaseParser["ShowL2vpnForwardingMessageCountersResult"],
):
    """Parser for 'show l2vpn forwarding message counters private location'.

    Parses L2FIB collaborator message counters, event trace history, and
    round-trip delay statistics tables.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.L2VPN})

    @classmethod
    def parse(cls, output: str) -> "ShowL2vpnForwardingMessageCountersResult":
        """Parse message counters output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed message counters, event trace history, and delay tables.

        Raises:
            ValueError: If no message counter data found in output.
        """
        lines = output.splitlines()

        # Phase 1: Parse message counters
        message_counters, counter_end = _parse_counter_section(lines, 0)

        # Phase 2: Parse event trace history
        event_trace_history: list[EventTraceEntry] = []
        event_trace_total_events: int = 0
        rtd_start = counter_end

        # Find event trace header
        for idx in range(counter_end, len(lines)):
            evt_match = _EVENT_TRACE_HEADER.search(lines[idx])
            if evt_match:
                event_trace_total_events = int(evt_match.group("total"))
                event_trace_history, rtd_start = _parse_event_trace(
                    lines, idx + 1, event_trace_total_events
                )
                break

        # Phase 3: Parse round-trip delay tables
        round_trip_delays = _parse_rtd_tables(lines, rtd_start)

        if not message_counters:
            msg = "No L2VPN forwarding message counter data found in output"
            raise ValueError(msg)

        return ShowL2vpnForwardingMessageCountersResult(
            message_counters=message_counters,
            event_trace_history=event_trace_history,
            event_trace_total_events=event_trace_total_events,
            round_trip_delays=round_trip_delays,
        )
