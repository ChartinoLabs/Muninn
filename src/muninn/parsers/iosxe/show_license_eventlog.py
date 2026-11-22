"""Parser for 'show license eventlog' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# Matches the event log header line.
_HEADER_RE = re.compile(r"^\s*\*{4}\s*Event\s+Log\s*\*{4}\s*$")

# Matches the start of an event line:
#   2021-09-10 14:03:56.089 UTC SAEVT_READY
_EVENT_START_RE = re.compile(
    r"^\s*(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<timezone>\S+)\s+"
    r"(?P<event_type>\S+)"
    r"(?:\s+(?P<attrs_start>.+))?\s*$"
)

# Matches key="value" pairs within the attributes portion.
_KV_RE = re.compile(r'(?P<key>\w+)="(?P<value>[^"]*)"')

# Matches an unquoted key=value pair (e.g. count=0 without quotes).
_KV_UNQUOTED_RE = re.compile(r"(?P<key>\w+)=(?P<value>\S+)")


class EventEntry(TypedDict):
    """Schema for a single event log entry."""

    timestamp: str
    timezone: str
    event_type: str
    attributes: NotRequired[dict[str, str]]


class ShowLicenseEventlogResult(TypedDict):
    """Schema for 'show license eventlog' parsed output."""

    events: list[EventEntry]


def _parse_attributes(text: str) -> dict[str, str]:
    """Extract key=value pairs from an attribute string.

    Handles both quoted (key="value") and unquoted (key=value) forms.
    """
    attrs: dict[str, str] = {}
    for match in _KV_RE.finditer(text):
        attrs[match.group("key")] = match.group("value")
    # If no quoted matches found, try unquoted form.
    if not attrs:
        for match in _KV_UNQUOTED_RE.finditer(text):
            attrs[match.group("key")] = match.group("value")
    return attrs


@register(OS.CISCO_IOSXE, "show license eventlog")
class ShowLicenseEventlogParser(BaseParser[ShowLicenseEventlogResult]):
    """Parser for 'show license eventlog' on IOS-XE.

    Parses the Smart Licensing event log which contains timestamped
    entries with event types and optional key-value attributes.
    Events may span multiple lines due to terminal-width wrapping.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLicenseEventlogResult:
        """Parse 'show license eventlog' output.

        Args:
            output: Raw CLI output from 'show license eventlog' command.

        Returns:
            Parsed event log data.

        Raises:
            ValueError: If no event log entries are found.
        """
        events: list[dict] = []
        lines = output.splitlines()
        current_attrs_text = ""
        current_event: dict | None = None

        for line in lines:
            # Skip the header line.
            if _HEADER_RE.match(line):
                continue

            # Skip blank lines.
            if not line.strip():
                _finalize_event(current_event, current_attrs_text, events)
                current_event = None
                current_attrs_text = ""
                continue

            # Try to match a new event start.
            match = _EVENT_START_RE.match(line)
            if match:
                # Finalize the previous event if one is pending.
                _finalize_event(current_event, current_attrs_text, events)

                current_event = {
                    "timestamp": match.group("timestamp"),
                    "timezone": match.group("timezone"),
                    "event_type": match.group("event_type"),
                }
                current_attrs_text = match.group("attrs_start") or ""
            elif current_event is not None:
                # Continuation line: append to current attributes text.
                current_attrs_text += " " + line.strip()

        # Finalize the last event.
        _finalize_event(current_event, current_attrs_text, events)

        if not events:
            msg = "No event log entries found in output"
            raise ValueError(msg)

        return cast(ShowLicenseEventlogResult, {"events": events})


def _finalize_event(
    event: dict | None,
    attrs_text: str,
    events: list[dict],
) -> None:
    """Finalize a pending event by parsing its attributes and appending."""
    if event is None:
        return
    attrs_text = attrs_text.strip()
    if attrs_text:
        attrs = _parse_attributes(attrs_text)
        if attrs:
            event["attributes"] = attrs
    events.append(event)
