"""Parser for 'show redundancy history reverse' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_ENTRY_RE = re.compile(r"^(?P<timestamp>\d{2}:\d{2}:\d{2})\s+(?P<message>.+)$")


class HistoryEntry(TypedDict):
    """Schema for a single redundancy history event."""

    timestamp: str
    message: str


class ShowRedundancyHistoryReverseResult(TypedDict):
    """Schema for 'show redundancy history reverse' parsed output."""

    entries: list[HistoryEntry]


def _parse_entries(output: str) -> list[HistoryEntry]:
    """Extract history entries from raw output, joining wrapped lines."""
    entries: list[HistoryEntry] = []
    current_timestamp: str | None = None
    current_message: str | None = None

    for line in output.splitlines():
        if not line:
            continue

        match = _ENTRY_RE.match(line)
        if match:
            if current_timestamp is not None and current_message is not None:
                entries.append(_build_entry(current_timestamp, current_message))
            current_timestamp = match.group("timestamp")
            current_message = match.group("message")
        elif current_message is not None:
            # Continuation line from terminal wrapping
            current_message += " " + line.strip()

    # Flush the last entry
    if current_timestamp is not None and current_message is not None:
        entries.append(_build_entry(current_timestamp, current_message))

    return entries


def _build_entry(timestamp: str, message: str) -> HistoryEntry:
    """Construct a HistoryEntry dict."""
    return {"timestamp": timestamp, "message": message}


@register(OS.CISCO_IOSXE, "show redundancy history reverse")
class ShowRedundancyHistoryReverseParser(
    BaseParser[ShowRedundancyHistoryReverseResult],
):
    """Parser for 'show redundancy history reverse' on IOS-XE."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {ParserTag.REDUNDANCY, ParserTag.SYSTEM}
    )

    @classmethod
    def parse(cls, output: str) -> ShowRedundancyHistoryReverseResult:
        """Parse 'show redundancy history reverse' output.

        Each line begins with a HH:MM:SS timestamp followed by the event
        description.  Lines that do not start with a timestamp are treated
        as continuations of the previous entry (terminal-width wrapping).

        Args:
            output: Raw CLI output.

        Returns:
            Parsed history entries in reverse-chronological order.

        Raises:
            ValueError: If no history entries are found.
        """
        entries = _parse_entries(output)

        if not entries:
            msg = "No history entries found in output"
            raise ValueError(msg)

        return cast(ShowRedundancyHistoryReverseResult, {"entries": entries})
