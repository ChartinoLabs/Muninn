"""Parser for 'show logging onboard rp active clilog detail' command on IOS-XE."""

from __future__ import annotations

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register

# ---------------------------------------------------------------------------
# TypedDict schemas
# ---------------------------------------------------------------------------


class SummaryEntry(TypedDict):
    """Schema for a single CLI logging summary entry."""

    count: int


class ContinuousEntry(TypedDict):
    """Schema for a single CLI logging continuous entry."""

    date: str
    time: str
    command: str


class ShowLoggingOnboardRpActiveClilogDetailResult(TypedDict):
    """Schema for 'show logging onboard rp active clilog detail' parsed output.

    Top-level keys:
        summary: Command execution counts keyed by command string.
        continuous: Timestamped command entries keyed by sequence number.
    """

    summary: NotRequired[dict[str, SummaryEntry]]
    continuous: NotRequired[dict[str, ContinuousEntry]]


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Summary section entry: " 1    show logging onboard RP active clilog detail"
_SUMMARY_ENTRY_RE = re.compile(r"^\s*(?P<count>\d+)\s+(?P<command>.+?)\s*$")

# Continuous section entry: " 03/30/2023 02:41:08 show logging onboard ..."
_CONTINUOUS_ENTRY_RE = re.compile(
    r"^\s*(?P<date>\d{2}/\d{2}/\d{4})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<command>.+?)\s*$"
)

# Section headers
_SUMMARY_HEADER_RE = re.compile(r"^-*\s*CLI LOGGING SUMMARY INFORMATION\s*-*$")
_CONTINUOUS_HEADER_RE = re.compile(r"^-*\s*CLI LOGGING CONTINUOUS INFORMATION\s*-*$")

# Separator and column header lines
_SEPARATOR_RE = re.compile(r"^-{2,}$")
_COLUMN_HEADER_RE = re.compile(r"^\s*(COUNT\s+COMMAND|MM/DD/YYYY\s+HH:MM:SS\s+COMMAND)")

# Lines indicating no data
_NO_DATA_RE = re.compile(r"^\s*No\s+(summary|continuous)\s+data", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


@register(OS.CISCO_IOSXE, "show logging onboard rp active clilog detail")
class ShowLoggingOnboardRpActiveClilogDetailParser(
    BaseParser["ShowLoggingOnboardRpActiveClilogDetailResult"],
):
    """Parser for 'show logging onboard rp active clilog detail' on IOS-XE.

    Parses CLI logging summary (command execution counts) and continuous
    (timestamped command history) sections from onboard logging output.
    """

    @classmethod
    def parse(cls, output: str) -> ShowLoggingOnboardRpActiveClilogDetailResult:
        """Parse 'show logging onboard rp active clilog detail' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed CLI logging data with summary and continuous sections.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        lines = output.splitlines()

        if not lines or all(not line.strip() for line in lines):
            msg = "No output to parse"
            raise ValueError(msg)

        summary, continuous = cls._parse_sections(lines)

        result: ShowLoggingOnboardRpActiveClilogDetailResult = {}
        if summary:
            result["summary"] = summary
        if continuous:
            result["continuous"] = continuous

        if not result:
            msg = "No CLI logging data found in output"
            raise ValueError(msg)

        return result

    @classmethod
    def _parse_sections(
        cls, lines: list[str]
    ) -> tuple[
        dict[str, SummaryEntry],
        dict[str, ContinuousEntry],
    ]:
        """Split output into summary and continuous sections and parse each.

        Returns:
            Tuple of (summary_dict, continuous_dict).
        """
        section: str | None = None
        summary: dict[str, SummaryEntry] = {}
        continuous: dict[str, ContinuousEntry] = {}
        continuous_seq = 0

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            # Detect section transitions
            if _SUMMARY_HEADER_RE.match(stripped):
                section = "summary"
                continue

            if _CONTINUOUS_HEADER_RE.match(stripped):
                section = "continuous"
                continue

            # Skip separator and column header lines
            if _SEPARATOR_RE.match(stripped) or _COLUMN_HEADER_RE.match(stripped):
                continue

            # Skip "no data" lines
            if _NO_DATA_RE.match(stripped):
                continue

            # Parse entries based on current section
            if section == "summary":
                cls._parse_summary_line(stripped, summary)
            elif section == "continuous":
                continuous_seq = cls._parse_continuous_line(
                    stripped, continuous, continuous_seq
                )

        return summary, continuous

    @classmethod
    def _parse_summary_line(
        cls,
        line: str,
        summary: dict[str, SummaryEntry],
    ) -> None:
        """Parse a single summary section line and aggregate by command."""
        match = _SUMMARY_ENTRY_RE.match(line)
        if not match:
            return

        command = match.group("command")
        count = int(match.group("count"))

        if command in summary:
            summary[command]["count"] += count
        else:
            summary[command] = {"count": count}

    @classmethod
    def _parse_continuous_line(
        cls,
        line: str,
        continuous: dict[str, ContinuousEntry],
        seq: int,
    ) -> int:
        """Parse a single continuous section line.

        Returns:
            Updated sequence counter.
        """
        match = _CONTINUOUS_ENTRY_RE.match(line)
        if not match:
            return seq

        seq += 1
        continuous[str(seq)] = {
            "date": match.group("date"),
            "time": match.group("time"),
            "command": match.group("command"),
        }

        return seq
