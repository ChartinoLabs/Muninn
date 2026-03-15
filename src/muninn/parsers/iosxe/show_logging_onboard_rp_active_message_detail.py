"""Parser for 'show logging onboard rp active message detail' on IOS-XE."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class SummaryMessageEntry(TypedDict):
    """Schema for a single summary message entry."""

    timestamp: str
    facility: str
    severity: int
    mnemonic: str
    count: NotRequired[int]
    count_exceeded: NotRequired[bool]
    persistence_flag: NotRequired[str]
    description: str


class ContinuousMessageEntry(TypedDict):
    """Schema for a single continuous message entry."""

    timestamp: str
    facility: str
    severity: int
    mnemonic: str
    description: str


class ShowLoggingOnboardRpActiveMessageDetailResult(TypedDict):
    """Schema for 'show logging onboard rp active message detail' parsed output.

    Messages are keyed by a 1-based sequence number (as string) within
    each section.
    """

    summary_messages: NotRequired[dict[str, SummaryMessageEntry]]
    continuous_messages: NotRequired[dict[str, ContinuousMessageEntry]]


# -- Section headers --

_SUMMARY_HEADER = re.compile(
    r"^ERROR\s+MESSAGE\s+SUMMARY\s+INFORMATION$", re.IGNORECASE
)
_CONTINUOUS_HEADER = re.compile(
    r"^ERROR\s+MESSAGE\s+CONTINUOUS\s+INFORMATION$", re.IGNORECASE
)

# -- Message patterns --

# Summary line with structured syslog: count may have ">" prefix for overflow.
# Two formats observed:
#   count LAST  description
#   count : LAST : description
_SUMMARY_MSG = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
    r"%(?P<facility>\S+?)-(?P<sev>\d)-(?P<mnem>\S+)\s*:\s*"
    r"(?P<count>>?\d+)\s+:?\s*(?P<flag>LAST|FIRST)?\s*:?\s*"
    r"(?P<desc>.+)$"
)

# Summary line with unrecognized message ID (no count/flag).
_SUMMARY_UNRECOGNIZED = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
    r"%Unrecognized\s+message\s+ID\s+(?P<id>\d+)$"
)

# Continuous line with structured syslog.
_CONTINUOUS_MSG = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
    r"%(?P<facility>\S+?)-(?P<sev>\d)-(?P<mnem>\S+)\s*:\s*"
    r"(?P<desc>.+)$"
)

# Continuous line with unrecognized message ID.
_CONTINUOUS_UNRECOGNIZED = re.compile(
    r"^(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+"
    r"%Unrecognized\s+message\s+ID\s+(?P<id>\d+)$"
)

_SEPARATOR = re.compile(r"^-{3,}$")
_COLUMN_HEADER = re.compile(r"^MM/DD/YYYY", re.IGNORECASE)

_UNRECOGNIZED_FACILITY = "SYSTEM"
_UNRECOGNIZED_MNEMONIC = "UNRECOGNIZED_MSG_ID"
_UNRECOGNIZED_SEVERITY = 0


def _is_skip_line(line: str) -> bool:
    """Return True for lines that should be skipped."""
    if not line:
        return True
    if _SEPARATOR.match(line):
        return True
    return bool(_COLUMN_HEADER.match(line))


def _parse_count(raw: str) -> tuple[int, bool]:
    """Parse a count value, returning (count, exceeded).

    A leading '>' indicates the actual count exceeded the reported value.
    """
    if raw.startswith(">"):
        return int(raw[1:]), True
    return int(raw), False


def _parse_summary_line(line: str) -> SummaryMessageEntry | None:
    """Try to parse a summary message line."""
    match = _SUMMARY_MSG.match(line)
    if match:
        count, exceeded = _parse_count(match.group("count"))
        entry = SummaryMessageEntry(
            timestamp=match.group("ts"),
            facility=match.group("facility"),
            severity=int(match.group("sev")),
            mnemonic=match.group("mnem"),
            count=count,
            description=match.group("desc").strip(),
        )
        if exceeded:
            entry["count_exceeded"] = True
        flag = match.group("flag")
        if flag:
            entry["persistence_flag"] = flag
        return entry

    match = _SUMMARY_UNRECOGNIZED.match(line)
    if match:
        return SummaryMessageEntry(
            timestamp=match.group("ts"),
            facility=_UNRECOGNIZED_FACILITY,
            severity=_UNRECOGNIZED_SEVERITY,
            mnemonic=_UNRECOGNIZED_MNEMONIC,
            description=f"Unrecognized message ID {match.group('id')}",
        )

    return None


def _parse_continuous_line(line: str) -> ContinuousMessageEntry | None:
    """Try to parse a continuous message line."""
    match = _CONTINUOUS_MSG.match(line)
    if match:
        return ContinuousMessageEntry(
            timestamp=match.group("ts"),
            facility=match.group("facility"),
            severity=int(match.group("sev")),
            mnemonic=match.group("mnem"),
            description=match.group("desc").strip(),
        )

    match = _CONTINUOUS_UNRECOGNIZED.match(line)
    if match:
        return ContinuousMessageEntry(
            timestamp=match.group("ts"),
            facility=_UNRECOGNIZED_FACILITY,
            severity=_UNRECOGNIZED_SEVERITY,
            mnemonic=_UNRECOGNIZED_MNEMONIC,
            description=f"Unrecognized message ID {match.group('id')}",
        )

    return None


_SECTION_SUMMARY = "summary"
_SECTION_CONTINUOUS = "continuous"


def _detect_section(line: str) -> str | None:
    """Detect if line is a section header. Returns section name or None."""
    if _SUMMARY_HEADER.match(line):
        return _SECTION_SUMMARY
    if _CONTINUOUS_HEADER.match(line):
        return _SECTION_CONTINUOUS
    return None


def _extract_messages(
    output: str,
) -> tuple[dict[str, SummaryMessageEntry], dict[str, ContinuousMessageEntry]]:
    """Extract summary and continuous messages from raw output."""
    summary_msgs: dict[str, SummaryMessageEntry] = {}
    continuous_msgs: dict[str, ContinuousMessageEntry] = {}
    current_section: str | None = None
    summary_seq = 0
    continuous_seq = 0

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if _is_skip_line(line):
            continue

        section = _detect_section(line)
        if section is not None:
            current_section = section
            continue

        if current_section == _SECTION_SUMMARY:
            entry = _parse_summary_line(line)
            if entry is not None:
                summary_seq += 1
                summary_msgs[str(summary_seq)] = entry

        elif current_section == _SECTION_CONTINUOUS:
            cont_entry = _parse_continuous_line(line)
            if cont_entry is not None:
                continuous_seq += 1
                continuous_msgs[str(continuous_seq)] = cont_entry

    return summary_msgs, continuous_msgs


def _build_result(
    summary_msgs: dict[str, SummaryMessageEntry],
    continuous_msgs: dict[str, ContinuousMessageEntry],
) -> ShowLoggingOnboardRpActiveMessageDetailResult:
    """Build the result dict, omitting empty sections."""
    if not summary_msgs and not continuous_msgs:
        msg = "No message entries found in output"
        raise ValueError(msg)

    result = ShowLoggingOnboardRpActiveMessageDetailResult()
    if summary_msgs:
        result["summary_messages"] = summary_msgs
    if continuous_msgs:
        result["continuous_messages"] = continuous_msgs
    return result


@register(OS.CISCO_IOSXE, "show logging onboard rp active message detail")
class ShowLoggingOnboardRpActiveMessageDetailParser(
    BaseParser[ShowLoggingOnboardRpActiveMessageDetailResult],
):
    """Parser for 'show logging onboard rp active message detail' command.

    Parses two sections:
      - ERROR MESSAGE SUMMARY INFORMATION: aggregated messages with counts.
      - ERROR MESSAGE CONTINUOUS INFORMATION: chronological message log.

    Example output:
        ERROR MESSAGE SUMMARY INFORMATION
        -------------------------------------------------------
        MM/DD/YYYY HH:MM:SS Facility-Sev-Name | Count | ...
        -------------------------------------------------------
        05/24/2023 19:02:45 %Unrecognized message ID 2507
        05/25/2023 10:33:38 %IOSXE-2-DIAGNOSTICS_PASSED : ...
        -------------------------------------------------------
        ERROR MESSAGE CONTINUOUS INFORMATION
        -------------------------------------------------------
        MM/DD/YYYY HH:MM:SS Facility-Sev-Name
        -------------------------------------------------------
        05/24/2023 18:42:22 %IOSXE-2-DIAGNOSTICS_PASSED : ...
    """

    @classmethod
    def parse(cls, output: str) -> ShowLoggingOnboardRpActiveMessageDetailResult:
        """Parse 'show logging onboard rp active message detail' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed message detail data with summary and continuous sections.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        summary_msgs, continuous_msgs = _extract_messages(output)
        return _build_result(summary_msgs, continuous_msgs)
