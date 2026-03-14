"""Parser for 'show authentication sessions' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Header line that marks the start of tabular data
_HEADER_RE = re.compile(
    r"^\s*Interface\s+MAC\s+Address\s+Method\s+Domain\s+Status",
    re.IGNORECASE,
)

# Separator line of dashes
_SEPARATOR_RE = re.compile(r"^[\s\-]+$")

# Data line pattern for the summary table
# Supports two formats:
#   Interface  MAC Address     Method   Domain   Status          Session ID
#   Interface  MAC Address     Method   Domain   Status   Fg     Session ID
_DATA_RE = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<mac_address>\S+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<domain>\S+)\s+"
    r"(?P<status>(?:Authz\s+\S+|\S+))\s+"
    r"(?:(?P<fg>\S+)\s+)?"
    r"(?P<session_id>[0-9A-Fa-f]+)\s*$",
)

# Session count line
_SESSION_COUNT_RE = re.compile(
    r"^\s*Session\s+count\s*=\s*(\d+)",
    re.IGNORECASE,
)


class AuthSessionEntry(TypedDict):
    """Schema for a single authentication session entry."""

    method: str
    domain: str
    status: str
    session_id: str
    fg: NotRequired[str]


class ShowAuthenticationSessionsResult(TypedDict):
    """Schema for 'show authentication sessions' parsed output."""

    sessions: dict[str, dict[str, AuthSessionEntry]]
    session_count: NotRequired[int]


def _find_data_start(lines: list[str]) -> int:
    """Find the index of the first data line after the header.

    Raises:
        ValueError: If no header line is found in the output.
    """
    for i, line in enumerate(lines):
        if _HEADER_RE.match(line):
            return i + 1

    msg = "No authentication sessions header line found in output"
    raise ValueError(msg)


def _parse_output(output: str) -> ShowAuthenticationSessionsResult:
    """Parse the full show authentication sessions output."""
    lines = output.splitlines()
    start_idx = _find_data_start(lines)

    sessions: dict[str, dict[str, AuthSessionEntry]] = {}
    session_count: int | None = None

    for line in lines[start_idx:]:
        # Skip blank lines and separator lines
        if not line.strip() or _SEPARATOR_RE.match(line):
            continue

        # Check for session count
        count_match = _SESSION_COUNT_RE.match(line)
        if count_match:
            session_count = int(count_match.group(1))
            continue

        # Try to match a data line
        data_match = _DATA_RE.match(line)
        if not data_match:
            continue

        raw_interface = data_match.group("interface")
        interface = canonical_interface_name(raw_interface, os=OS.CISCO_IOS)
        mac_address = data_match.group("mac_address")

        entry: AuthSessionEntry = {
            "method": data_match.group("method"),
            "domain": data_match.group("domain"),
            "status": data_match.group("status"),
            "session_id": data_match.group("session_id"),
        }

        fg = data_match.group("fg")
        if fg:
            entry["fg"] = fg

        if interface not in sessions:
            sessions[interface] = {}
        sessions[interface][mac_address] = entry

    if not sessions:
        msg = "No authentication sessions found in output"
        raise ValueError(msg)

    result: ShowAuthenticationSessionsResult = {"sessions": sessions}
    if session_count is not None:
        result["session_count"] = session_count

    return result


@register(OS.CISCO_IOS, "show authentication sessions")
class ShowAuthenticationSessionsParser(
    BaseParser[ShowAuthenticationSessionsResult],
):
    """Parser for 'show authentication sessions' on IOS."""

    @classmethod
    def parse(cls, output: str) -> ShowAuthenticationSessionsResult:
        """Parse 'show authentication sessions' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed authentication sessions keyed by interface, then MAC address.

        Raises:
            ValueError: If no sessions found or no header detected.
        """
        return _parse_output(output)
