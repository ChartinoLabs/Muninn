"""Parser for IOS authentication session summary commands."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

_HEADER_RE = re.compile(
    r"^\s*Interface\s+(?:MAC\s+Address|Identifier)\s+Method\s+Domain\s+Status",
    re.IGNORECASE,
)
_SEPARATOR_RE = re.compile(r"^[\s\-]+$")
_DATA_RE = re.compile(
    r"^\s*(?P<interface>\S+)\s+"
    r"(?P<mac_address>\S+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<domain>\S+)\s+"
    r"(?P<status>(?:Authz\s+\S+|\S+))\s+"
    r"(?:(?P<fg>\S+)\s+)?"
    r"(?P<session_id>[0-9A-Fa-f]+)\s*$",
)
_SESSION_COUNT_RE = re.compile(r"^\s*Session\s+count\s*=\s*(\d+)", re.IGNORECASE)


class SessionTableEntry(TypedDict):
    """Normalized row parsed from an IOS session summary table."""

    interface: str
    mac_address: str
    method: str
    domain: str
    status: str
    session_id: str
    fg: NotRequired[str]


class ParsedSessionTable(TypedDict):
    """Normalized parse result for IOS session tables."""

    sessions: list[SessionTableEntry]
    session_count: NotRequired[int]


def _find_data_start(lines: list[str], *, missing_header_message: str) -> int:
    for i, line in enumerate(lines):
        if _HEADER_RE.match(line):
            return i + 1

    raise ValueError(missing_header_message)


def _parse_session_table(
    output: str,
    *,
    missing_header_message: str,
    missing_sessions_message: str,
) -> ParsedSessionTable:
    """Parse IOS authentication/access session summary tables."""
    lines = output.splitlines()
    start_idx = _find_data_start(lines, missing_header_message=missing_header_message)

    sessions: list[SessionTableEntry] = []
    session_count: int | None = None

    for line in lines[start_idx:]:
        if not line.strip() or _SEPARATOR_RE.match(line):
            continue

        count_match = _SESSION_COUNT_RE.match(line)
        if count_match:
            session_count = int(count_match.group(1))
            continue

        data_match = _DATA_RE.match(line)
        if not data_match:
            continue

        entry: SessionTableEntry = {
            "interface": canonical_interface_name(
                data_match.group("interface"),
                os=OS.CISCO_IOS,
            ),
            "mac_address": data_match.group("mac_address"),
            "method": data_match.group("method"),
            "domain": data_match.group("domain"),
            "status": data_match.group("status"),
            "session_id": data_match.group("session_id"),
        }

        fg = data_match.group("fg")
        if fg:
            entry["fg"] = fg

        sessions.append(entry)

    if not sessions:
        raise ValueError(missing_sessions_message)

    result: ParsedSessionTable = {"sessions": sessions}
    if session_count is not None:
        result["session_count"] = session_count

    return result


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


@register(OS.CISCO_IOS, "show access-session")
@register(OS.CISCO_IOS, "show authentication sessions")
class ShowAuthenticationSessionsParser(
    BaseParser[ShowAuthenticationSessionsResult],
):
    """Parser for 'show authentication sessions' and 'show access-session'."""

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
        parsed = _parse_session_table(
            output,
            missing_header_message=(
                "No authentication sessions header line found in output"
            ),
            missing_sessions_message="No authentication sessions found in output",
        )

        sessions: dict[str, dict[str, AuthSessionEntry]] = {}
        for entry in parsed["sessions"]:
            interface = entry["interface"]
            mac_address = entry["mac_address"]

            auth_entry: AuthSessionEntry = {
                "method": entry["method"],
                "domain": entry["domain"],
                "status": entry["status"],
                "session_id": entry["session_id"],
            }
            if "fg" in entry:
                auth_entry["fg"] = entry["fg"]

            if interface not in sessions:
                sessions[interface] = {}
            sessions[interface][mac_address] = auth_entry

        result: ShowAuthenticationSessionsResult = {"sessions": sessions}
        if "session_count" in parsed:
            result["session_count"] = parsed["session_count"]

        return result
