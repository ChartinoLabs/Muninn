"""Shared IOS session table parsing helpers."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
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
    """Normalized parse result for shared IOS session tables."""

    sessions: list[SessionTableEntry]
    session_count: NotRequired[int]


def _find_data_start(lines: list[str], *, missing_header_message: str) -> int:
    for i, line in enumerate(lines):
        if _HEADER_RE.match(line):
            return i + 1

    raise ValueError(missing_header_message)


def parse_session_table(
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
