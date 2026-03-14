"""Parser for 'show access-session' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name

# Matches a session line in either format:
#   Interface  MAC Address     Method   Domain   Status         Session ID
#   Interface  Identifier      Method   Domain   Status         Session ID
#   Interface  MAC Address     Method   Domain   Status  Fg     Session ID
# The status field may be one or two words (e.g. "Auth", "Authz Success").
# The session ID is always a hex string at end of line.
_SESSION_PATTERN = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<mac_address>\S+)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<domain>\S+)\s+"
    r"(?P<status>.+?)\s+"
    r"(?P<session_id>[0-9A-Fa-f]{24,})\s*$"
)

# Lines to skip: headers, separator dashes, session count, key legend
_SKIP_PATTERN = re.compile(
    r"^(?:Interface\s|---|-{10,}|Session\s+count|Key\s+to\s+Session|"
    r"\s+[A-Z]\s+-\s|$)"
)

# Known status values that may precede a single-char flag
_KNOWN_STATUSES = frozenset(
    {
        "Auth",
        "Unauth",
        "Authz Success",
        "Authz Failed",
        "Running",
        "Idle",
    }
)


class AccessSessionEntry(TypedDict):
    """Schema for a single access session entry."""

    interface: str
    mac_address: str
    method: str
    domain: str
    status: str
    flags: NotRequired[str]


class ShowAccessSessionResult(TypedDict):
    """Schema for 'show access-session' parsed output."""

    sessions: dict[str, AccessSessionEntry]


def _extract_status_and_flags(status_raw: str) -> tuple[str, str]:
    """Separate the status text from an optional trailing flag character.

    The "Fg" column, when present, appends a single uppercase letter
    after the status text. This function detects that pattern and
    returns (status, flags). If no flag is found, flags is empty.

    Args:
        status_raw: Raw status field from the regex match.

    Returns:
        Tuple of (status, flags).
    """
    parts = status_raw.rsplit(None, 1)
    if len(parts) == 2 and len(parts[-1]) == 1 and parts[-1].isupper():
        if parts[0] in _KNOWN_STATUSES:
            return parts[0], parts[1]
    return status_raw, ""


def _build_entry(match: re.Match[str]) -> tuple[str, AccessSessionEntry]:
    """Build a session entry from a regex match.

    Args:
        match: Successful regex match of a session line.

    Returns:
        Tuple of (session_id, entry dict).
    """
    session_id = match.group("session_id")
    interface = canonical_interface_name(match.group("interface"))
    status, flags = _extract_status_and_flags(match.group("status").strip())

    entry: AccessSessionEntry = {
        "interface": interface,
        "mac_address": match.group("mac_address"),
        "method": match.group("method"),
        "domain": match.group("domain"),
        "status": status,
    }

    if flags:
        entry["flags"] = flags

    return session_id, entry


@register(OS.CISCO_IOS, "show access-session")
class ShowAccessSessionParser(BaseParser[ShowAccessSessionResult]):
    """Parser for 'show access-session' command.

    Example output::

        Interface  MAC Address     Method  Domain  Status   Session ID
        Fa3/0/40   (unknown)       mab     UNKNOWN Running  0A5C...01FF
        Fa3/0/13   002a.12cd.3d08  mab     DATA    Auth     0A0A...01FF

    Sessions are keyed by session ID since the same interface can host
    multiple sessions (e.g. DATA and VOICE on the same port).
    """

    @classmethod
    def parse(cls, output: str) -> ShowAccessSessionResult:
        """Parse 'show access-session' output.

        Args:
            output: Raw CLI output from 'show access-session' command.

        Returns:
            Parsed sessions keyed by session ID.

        Raises:
            ValueError: If no sessions found in output.
        """
        sessions: dict[str, AccessSessionEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _SKIP_PATTERN.match(stripped):
                continue

            match = _SESSION_PATTERN.match(stripped)
            if not match:
                continue

            session_id, entry = _build_entry(match)
            sessions[session_id] = entry

        if not sessions:
            msg = "No access sessions found in output"
            raise ValueError(msg)

        return ShowAccessSessionResult(sessions=sessions)
