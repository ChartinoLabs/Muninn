"""Parser for 'show users' command on IOS."""

import re
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class UserEntry(TypedDict):
    """Schema for a single user line entry."""

    active: bool
    host: NotRequired[str]
    user: NotRequired[str]
    idle: NotRequired[str]
    location: NotRequired[str]


class ShowUsersResult(TypedDict):
    """Schema for 'show users' parsed output."""

    lines: dict[str, UserEntry]


# Matches user table lines such as:
#  *  0 con 0                idle                 01:58
#    10 vty 0                Virtual-Access2        0        1212321
#  *  4 vty 1     admin      idle                 00:00:00   10.0.0.2
#  * vty 322                 idle                 00:00:00 10.24.69.196
#  *868 vty 0/1/0 lab        idle                 00:00:00 10.61.105.18
_USER_LINE_RE = re.compile(
    r"^(?P<active>\*)?"
    r"(?: +)?"
    r"(?P<line>(?:\d+)?\s*\S+ (?:\d+(?:/\d+)*))"
    r"(?:(?: {1,9})(?P<user>\S+))?"
    r" +(?P<host>\S+)"
    r"(?: +)?"
    r"(?P<idle>\S+)?"
    r"(?: +(?P<location>\S+))?$"
)

# Section header for the Interface table that follows the user table
_INTERFACE_HEADER_RE = re.compile(r"^\s*Interface\s+User\s+Mode\s+Idle\s+Peer Address")

# Header line for the user table
_USER_HEADER_RE = re.compile(r"^\s*Line\s+User\s+Host")

# Whitespace normalization pattern
_WHITESPACE_RE = re.compile(r"\s+")

# Optional fields to extract from the regex match
_OPTIONAL_FIELDS = ("user", "host", "idle", "location")


def _build_entry(match: re.Match[str]) -> tuple[str, UserEntry]:
    """Build a UserEntry from a regex match.

    Args:
        match: Successful regex match against a user line.

    Returns:
        Tuple of (line_name, entry).
    """
    line_name = _WHITESPACE_RE.sub(" ", match.group("line").strip())

    entry: UserEntry = {
        "active": match.group("active") == "*",
    }

    for field in _OPTIONAL_FIELDS:
        value = match.group(field)
        if value:
            entry[field] = value  # type: ignore[literal-required]

    return line_name, entry


@register(OS.CISCO_IOS, "show users")
class ShowUsersParser(BaseParser[ShowUsersResult]):
    """Parser for 'show users' on IOS.

    Parses the user session table showing line, user, host, idle time,
    and location for each active terminal session.

    Example output::

            Line       User       Host(s)              Idle       Location
         *  0 con 0                idle                 01:58
           10 vty 0                Virtual-Access2        0        1212321
    """

    @classmethod
    def parse(cls, output: str) -> ShowUsersResult:
        """Parse 'show users' output.

        Args:
            output: Raw CLI output from 'show users' command.

        Returns:
            Parsed user entries keyed by line name.

        Raises:
            ValueError: If no user entries found in output.
        """
        lines: dict[str, UserEntry] = {}

        for raw_line in output.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue

            # Stop parsing at the Interface section
            if _INTERFACE_HEADER_RE.match(raw_line):
                break

            # Skip the header line
            if _USER_HEADER_RE.match(raw_line):
                continue

            match = _USER_LINE_RE.match(stripped)
            if not match:
                continue

            line_name, entry = _build_entry(match)
            lines[line_name] = entry

        if not lines:
            msg = "No user entries found in output"
            raise ValueError(msg)

        return {"lines": lines}
