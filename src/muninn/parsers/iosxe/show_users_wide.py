"""Parser for 'show users wide' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

_HEADER_RE = re.compile(r"^\s*Line\s+User(?:\s+Host\(s\)\s+Idle\s+Location)?\s*$")
_INTERFACE_HEADER_RE = re.compile(r"^\s*Interface\s+User\s+Mode\s+Idle\s+Peer Address")

# Row format on IOS-XE 'show users wide':
#   <abs_line> <line_type> <line_id> [<user>] [<host>] [<idle>] [<location>]
# An optional leading '*' marks the active line. The User/Host/Idle/Location
# columns are sparsely populated; only Line is guaranteed.
_ROW_RE = re.compile(
    r"^(?P<active>\*)?\s*"
    r"(?:\d+\s+)?"
    r"(?P<line_type>\S+)\s+(?P<line_id>\d+(?:/\d+)*)"
    r"(?:\s+(?P<user>\S+))?"
    r"(?:\s+(?P<host>\S+))?"
    r"(?:\s+(?P<idle>\d+:\d+:\d+))?"
    r"(?:\s+(?P<location>\S+))?"
    r"\s*$"
)


class UserWideEntry(TypedDict):
    """Schema for a single line entry from 'show users wide'."""

    active: bool
    user: NotRequired[str]
    host: NotRequired[str]
    idle: NotRequired[str]
    location: NotRequired[str]


class ShowUsersWideResult(TypedDict):
    """Schema for 'show users wide' parsed output."""

    lines: dict[str, dict[str, UserWideEntry]]


_OPTIONAL_FIELDS = ("user", "host", "idle", "location")


def _build_entry(match: re.Match[str]) -> tuple[str, str, UserWideEntry]:
    """Assemble a (line_type, line_id, entry) tuple from a row match."""
    entry: UserWideEntry = {"active": match.group("active") == "*"}
    for field in _OPTIONAL_FIELDS:
        value = match.group(field)
        if value:
            entry[field] = value
    return match.group("line_type"), match.group("line_id"), entry


@register(OS.CISCO_IOSXE, "show users wide")
class ShowUsersWideParser(BaseParser[ShowUsersWideResult]):
    """Parser for 'show users wide' on IOS-XE.

    Parses the user session table showing line, user, and (when present)
    host, idle time, and location for each terminal session. On IOS-XE
    the Host/Idle/Location columns are frequently omitted, so all four
    are optional in the output schema.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowUsersWideResult:
        """Parse 'show users wide' output.

        Args:
            output: Raw CLI output from 'show users wide'.

        Returns:
            User entries keyed by line family (e.g. ``con``, ``vty``) and
            line identifier.

        Raises:
            ValueError: If no user entries are found in the output.
        """
        result: dict[str, dict[str, UserWideEntry]] = {}

        for raw_line in output.splitlines():
            if _INTERFACE_HEADER_RE.match(raw_line):
                break
            if not raw_line.strip() or _HEADER_RE.match(raw_line):
                continue

            match = _ROW_RE.match(raw_line)
            if match is None:
                continue

            line_type, line_id, entry = _build_entry(match)
            result.setdefault(line_type, {})[line_id] = entry

        if not result:
            msg = "No user entries found in 'show users wide' output"
            raise ValueError(msg)

        return {"lines": result}
