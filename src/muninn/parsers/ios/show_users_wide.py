"""Parser for 'show users wide' command on Cisco IOS and IOS-XE."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag

# IOS emits the full wide header; IOS-XE often emits only ``Line  User``
# because the Host(s)/Idle/Location columns are dropped when those values
# are absent across all rows.
_HEADER_RE = re.compile(r"^\s*Line\s+User(?:\s+Host\(s\)\s+Idle\s+Location)?\s*$")
_INTERFACE_HEADER_RE = re.compile(r"^\s*Interface\s+User\s+Mode\s+Idle\s+Peer Address")

# Wide form anchors on the HH:MM:SS idle field; user+host appear together
# or not at all.
_ROW_WIDE_RE = re.compile(
    r"^(?P<active>\*)?\s*"
    r"(?:\d+\s+)?"
    r"(?P<line_type>\S+)\s+(?P<line_id>\d+(?:/\d+)*)"
    r"(?:\s+(?P<user>\S+)\s+(?P<host>\S+))?"
    r"\s+(?P<idle>\d+:\d+:\d+)"
    r"(?:\s+(?P<location>\S+))?\s*$"
)
# Slim form has no idle/location columns and only an optional user.
_ROW_SLIM_RE = re.compile(
    r"^(?P<active>\*)?\s*"
    r"(?:\d+\s+)?"
    r"(?P<line_type>\S+)\s+(?P<line_id>\d+(?:/\d+)*)"
    r"(?:\s+(?P<user>\S+))?\s*$"
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
    groups = match.groupdict()
    for field in _OPTIONAL_FIELDS:
        value = groups.get(field)
        if value:
            entry[field] = value
    return match.group("line_type"), match.group("line_id"), entry


@register(OS.CISCO_IOSXE, "show users wide")
@register(OS.CISCO_IOS, "show users wide")
class ShowUsersWideParser(BaseParser[ShowUsersWideResult]):
    """Parser for 'show users wide' on Cisco IOS and IOS-XE.

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

            # Try the wide layout first, then fall back to the slim layout.
            # The two-pass approach is required because IOS-XE often emits
            # idle-with-no-user rows (e.g. unused vty lines like
            # ``0 con 0  00:00:00``) where a single combined regex would
            # mis-assign the idle value to the ``user`` field.
            match = _ROW_WIDE_RE.match(raw_line) or _ROW_SLIM_RE.match(raw_line)
            if match is None:
                continue

            line_type, line_id, entry = _build_entry(match)
            result.setdefault(line_type, {})[line_id] = entry

        if not result:
            msg = "No user entries found in 'show users wide' output"
            raise ValueError(msg)

        return {"lines": result}
