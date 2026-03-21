"""Parser for 'show netconf-yang sessions' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class NetconfYangSessionEntry(TypedDict):
    """One NETCONF-YANG management session."""

    session_id: str
    transport: str
    username: str
    source_host: str
    global_lock: str


class ShowNetconfYangSessionsResult(TypedDict):
    """Schema for 'show netconf-yang sessions' parsed output."""

    session_count: int
    sessions: list[NetconfYangSessionEntry]


_SESSION_COUNT_PATTERN = re.compile(
    r"^Number of sessions\s*:\s*(?P<count>\d+)\s*$",
    re.IGNORECASE,
)

_SESSION_ROW_PATTERN = re.compile(
    r"^(?P<id>\d+)\s+"
    r"(?P<transport>\S+)\s+"
    r"(?P<username>\S+)\s+"
    r"(?P<source>\S+)\s+"
    r"(?P<lock>\S+)\s*$"
)


@register(OS.CISCO_IOSXE, "show netconf-yang sessions")
class ShowNetconfYangSessionsParser(BaseParser[ShowNetconfYangSessionsResult]):
    """Parser for 'show netconf-yang sessions' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNetconfYangSessionsResult:
        """Parse 'show netconf-yang sessions' output.

        Args:
            output: Raw CLI output from 'show netconf-yang sessions'.

        Returns:
            Session count and session rows from the table.
        """
        session_count = 0
        sessions: list[NetconfYangSessionEntry] = []

        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue

            count_match = _SESSION_COUNT_PATTERN.match(line)
            if count_match:
                session_count = int(count_match.group("count"))
                continue

            if line.startswith("-") or "session-id" in line.lower():
                continue

            row_match = _SESSION_ROW_PATTERN.match(line)
            if row_match:
                sessions.append(
                    NetconfYangSessionEntry(
                        session_id=row_match.group("id"),
                        transport=row_match.group("transport"),
                        username=row_match.group("username"),
                        source_host=row_match.group("source"),
                        global_lock=row_match.group("lock"),
                    )
                )

        return ShowNetconfYangSessionsResult(
            session_count=session_count,
            sessions=sessions,
        )
