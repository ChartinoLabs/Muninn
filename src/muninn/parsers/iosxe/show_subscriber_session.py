"""Parser for 'show subscriber session' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class SubscriberSessionEntry(TypedDict):
    """One row from 'show subscriber session'."""

    uniq_id: str
    interface: str
    state: str
    service: str
    uptime: str
    tc_ct: str
    identifier: str


class ShowSubscriberSessionResult(TypedDict):
    """Schema for 'show subscriber session' parsed output."""

    total_sessions: int
    sessions: list[SubscriberSessionEntry]


_ROW_RE = re.compile(
    r"^\s*(?P<id>\d+)\s+(?P<if>\S+)\s+(?P<st>\S+)\s+(?P<svc>\S+)\s+"
    r"(?P<up>\S+)\s+(?P<tcc>\S+)\s+(?P<ident>.+)$"
)


def _parse_total_sessions(line: str) -> int | None:
    m = re.search(r"Total sessions\s+(\d+)", line, re.I)
    return int(m.group(1)) if m else None


def _parse_session_row(line: str) -> SubscriberSessionEntry | None:
    m = _ROW_RE.match(line)
    if not m:
        return None
    return SubscriberSessionEntry(
        uniq_id=m.group("id"),
        interface=m.group("if"),
        state=m.group("st"),
        service=m.group("svc"),
        uptime=m.group("up"),
        tc_ct=m.group("tcc"),
        identifier=m.group("ident").strip(),
    )


@register(OS.CISCO_IOSXE, "show subscriber session")
class ShowSubscriberSessionParser(BaseParser[ShowSubscriberSessionResult]):
    """Parser for 'show subscriber session' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowSubscriberSessionResult:
        """Parse 'show subscriber session' output."""
        total: int | None = None
        sessions: list[SubscriberSessionEntry] = []
        for line in output.splitlines():
            line = line.rstrip()
            if not line.strip():
                continue
            if line.strip().lower().startswith("uniq id"):
                continue
            if "Total sessions" in line:
                total = _parse_total_sessions(line)
                continue
            row = _parse_session_row(line)
            if row:
                sessions.append(row)
        if total is None:
            msg = "Total sessions line not found"
            raise ValueError(msg)
        return cast(
            ShowSubscriberSessionResult,
            {"total_sessions": total, "sessions": sessions},
        )
