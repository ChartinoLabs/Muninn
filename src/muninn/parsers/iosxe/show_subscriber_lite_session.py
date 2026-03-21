"""Parser for 'show subscriber lite-session' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class SubscriberLiteSessionEntry(TypedDict):
    """One lite session row."""

    src_ip: str
    vrf: str
    s_vrf: str
    uptime_sec: int
    interface: str
    pbhk: str


class ShowSubscriberLiteSessionResult(TypedDict):
    """Schema for 'show subscriber lite-session' parsed output."""

    total_lite_sessions_up: int
    sessions: dict[str, SubscriberLiteSessionEntry]


_TOTAL_RE = re.compile(r"^Total lite sessions up:\s*(\d+)\s*$", re.I)
_ROW_RE = re.compile(
    r"^\s*(?P<ip>\S+)\s+(?P<vrf>\S+)\s+(?P<svrf>\S+)\s+(?P<up>\d+)\s+"
    r"(?P<if>\S+)\s+(?P<pbhk>\S+)\s*$"
)


def _parse_lite_row(line: str) -> SubscriberLiteSessionEntry | None:
    m = _ROW_RE.match(line)
    if not m:
        return None
    return SubscriberLiteSessionEntry(
        src_ip=m.group("ip"),
        vrf=m.group("vrf"),
        s_vrf=m.group("svrf"),
        uptime_sec=int(m.group("up")),
        interface=canonical_interface_name(m.group("if"), os=OS.CISCO_IOSXE),
        pbhk=m.group("pbhk"),
    )


@register(OS.CISCO_IOSXE, "show subscriber lite-session")
class ShowSubscriberLiteSessionParser(BaseParser[ShowSubscriberLiteSessionResult]):
    """Parser for 'show subscriber lite-session' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowSubscriberLiteSessionResult:
        """Parse 'show subscriber lite-session' output."""
        total = 0
        sessions: dict[str, SubscriberLiteSessionEntry] = {}
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            tm = _TOTAL_RE.match(line)
            if tm:
                total = int(tm.group(1))
                continue
            if line.lower().startswith("src-ip"):
                continue
            row = _parse_lite_row(line)
            if row:
                sessions[row["src_ip"]] = row
        if total == 0 and not sessions:
            msg = "No lite session data parsed"
            raise ValueError(msg)
        return cast(
            ShowSubscriberLiteSessionResult,
            {"total_lite_sessions_up": total, "sessions": sessions},
        )
