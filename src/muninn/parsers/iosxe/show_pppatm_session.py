"""Parser for 'show pppatm session' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PppAtmSessionRow(TypedDict):
    """One PPPoATM session row."""

    uniq_id: str
    atm_intf: str
    vpi_vci: str
    encap: str
    vt: str
    va: str
    va_st: str
    state: str


class ShowPppAtmSessionResult(TypedDict):
    """Schema for 'show pppatm session' parsed output."""

    summary_lines: list[str]
    sessions_in_state: str | None
    sessions_total: int | None
    sessions: dict[str, PppAtmSessionRow]


_STATE_RE = re.compile(
    r"^(\d+)\s+session\s+in\s+(.+?)\s+State\s*$",
    re.I,
)
_TOTAL_RE = re.compile(r"^(\d+)\s+session\s+total\s*$", re.I)
_ROW_RE = re.compile(
    r"^(?P<uid>\S+)\s+(?P<atm>\S+)\s+(?P<vpi>\S+)\s+(?P<enc>\S+)\s+"
    r"(?P<vt>\S+)\s+(?P<va>\S+)\s+(?P<vast>\S+)\s+(?P<st>\S+)\s*$"
)
# Columns: Uniq ID, ATM-Intf, VPI/VCI, Encap, VT, VA, VA-st, State


def _session_dict_key(row: PppAtmSessionRow) -> str:
    """Stable key when the device omits a numeric uniq id."""
    uid = row["uniq_id"]
    if uid != "N/A":
        return uid
    return row["atm_intf"]


def _parse_pppatm_row(line: str) -> PppAtmSessionRow | None:
    m = _ROW_RE.match(line.strip())
    if not m:
        return None
    return PppAtmSessionRow(
        uniq_id=m.group("uid"),
        atm_intf=m.group("atm"),
        vpi_vci=m.group("vpi"),
        encap=m.group("enc"),
        vt=m.group("vt"),
        va=m.group("va"),
        va_st=m.group("vast"),
        state=m.group("st"),
    )


class _PppAtmAcc:
    """Mutable state for PPPoATM session parse."""

    __slots__ = ("summary_lines", "sessions_in_state", "sessions_total", "sessions")

    def __init__(self) -> None:
        self.summary_lines: list[str] = []
        self.sessions_in_state: str | None = None
        self.sessions_total: int | None = None
        self.sessions: dict[str, PppAtmSessionRow] = {}

    def feed(self, line: str) -> None:
        s = line.strip()
        if not s:
            return
        if s.lower().startswith("show pppatm"):
            self.summary_lines.append(s)
            return
        sm = _STATE_RE.match(s)
        if sm:
            self.sessions_in_state = sm.group(2).strip()
            return
        tm = _TOTAL_RE.match(s)
        if tm:
            self.sessions_total = int(tm.group(1))
            return
        if s.startswith("Uniq ID") or set(s) <= {"-"}:
            return
        row = _parse_pppatm_row(s)
        if row:
            self.sessions[_session_dict_key(row)] = row

    def result(self) -> ShowPppAtmSessionResult:
        if self.sessions_total is None and not self.sessions:
            msg = "No PPPoATM session data parsed"
            raise ValueError(msg)
        return cast(
            ShowPppAtmSessionResult,
            {
                "summary_lines": self.summary_lines,
                "sessions_in_state": self.sessions_in_state,
                "sessions_total": self.sessions_total,
                "sessions": self.sessions,
            },
        )


def _parse_pppatm_session(output: str) -> ShowPppAtmSessionResult:
    acc = _PppAtmAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show pppatm session")
class ShowPppAtmSessionParser(BaseParser[ShowPppAtmSessionResult]):
    """Parser for 'show pppatm session' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPppAtmSessionResult:
        """Parse 'show pppatm session' output."""
        return _parse_pppatm_session(output)
