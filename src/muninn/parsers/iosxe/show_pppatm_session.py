"""Parser for 'show pppatm session' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class PppAtmSessionRow(TypedDict):
    """One PPPoATM session row.

    ``atm_intf``, ``vt``, and ``va`` (when present) are canonical interface names.
    Columns that contained only NA-like placeholders (no semantic value) are omitted.
    """

    atm_intf: str
    uniq_id: NotRequired[str]
    vpi_vci: NotRequired[str]
    encap: NotRequired[str]
    vt: NotRequired[str]
    va: NotRequired[str]
    va_st: NotRequired[str]
    state: NotRequired[str]


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


def _is_na_like_placeholder(value: str) -> bool:
    """True when *value* is the usual Cisco “no value” sentinel, case-insensitive."""
    return value.strip().casefold() in {"n/a", "na"}


def _optional_cli_str(raw: str) -> str | None:
    """Return stripped CLI text, or *None* when it is an NA-like placeholder."""
    s = raw.strip()
    if _is_na_like_placeholder(s):
        return None
    return s


def _optional_canonical_interface(raw: str) -> str | None:
    """Canonical interface name, or *None* when *raw* is an NA-like placeholder."""
    s = _optional_cli_str(raw)
    if s is None:
        return None
    return canonical_interface_name(s, os=OS.CISCO_IOSXE)


def _session_dict_key(row: PppAtmSessionRow) -> str:
    """Stable key when the device omits a numeric uniq id."""
    uid = row.get("uniq_id")
    if uid:
        return uid
    return row["atm_intf"]


def _parse_pppatm_row(line: str) -> PppAtmSessionRow | None:
    m = _ROW_RE.match(line.strip())
    if not m:
        return None
    atm = _optional_canonical_interface(m.group("atm"))
    if atm is None:
        return None
    out: dict[str, str] = {"atm_intf": atm}
    uid = _optional_cli_str(m.group("uid"))
    if uid is not None:
        out["uniq_id"] = uid
    vpi = _optional_cli_str(m.group("vpi"))
    if vpi is not None:
        out["vpi_vci"] = vpi
    enc = _optional_cli_str(m.group("enc"))
    if enc is not None:
        out["encap"] = enc
    vt = _optional_canonical_interface(m.group("vt"))
    if vt is not None:
        out["vt"] = vt
    va = _optional_canonical_interface(m.group("va"))
    if va is not None:
        out["va"] = va
    vast = _optional_cli_str(m.group("vast"))
    if vast is not None:
        out["va_st"] = vast
    st = _optional_cli_str(m.group("st"))
    if st is not None:
        out["state"] = st
    return cast(PppAtmSessionRow, out)


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
