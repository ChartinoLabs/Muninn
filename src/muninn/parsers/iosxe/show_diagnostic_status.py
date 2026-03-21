"""Parser for 'show diagnostic status' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class DiagnosticTestEntry(TypedDict):
    """One running diagnostic test."""

    name: str
    run_by: str


class DiagnosticCardEntry(TypedDict):
    """Diagnostics for one card."""

    card: str
    description: str
    tests: dict[str, DiagnosticTestEntry]


class ShowDiagnosticStatusResult(TypedDict):
    """Schema for 'show diagnostic status' parsed output."""

    cards: dict[str, DiagnosticCardEntry]


_HEADER_SKIP = re.compile(r"^(Card|======|------)", re.I)
_ROW_RE = re.compile(
    r"^\s*(?P<card>\d+)\s+(?P<desc>.+?)\s{2,}(?P<test>\S+)\s+(?P<run><[^>]+>)\s*$",
)
_CONT_RE = re.compile(r"^\s+(?P<test>\S+)\s+(?P<run><[^>]+>)\s*$")


def _parse_diagnostic_status(output: str) -> dict[str, DiagnosticCardEntry]:
    cards: dict[str, DiagnosticCardEntry] = {}
    current: DiagnosticCardEntry | None = None
    for line in output.splitlines():
        s = line.rstrip()
        if not s.strip() or "show diagnostic" in s.lower():
            continue
        if _HEADER_SKIP.match(s.strip()):
            continue
        m = _ROW_RE.match(s)
        if m:
            tname = m.group("test")
            card_id = m.group("card")
            current = DiagnosticCardEntry(
                card=card_id,
                description=m.group("desc").strip(),
                tests={
                    tname: DiagnosticTestEntry(
                        name=tname,
                        run_by=m.group("run"),
                    )
                },
            )
            cards[card_id] = current
            continue
        cm = _CONT_RE.match(s)
        if cm and current is not None:
            tname = cm.group("test")
            current["tests"][tname] = DiagnosticTestEntry(
                name=tname,
                run_by=cm.group("run"),
            )
    return cards


@register(OS.CISCO_IOSXE, "show diagnostic status")
class ShowDiagnosticStatusParser(BaseParser[ShowDiagnosticStatusResult]):
    """Parser for 'show diagnostic status' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.PLATFORM})

    @classmethod
    def parse(cls, output: str) -> ShowDiagnosticStatusResult:
        """Parse 'show diagnostic status' output."""
        cards = _parse_diagnostic_status(output)
        if not cards:
            msg = "No diagnostic status entries parsed"
            raise ValueError(msg)
        return cast(ShowDiagnosticStatusResult, {"cards": cards})
