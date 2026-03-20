"""Parser for 'show pppoe statistics' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class PppoeCounterRow(TypedDict):
    """One PPPoE counter row."""

    name: str
    total: int
    since_cleared: int


class ShowPppoeStatisticsResult(TypedDict):
    """Schema for 'show pppoe statistics' parsed output."""

    pppoe_events: list[PppoeCounterRow]
    pppoe_statistics: list[PppoeCounterRow]


def _split_counter_row(line: str) -> tuple[str, int, int] | None:
    parts = line.split()
    if len(parts) < 3:
        return None
    try:
        total = int(parts[-2])
        cleared = int(parts[-1])
    except ValueError:
        return None
    name = " ".join(parts[:-2]).strip()
    if not name or name.startswith("---"):
        return None
    if re.match(r"^-+$", name):
        return None
    return name, total, cleared


class _PppoeAcc:
    """Mutable state for PPPoE statistics parse."""

    __slots__ = ("mode", "events", "stats")

    def __init__(self) -> None:
        self.mode: str | None = None
        self.events: list[PppoeCounterRow] = []
        self.stats: list[PppoeCounterRow] = []

    def feed(self, line: str) -> None:
        s = line.strip()
        if self._set_mode(s):
            return
        if self._skip_noise(s):
            return
        self._append_row(line)

    def _set_mode(self, s: str) -> bool:
        if "PPPoE Events" in s and "TOTAL" in s:
            self.mode = "events"
            return True
        if "PPPoE Statistics" in s and "TOTAL" in s:
            self.mode = "stats"
            return True
        return False

    def _skip_noise(self, s: str) -> bool:
        return (
            not s
            or set(s) <= {"-"}
            or s.startswith("Load for")
            or s.startswith("Time source")
        )

    def _append_row(self, line: str) -> None:
        sp = _split_counter_row(line)
        if not sp or not self.mode:
            return
        row = PppoeCounterRow(
            name=sp[0],
            total=sp[1],
            since_cleared=sp[2],
        )
        if self.mode == "events":
            self.events.append(row)
        else:
            self.stats.append(row)

    def result(self) -> ShowPppoeStatisticsResult:
        if not self.events and not self.stats:
            msg = "No PPPoE statistics tables parsed"
            raise ValueError(msg)
        return cast(
            ShowPppoeStatisticsResult,
            {
                "pppoe_events": self.events,
                "pppoe_statistics": self.stats,
            },
        )


def _parse_pppoe_statistics(output: str) -> ShowPppoeStatisticsResult:
    acc = _PppoeAcc()
    for line in output.splitlines():
        acc.feed(line)
    return acc.result()


@register(OS.CISCO_IOSXE, "show pppoe statistics")
class ShowPppoeStatisticsParser(BaseParser[ShowPppoeStatisticsResult]):
    """Parser for 'show pppoe statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPppoeStatisticsResult:
        """Parse 'show pppoe statistics' output."""
        return _parse_pppoe_statistics(output)
