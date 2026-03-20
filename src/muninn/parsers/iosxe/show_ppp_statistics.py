"""Parser for 'show ppp statistics' command on IOS-XE."""

import re
from enum import IntEnum
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class _PppSection(IntEnum):
    NONE = 0
    STATISTICS = 1
    MIB_COUNTERS = 2
    DISCONNECT = 3


class PppStatisticRow(TypedDict):
    """Row under 'Type PPP Statistic'."""

    type_id: int
    description: str
    total: int
    since_cleared: int


class PppMibCounterRow(TypedDict):
    """Row under 'Type PPP MIB Counters'."""

    type_id: int
    description: str
    peak: int
    current: int


class PppDisconnectRow(TypedDict):
    """Row under 'Type PPP Disconnect Reason'."""

    type_id: int
    description: str
    total: int
    since_cleared: int


class ShowPppStatisticsResult(TypedDict):
    """Schema for 'show ppp statistics' parsed output."""

    statistics: list[PppStatisticRow]
    mib_counters: list[PppMibCounterRow]
    disconnect_reasons: list[PppDisconnectRow]


_TWO_VALUE_ROW = re.compile(
    r"^\s*(?P<type_id>\d+)\s+(?P<desc>.+?)\s+(?P<a>\d+)\s+(?P<b>\d+)\s*$"
)


def _append_row_for_section(
    section: _PppSection,
    type_id: int,
    desc: str,
    a: int,
    b: int,
    statistics: list[PppStatisticRow],
    mib_counters: list[PppMibCounterRow],
    disconnect_reasons: list[PppDisconnectRow],
) -> None:
    if section is _PppSection.STATISTICS:
        statistics.append(
            PppStatisticRow(
                type_id=type_id,
                description=desc,
                total=a,
                since_cleared=b,
            )
        )
    elif section is _PppSection.MIB_COUNTERS:
        mib_counters.append(
            PppMibCounterRow(
                type_id=type_id,
                description=desc,
                peak=a,
                current=b,
            )
        )
    elif section is _PppSection.DISCONNECT:
        disconnect_reasons.append(
            PppDisconnectRow(
                type_id=type_id,
                description=desc,
                total=a,
                since_cleared=b,
            )
        )


def _update_section(stripped: str, section: _PppSection) -> _PppSection:
    if "Type PPP Statistic" in stripped and "MIB" not in stripped:
        return _PppSection.STATISTICS
    if "Type PPP MIB Counters" in stripped:
        return _PppSection.MIB_COUNTERS
    if "Type PPP Disconnect Reason" in stripped:
        return _PppSection.DISCONNECT
    return section


def _parse_ppp_statistics_output(output: str) -> ShowPppStatisticsResult:
    statistics: list[PppStatisticRow] = []
    mib_counters: list[PppMibCounterRow] = []
    disconnect_reasons: list[PppDisconnectRow] = []

    section = _PppSection.NONE

    for raw in output.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        new_section = _update_section(stripped, section)
        if new_section != section:
            section = new_section
            continue

        if stripped.startswith("----") or stripped.startswith("Type "):
            continue

        match = _TWO_VALUE_ROW.match(line)
        if not match or section is _PppSection.NONE:
            continue

        type_id = int(match.group("type_id"))
        desc = match.group("desc").strip()
        a = int(match.group("a"))
        b = int(match.group("b"))
        _append_row_for_section(
            section,
            type_id,
            desc,
            a,
            b,
            statistics,
            mib_counters,
            disconnect_reasons,
        )

    return ShowPppStatisticsResult(
        statistics=statistics,
        mib_counters=mib_counters,
        disconnect_reasons=disconnect_reasons,
    )


@register(OS.CISCO_IOSXE, "show ppp statistics")
class ShowPppStatisticsParser(BaseParser[ShowPppStatisticsResult]):
    """Parser for 'show ppp statistics' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowPppStatisticsResult:
        """Parse 'show ppp statistics' output into three tabular sections."""
        return _parse_ppp_statistics_output(output)
