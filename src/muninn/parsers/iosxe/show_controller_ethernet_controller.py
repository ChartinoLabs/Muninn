"""Parser for 'show controller ethernet-controller' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ControllerEthernetColumn(TypedDict):
    """One numeric counter and its description in a transmit or receive column."""

    value: str
    label: str


class ControllerEthernetStatRow(TypedDict):
    """One line of statistics.

    ``transmit`` and ``receive`` are independent counters shown on the same line;
    their labels often match (e.g. both ``Total bytes``) but may differ
    (e.g. ``System FCS error frames`` vs ``IpgViolation frames``).

    ``receive`` is omitted when the line has no receive column.
    """

    transmit: ControllerEthernetColumn
    receive: NotRequired[ControllerEthernetColumn]


class ShowControllerEthernetControllerResult(TypedDict):
    """Schema for 'show controller ethernet-controller' parsed output."""

    interface: str
    statistics: list[ControllerEthernetStatRow]
    last_update: str


_IF_RE = re.compile(
    r"^Transmit\s+(\S+)\s+Receive\s*$",
    re.I,
)
_LAST_RE = re.compile(r"^LAST UPDATE\s+(.+)$", re.I)
# Two columns separated by wide padding; labels may contain single spaces
# (e.g. "Total bytes", "65 to 127 byte frames").
_STAT_ROW_FULL_RE = re.compile(
    r"^\s*(\d+)\s+(.+?)\s{2,}(\d+)\s+(.+)$",
)
# Continuation lines with only the transmit column (e.g. collision sub-counts).
_STAT_ROW_TX_ONLY_RE = re.compile(r"^\s*(\d+)\s+(.+)$")


def _parse_stat_row(line: str) -> ControllerEthernetStatRow | None:
    s = line.rstrip()
    m = _STAT_ROW_FULL_RE.match(s)
    if m:
        return ControllerEthernetStatRow(
            transmit=ControllerEthernetColumn(
                value=m.group(1),
                label=m.group(2).strip(),
            ),
            receive=ControllerEthernetColumn(
                value=m.group(3),
                label=m.group(4).strip(),
            ),
        )
    m = _STAT_ROW_TX_ONLY_RE.match(s)
    if m:
        return ControllerEthernetStatRow(
            transmit=ControllerEthernetColumn(
                value=m.group(1),
                label=m.group(2).strip(),
            ),
        )
    return None


def _parse_controller_ethernet(output: str) -> ShowControllerEthernetControllerResult:
    lines = output.splitlines()
    interface = ""
    stats: list[ControllerEthernetStatRow] = []
    last_update = ""
    for line in lines:
        s = line.rstrip()
        if not s.strip():
            continue
        im = _IF_RE.match(s.strip())
        if im:
            interface = im.group(1)
            continue
        lm = _LAST_RE.match(s.strip())
        if lm:
            last_update = lm.group(1).strip()
            continue
        row = _parse_stat_row(s)
        if row:
            stats.append(row)
    if not interface:
        msg = "Ethernet controller interface not found"
        raise ValueError(msg)
    return ShowControllerEthernetControllerResult(
        interface=interface,
        statistics=stats,
        last_update=last_update,
    )


@register(OS.CISCO_IOSXE, "show controller ethernet-controller")
class ShowControllerEthernetControllerParser(
    BaseParser[ShowControllerEthernetControllerResult]
):
    """Parser for 'show controller ethernet-controller' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowControllerEthernetControllerResult:
        """Parse 'show controller ethernet-controller' output."""
        return _parse_controller_ethernet(output)
