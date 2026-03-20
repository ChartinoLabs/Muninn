"""Parser for 'show controller ethernet-controller' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ControllerEthernetStatRow(TypedDict):
    """One transmit/receive statistics row."""

    transmit_value: str
    transmit_label: str
    receive_value: str
    receive_label: str


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


def _parse_stat_row(line: str) -> ControllerEthernetStatRow | None:
    parts = re.split(r"\s{2,}", line.strip())
    if len(parts) < 4:
        return None
    if not parts[0].isdigit() or not parts[2].isdigit():
        return None
    return ControllerEthernetStatRow(
        transmit_value=parts[0],
        transmit_label=parts[1],
        receive_value=parts[2],
        receive_label=parts[3],
    )


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
