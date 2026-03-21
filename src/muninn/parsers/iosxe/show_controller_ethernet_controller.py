"""Parser for 'show controller ethernet-controller' command on IOS-XE."""

import re
from typing import ClassVar, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class ControllerEthernetCounterEntry(TypedDict):
    """Numeric counter under a label key."""

    value: str


class ControllerEthernetStatistics(TypedDict):
    """Per-column counters keyed by CLI label.

    Labels are unique keys; if the device repeats a label in the same column,
    later keys are suffixed `` (2)``, `` (3)``, …
    """

    transmit: dict[str, ControllerEthernetCounterEntry]
    receive: dict[str, ControllerEthernetCounterEntry]


class ShowControllerEthernetControllerResult(TypedDict):
    """Schema for 'show controller ethernet-controller' parsed output."""

    interface: str
    statistics: ControllerEthernetStatistics
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


def _unique_label_key(d: dict[str, ControllerEthernetCounterEntry], label: str) -> str:
    """Return a key not already present in ``d`` (suffix duplicate labels)."""
    if label not in d:
        return label
    n = 2
    while f"{label} ({n})" in d:
        n += 1
    return f"{label} ({n})"


def _parse_controller_ethernet(output: str) -> ShowControllerEthernetControllerResult:
    lines = output.splitlines()
    interface = ""
    transmit: dict[str, ControllerEthernetCounterEntry] = {}
    receive: dict[str, ControllerEthernetCounterEntry] = {}
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
        m = _STAT_ROW_FULL_RE.match(s)
        if m:
            tx_label = m.group(2).strip()
            rx_label = m.group(4).strip()
            tx_key = _unique_label_key(transmit, tx_label)
            rx_key = _unique_label_key(receive, rx_label)
            transmit[tx_key] = ControllerEthernetCounterEntry(value=m.group(1))
            receive[rx_key] = ControllerEthernetCounterEntry(value=m.group(3))
            continue
        m = _STAT_ROW_TX_ONLY_RE.match(s)
        if m:
            tx_label = m.group(2).strip()
            tx_key = _unique_label_key(transmit, tx_label)
            transmit[tx_key] = ControllerEthernetCounterEntry(value=m.group(1))
            continue
    if not interface:
        msg = "Ethernet controller interface not found"
        raise ValueError(msg)
    return ShowControllerEthernetControllerResult(
        interface=interface,
        statistics=ControllerEthernetStatistics(transmit=transmit, receive=receive),
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
