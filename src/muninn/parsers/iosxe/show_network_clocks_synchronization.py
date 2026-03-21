"""Parser for 'show network-clocks synchronization' command on IOS-XE."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class NetworkClockInterfaceRow(TypedDict):
    """One row in the nominated interfaces table."""

    interface: str
    selected: bool
    sig_type: str
    mode_ql: str
    prio: int
    ql_in: str
    esmc_tx: NotRequired[str]
    esmc_rx: NotRequired[str]


class ShowNetworkClocksSynchronizationResult(TypedDict):
    """Schema for 'show network-clocks synchronization' parsed output."""

    settings: dict[str, str]
    interfaces: dict[str, NetworkClockInterfaceRow]


_ROW_RE = re.compile(
    r"^\s*(?P<mark>\*)?(?P<if>\S+)\s+(?P<sig>\S+)\s+(?P<mode>\S+)\s+"
    r"(?P<prio>\d+)\s+(?P<ql>\S+)\s+(?P<tx>\S+)\s+(?P<rx>\S+)\s*$"
)


def _parse_ncs_kv_line(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    k, v = line.split(":", 1)
    k = k.strip()
    v = v.strip()
    if not k:
        return None
    return k, v


def _parse_interface_row(line: str) -> NetworkClockInterfaceRow | None:
    m = _ROW_RE.match(line.rstrip())
    if not m:
        return None
    raw_if = m.group("if")
    tx = m.group("tx")
    rx = m.group("rx")
    row: NetworkClockInterfaceRow = {
        "interface": canonical_interface_name(raw_if, os=OS.CISCO_IOSXE),
        "selected": bool(m.group("mark")),
        "sig_type": m.group("sig"),
        "mode_ql": m.group("mode"),
        "prio": int(m.group("prio")),
        "ql_in": m.group("ql"),
    }
    if tx != "-":
        row["esmc_tx"] = tx
    if rx != "-":
        row["esmc_rx"] = rx
    return row


class _NcsAccum:
    """Accumulator for network-clocks synchronization parse."""

    __slots__ = ("settings", "interfaces", "in_table")

    def __init__(self) -> None:
        self.settings: dict[str, str] = {}
        self.interfaces: dict[str, NetworkClockInterfaceRow] = {}
        self.in_table = False

    def feed(self, line: str) -> None:
        s = line.rstrip()
        if not s.strip():
            return
        if s.strip() == "Nominated Interfaces":
            self.in_table = True
            return
        if self._consume_table(s):
            return
        pair = _parse_ncs_kv_line(s)
        if pair and pair[1] != "-":
            self.settings[pair[0]] = pair[1]

    def _consume_table(self, s: str) -> bool:
        if not self.in_table:
            return False
        if "Interface" in s and "SigType" in s:
            return True
        if set(s.strip()) <= {"-"}:
            return True
        row = _parse_interface_row(s)
        if row:
            self.interfaces[row["interface"]] = row
        return True


def _parse_network_clocks_synchronization(
    output: str,
) -> ShowNetworkClocksSynchronizationResult:
    acc = _NcsAccum()
    for line in output.splitlines():
        acc.feed(line)
    if not acc.settings and not acc.interfaces:
        msg = "No network-clocks synchronization data parsed"
        raise ValueError(msg)
    return cast(
        ShowNetworkClocksSynchronizationResult,
        {"settings": acc.settings, "interfaces": acc.interfaces},
    )


@register(OS.CISCO_IOSXE, "show network-clocks synchronization")
class ShowNetworkClocksSynchronizationParser(
    BaseParser[ShowNetworkClocksSynchronizationResult]
):
    """Parser for 'show network-clocks synchronization' command."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowNetworkClocksSynchronizationResult:
        """Parse 'show network-clocks synchronization' output."""
        return _parse_network_clocks_synchronization(output)
