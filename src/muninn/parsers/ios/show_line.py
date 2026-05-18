"""Parser for 'show line' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

_HEADER_RE = re.compile(
    r"^\s*Tty\s+Typ\s+Tx/Rx\s+A\s+Modem\s+Roty\s+AccO\s+AccI\s+"
    r"Uses\s+Noise\s+Overruns\s+Int\s*$"
)

# Row layout (columns are space-padded and some fields can be ``-``):
#   [*] <tty> <typ> [<tx/rx>] <a> <modem> <roty> <acco> <acci>
#       <uses> <noise> <hw>/<sw> <int>
# The Tx/Rx column may be blank (no token at all) when the line type does
# not have a configured speed (CTY, VTY, etc.). When present, it appears as
# ``<tx>/<rx>``.
_ROW_RE = re.compile(
    r"^(?P<active>\*)?\s*"
    r"(?P<tty>\d+)\s+"
    r"(?P<typ>\S+)\s+"
    r"(?:(?P<tx_rx>\d+/\d+)\s+)?"
    r"(?P<autobaud>\S+)\s+"
    r"(?P<modem>\S+)\s+"
    r"(?P<roty>\S+)\s+"
    r"(?P<acco>\S+)\s+"
    r"(?P<acci>\S+)\s+"
    r"(?P<uses>\d+)\s+"
    r"(?P<noise>\d+)\s+"
    r"(?P<hw_overruns>\d+)/(?P<sw_overruns>\d+)\s+"
    r"(?P<interface>\S+)\s*$"
)

_PLACEHOLDER = "-"


def _omit_placeholder(value: str) -> str | None:
    """Return ``value`` unchanged, or ``None`` if it is the ``-`` placeholder."""
    return None if value == _PLACEHOLDER else value


class LineEntry(TypedDict):
    """Schema for a single line entry from 'show line'."""

    tty: int
    type: str
    active: bool
    uses: int
    noise: int
    hardware_overruns: int
    software_overruns: int
    tx_speed: NotRequired[int]
    rx_speed: NotRequired[int]
    autobaud: NotRequired[str]
    modem: NotRequired[str]
    rotary: NotRequired[str]
    access_class_out: NotRequired[str]
    access_class_in: NotRequired[str]
    interface: NotRequired[str]


class ShowLineResult(TypedDict):
    """Schema for 'show line' parsed output."""

    lines: dict[str, LineEntry]


def _build_entry(match: re.Match[str]) -> tuple[str, LineEntry]:
    """Assemble a (tty, entry) tuple from a row match."""
    tty = match.group("tty")
    entry: LineEntry = {
        "tty": int(tty),
        "type": match.group("typ"),
        "active": match.group("active") == "*",
        "uses": int(match.group("uses")),
        "noise": int(match.group("noise")),
        "hardware_overruns": int(match.group("hw_overruns")),
        "software_overruns": int(match.group("sw_overruns")),
    }

    tx_rx = match.group("tx_rx")
    if tx_rx is not None:
        tx_speed, rx_speed = tx_rx.split("/", 1)
        entry["tx_speed"] = int(tx_speed)
        entry["rx_speed"] = int(rx_speed)

    if (autobaud := _omit_placeholder(match.group("autobaud"))) is not None:
        entry["autobaud"] = autobaud
    if (modem := _omit_placeholder(match.group("modem"))) is not None:
        entry["modem"] = modem
    if (rotary := _omit_placeholder(match.group("roty"))) is not None:
        entry["rotary"] = rotary
    if (acco := _omit_placeholder(match.group("acco"))) is not None:
        entry["access_class_out"] = acco
    if (acci := _omit_placeholder(match.group("acci"))) is not None:
        entry["access_class_in"] = acci
    if (interface := _omit_placeholder(match.group("interface"))) is not None:
        entry["interface"] = canonical_interface_name(interface, os=OS.CISCO_IOS)

    return tty, entry


@register(OS.CISCO_IOS, "show line")
class ShowLineParser(BaseParser[ShowLineResult]):
    """Parser for 'show line' on IOS.

    Parses the terminal line summary table showing TTY number, line type,
    Tx/Rx speed, modem/rotary/access-class settings, usage counters, and
    associated interface for each terminal line (CTY, VTY, AUX, TTY, ...).

    The ``*`` prefix in the leftmost column indicates an active session on
    that line and is exposed as ``active`` on the entry.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.SYSTEM})

    @classmethod
    def parse(cls, output: str) -> ShowLineResult:
        """Parse 'show line' output.

        Args:
            output: Raw CLI output from 'show line'.

        Returns:
            Line entries keyed by TTY number (as a string).

        Raises:
            ValueError: If no line entries are found in the output.
        """
        lines: dict[str, LineEntry] = {}

        for raw_line in output.splitlines():
            if not raw_line.strip() or _HEADER_RE.match(raw_line):
                continue

            match = _ROW_RE.match(raw_line)
            if match is None:
                continue

            tty, entry = _build_entry(match)
            lines[tty] = entry

        if not lines:
            msg = "No line entries found in 'show line' output"
            raise ValueError(msg)

        return {"lines": lines}
