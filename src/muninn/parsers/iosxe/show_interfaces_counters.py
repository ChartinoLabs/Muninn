"""Parser for 'show interfaces counters' command on IOS-XE."""

import re
from typing import ClassVar, Literal, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Section header for the input-counters block.
_IN_HEADER_RE = re.compile(
    r"^\s*Port\s+InOctets\s+InUcastPkts\s+InMcastPkts\s+InBcastPkts\s*$"
)

# Section header for the output-counters block.
_OUT_HEADER_RE = re.compile(
    r"^\s*Port\s+OutOctets\s+OutUcastPkts\s+OutMcastPkts\s+OutBcastPkts\s*$"
)

# Data row: port token followed by four non-negative integer counters.
# Port tokens look like ``Gi1/0/1``, ``Te1/1/2``, ``Ap1/0/1``, ``Po1``,
# ``Fa0/1``, ``Twe1/0/1``, etc.
_DATA_ROW_RE = re.compile(
    r"^(?P<port>[A-Za-z][A-Za-z]*\d[\w/.:-]*)"
    r"\s+(?P<octets>\d+)"
    r"\s+(?P<ucast>\d+)"
    r"\s+(?P<mcast>\d+)"
    r"\s+(?P<bcast>\d+)\s*$"
)


class DirectionCounters(TypedDict):
    """Counters for a single direction (input or output) on an interface."""

    octets: int
    ucast_pkts: int
    mcast_pkts: int
    bcast_pkts: int


class InterfaceCounters(TypedDict):
    """Per-interface counters with optional input and output sections.

    Both ``input`` and ``output`` are :class:`NotRequired` so the schema
    remains valid if a device emits only one of the two columnar blocks
    (for example, the trailing block is truncated by paging or only one
    section is present in a vendor-modified variant of the command).
    The standard ``show interfaces counters`` invocation always emits
    both blocks.
    """

    input: NotRequired[DirectionCounters]
    output: NotRequired[DirectionCounters]


class ShowInterfacesCountersResult(TypedDict):
    """Schema for 'show interfaces counters' parsed output on IOS-XE."""

    interfaces: dict[str, InterfaceCounters]


def _parse_data_row(line: str) -> tuple[str, DirectionCounters] | None:
    """Return ``(canonical_port, counters)`` if ``line`` is a data row.

    Returns ``None`` when the line does not match the expected columnar
    format (blank lines, header rows, footers, etc.).
    """
    match = _DATA_ROW_RE.match(line)
    if match is None:
        return None
    port = canonical_interface_name(match.group("port"), os=OS.CISCO_IOSXE)
    counters: DirectionCounters = {
        "octets": int(match.group("octets")),
        "ucast_pkts": int(match.group("ucast")),
        "mcast_pkts": int(match.group("mcast")),
        "bcast_pkts": int(match.group("bcast")),
    }
    return port, counters


@register(OS.CISCO_IOSXE, "show interfaces counters")
class ShowInterfacesCountersParser(BaseParser[ShowInterfacesCountersResult]):
    """Parser for 'show interfaces counters' on IOS-XE.

    The command emits two columnar blocks: an input-counters block keyed
    by ``InOctets``/``InUcastPkts``/``InMcastPkts``/``InBcastPkts`` and an
    output-counters block keyed by their ``Out*`` equivalents. Each row
    contains a port token followed by the four counters.

    The parser returns a mapping keyed by canonical interface name. Each
    entry carries an ``input`` and an ``output`` sub-dict. Both are
    marked :class:`NotRequired` to keep the schema valid when only one
    of the two columnar blocks is present in the supplied output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesCountersResult:
        """Parse 'show interfaces counters' output.

        Args:
            output: Raw CLI output from the
                ``show interfaces counters`` command.

        Returns:
            Parsed counter data keyed by canonical interface name.

        Raises:
            ValueError: If no interface rows are present in the output.
        """
        interfaces: dict[str, InterfaceCounters] = {}
        direction: Literal["input", "output"] | None = None

        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            if _IN_HEADER_RE.match(line):
                direction = "input"
                continue
            if _OUT_HEADER_RE.match(line):
                direction = "output"
                continue
            if direction is None:
                # Data rows before any recognised header are ignored.
                continue
            parsed = _parse_data_row(stripped)
            if parsed is None:
                continue
            port, counters = parsed
            entry = interfaces.setdefault(port, {})
            entry[direction] = counters

        if not interfaces:
            msg = "No interfaces found in 'show interfaces counters' output"
            raise ValueError(msg)

        return {"interfaces": interfaces}
