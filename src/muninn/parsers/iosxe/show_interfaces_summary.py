"""Parser for 'show interfaces summary' command on Cisco IOS-XE."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name

# Matches an interface data row.  The leading '*' indicates the interface
# is up; absence means the interface is down or administratively down.
# Fields are positional: interface, IHQ, IQD, OHQ, OQD, RXBS, RXPS,
# TXBS, TXPS, TRTL.  Values may be integers or '-' (placeholder).
_DATA_ROW_RE = re.compile(
    r"^(?P<up>[*\s])\s*"
    r"(?P<interface>\S+)"
    r"\s+(?P<ihq>\d+|-)"
    r"\s+(?P<iqd>\d+|-)"
    r"\s+(?P<ohq>\d+|-)"
    r"\s+(?P<oqd>\d+|-)"
    r"\s+(?P<rxbs>\d+|-)"
    r"\s+(?P<rxps>\d+|-)"
    r"\s+(?P<txbs>\d+|-)"
    r"\s+(?P<txps>\d+|-)"
    r"\s+(?P<trtl>\d+|-)\s*$"
)

# Matches the column header line to detect the start of the data section.
_HEADER_RE = re.compile(
    r"^\s*Interface\s+IHQ\s+IQD\s+OHQ\s+OQD\s+RXBS\s+"
    r"RXPS\s+TXBS\s+TXPS\s+TRTL\s*$"
)


class InterfaceSummaryEntry(TypedDict):
    """Per-interface queue and rate statistics.

    All numeric fields are :class:`NotRequired` because sub-interfaces
    often report ``-`` (no data available) for every counter.
    """

    is_up: bool
    ihq: NotRequired[int]
    iqd: NotRequired[int]
    ohq: NotRequired[int]
    oqd: NotRequired[int]
    rx_rate_bps: NotRequired[int]
    rx_rate_pps: NotRequired[int]
    tx_rate_bps: NotRequired[int]
    tx_rate_pps: NotRequired[int]
    throttle_count: NotRequired[int]


class ShowInterfacesSummaryResult(TypedDict):
    """Schema for 'show interfaces summary' parsed output on IOS-XE.

    Keyed by canonical interface name.
    """

    interfaces: dict[str, InterfaceSummaryEntry]


@register(OS.CISCO_IOSXE, "show interfaces summary")
class ShowInterfacesSummaryParser(BaseParser[ShowInterfacesSummaryResult]):
    """Parser for 'show interfaces summary' on Cisco IOS-XE.

    The command emits a tabular listing of all interfaces with their
    input/output hold-queue depths, drop counts, rates, and throttle
    counts.  Interfaces marked with a leading ``*`` are operationally up.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesSummaryResult:
        """Parse 'show interfaces summary' output on IOS-XE.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed interface summary keyed by canonical interface name.

        Raises:
            ValueError: If no interface data rows are found.
        """
        interfaces: dict[str, InterfaceSummaryEntry] = {}
        in_data_section = False

        for line in output.splitlines():
            stripped = line.rstrip()
            if not stripped:
                continue

            # Detect the header row to know we are in the data section.
            if _HEADER_RE.match(stripped):
                in_data_section = True
                continue

            # Skip separator lines (dashes).
            if SEPARATOR_DASH_SPACE_RE.match(stripped):
                continue

            if not in_data_section:
                continue

            match = _DATA_ROW_RE.match(stripped)
            if match is None:
                continue

            _build_entry(match, interfaces)

        if not interfaces:
            msg = "No interfaces found in 'show interfaces summary' output"
            raise ValueError(msg)

        return cast(ShowInterfacesSummaryResult, {"interfaces": interfaces})


def _build_entry(
    match: re.Match[str],
    interfaces: dict[str, InterfaceSummaryEntry],
) -> None:
    """Build and store a single interface entry from a regex match."""
    is_up = match.group("up") == "*"
    name = canonical_interface_name(match.group("interface"), os=OS.CISCO_IOSXE)

    entry: dict[str, object] = {"is_up": is_up}

    _set_int_field(entry, "ihq", match.group("ihq"))
    _set_int_field(entry, "iqd", match.group("iqd"))
    _set_int_field(entry, "ohq", match.group("ohq"))
    _set_int_field(entry, "oqd", match.group("oqd"))
    _set_int_field(entry, "rx_rate_bps", match.group("rxbs"))
    _set_int_field(entry, "rx_rate_pps", match.group("rxps"))
    _set_int_field(entry, "tx_rate_bps", match.group("txbs"))
    _set_int_field(entry, "tx_rate_pps", match.group("txps"))
    _set_int_field(entry, "throttle_count", match.group("trtl"))

    interfaces[name] = cast(InterfaceSummaryEntry, entry)


def _set_int_field(entry: dict[str, object], key: str, raw: str) -> None:
    """Set an integer field on the entry dict, omitting placeholders."""
    if raw != "-":
        entry[key] = int(raw)
