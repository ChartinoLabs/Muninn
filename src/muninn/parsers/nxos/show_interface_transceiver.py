"""Parser for 'show interface transceiver' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class TransceiverEntry(TypedDict):
    """Schema for a single interface transceiver entry."""

    sfp: str
    temperature_c: NotRequired[float]
    voltage_v: NotRequired[float]
    current_ma: NotRequired[float]
    tx_power_dbm: NotRequired[float]
    rx_power_dbm: NotRequired[float]


class ShowInterfaceTransceiverResult(TypedDict):
    """Schema for 'show interface transceiver' parsed output."""

    interfaces: dict[str, TransceiverEntry]


# Matches the header lines and separator
_HEADER_PATTERN = re.compile(r"^\s*(?:Port|---|\()", re.IGNORECASE)

# Matches transceiver data rows:
# Eth1/1   QSFP-40G-SR-BD   35.00   3.28   6.84   -2.48   -2.20
_ROW_PATTERN = re.compile(
    r"^(?P<port>(?:Eth|Ethernet)\S+)\s+"
    r"(?P<sfp>\S+)\s+"
    r"(?P<temp>\S+)\s+"
    r"(?P<voltage>\S+)\s+"
    r"(?P<current>\S+)\s+"
    r"(?P<tx_power>\S+)\s+"
    r"(?P<rx_power>\S+)"
)

# Values that should be omitted from output
_SKIP_VALUES = {"N/A", "--", "n/a"}

# Maps regex group names to TransceiverEntry keys
_FIELD_MAP: list[tuple[str, str]] = [
    ("temp", "temperature_c"),
    ("voltage", "voltage_v"),
    ("current", "current_ma"),
    ("tx_power", "tx_power_dbm"),
    ("rx_power", "rx_power_dbm"),
]


def _parse_float(value: str) -> float | None:
    """Parse a string to float, returning None for N/A or -- values.

    Args:
        value: Raw string value from CLI output.

    Returns:
        Parsed float or None if value should be omitted.
    """
    if value in _SKIP_VALUES:
        return None
    try:
        return float(value)
    except ValueError:
        return None


@register(OS.CISCO_NXOS, "show interface transceiver")
class ShowInterfaceTransceiverParser(
    BaseParser[ShowInterfaceTransceiverResult],
):
    """Parser for 'show interface transceiver' on NX-OS.

    Parses the transceiver summary table including SFP type,
    temperature, voltage, current, Tx power, and Rx power
    per interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceTransceiverResult:
        """Parse 'show interface transceiver' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed transceiver data keyed by canonical interface name.

        Raises:
            ValueError: If no transceiver entries found.
        """
        interfaces: dict[str, TransceiverEntry] = {}

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped or _HEADER_PATTERN.match(stripped):
                continue

            match = _ROW_PATTERN.match(stripped)
            if not match:
                continue

            port = canonical_interface_name(match.group("port"), os=OS.CISCO_NXOS)
            sfp = match.group("sfp")

            # Skip rows where the SFP field indicates no transceiver
            if sfp in _SKIP_VALUES:
                continue

            entry: TransceiverEntry = {"sfp": sfp}

            for group_name, key in _FIELD_MAP:
                val = _parse_float(match.group(group_name))
                if val is not None:
                    entry[key] = val  # type: ignore[literal-required]

            interfaces[port] = entry

        if not interfaces:
            msg = "No transceiver entries found in output"
            raise ValueError(msg)

        return ShowInterfaceTransceiverResult(interfaces=interfaces)
