"""Parser for 'show interfaces transceiver' command on Arista EOS."""

import re
from typing import Any, ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class TransceiverEntry(TypedDict):
    """Schema for a single interface transceiver entry."""

    temperature_c: NotRequired[float]
    voltage_v: NotRequired[float]
    current_ma: NotRequired[float]
    tx_power_dbm: NotRequired[float]
    rx_power_dbm: NotRequired[float]
    last_update: NotRequired[str]


class ShowInterfacesTransceiverResult(TypedDict):
    """Schema for 'show interfaces transceiver' parsed output on Arista EOS."""

    interfaces: dict[str, TransceiverEntry]


# Values that indicate no data is available and should be omitted.
_SKIP_VALUES = frozenset({"N/A", "n/a", "--"})

# Matches transceiver data rows. Arista EOS uses abbreviated interface names
# like "Et3/1/1", "Et3/17/1", "Ma1", etc.
#
# Example rows:
#   Et3/1/1    27.92      3.23      19.94     N/A      -2.39     0:00:06 ago
#   Et3/17/1   35.61      3.21      36.64    1.51      -0.10     0:00:03 ago
#   Et5/29/1   N/A        N/A       N/A       N/A       N/A      N/A
_ROW_PATTERN = re.compile(
    r"^(?P<port>[A-Za-z]+[\d/]+)\s+"
    r"(?P<temp>\S+)\s+"
    r"(?P<voltage>\S+)\s+"
    r"(?P<current>\S+)\s+"
    r"(?P<tx_power>\S+)\s+"
    r"(?P<rx_power>\S+)\s+"
    r"(?P<last_update>.+)$"
)

# Maps regex group names to TransceiverEntry keys.
_FIELD_MAP: list[tuple[str, str]] = [
    ("temp", "temperature_c"),
    ("voltage", "voltage_v"),
    ("current", "current_ma"),
    ("tx_power", "tx_power_dbm"),
    ("rx_power", "rx_power_dbm"),
]


def _parse_float(value: str) -> float | None:
    """Parse a string to float, returning None for N/A or skip values.

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


@register(OS.ARISTA_EOS, "show interfaces transceiver")
class ShowInterfacesTransceiverParser(
    BaseParser[ShowInterfacesTransceiverResult],
):
    """Parser for 'show interfaces transceiver' on Arista EOS.

    Parses the transceiver summary table including temperature, voltage,
    bias current, Tx power (dBm), and Rx power (dBm) per interface.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesTransceiverResult:
        """Parse 'show interfaces transceiver' output on Arista EOS.

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
            if not stripped:
                continue

            match = _ROW_PATTERN.match(stripped)
            if not match:
                continue

            port = canonical_interface_name(match.group("port"), os=OS.ARISTA_EOS)

            entry: TransceiverEntry = {}
            _d = cast(dict[str, Any], entry)

            for group_name, key in _FIELD_MAP:
                val = _parse_float(match.group(group_name))
                if val is not None:
                    _d[key] = val

            last_update = match.group("last_update").strip()
            if last_update not in _SKIP_VALUES:
                _d["last_update"] = last_update

            if not entry:
                continue

            interfaces[port] = entry

        if not interfaces:
            msg = "No transceiver entries found in output"
            raise ValueError(msg)

        return ShowInterfacesTransceiverResult(interfaces=interfaces)
