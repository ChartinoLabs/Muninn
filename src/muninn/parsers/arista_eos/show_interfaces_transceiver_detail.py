"""Parser for 'show interfaces transceiver detail' command on Arista EOS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ThresholdInfo(TypedDict):
    """Schema for alarm and warning thresholds."""

    high_alarm: float
    high_warning: float
    low_alarm: float
    low_warning: float


class TransceiverEntry(TypedDict):
    """Schema for a single transceiver interface entry."""

    temperature_celsius: NotRequired[float]
    temperature_thresholds: NotRequired[ThresholdInfo]
    voltage_volts: NotRequired[float]
    voltage_thresholds: NotRequired[ThresholdInfo]
    current_ma: NotRequired[float]
    current_thresholds: NotRequired[ThresholdInfo]
    tx_power_dbm: NotRequired[float]
    tx_power_thresholds: NotRequired[ThresholdInfo]
    rx_power_dbm: NotRequired[float]
    rx_power_thresholds: NotRequired[ThresholdInfo]


class ShowInterfacesTransceiverDetailResult(TypedDict):
    """Schema for 'show interfaces transceiver detail' parsed output."""

    interfaces: dict[str, TransceiverEntry]


# Section names as they appear in the CLI output, mapped to field prefixes.
_SECTION_MAP: dict[str, tuple[str, str]] = {
    "Temperature": ("temperature_celsius", "temperature_thresholds"),
    "Voltage": ("voltage_volts", "voltage_thresholds"),
    "Current": ("current_ma", "current_thresholds"),
    "Tx Power": ("tx_power_dbm", "tx_power_thresholds"),
    "Rx Power": ("rx_power_dbm", "rx_power_thresholds"),
}


@register(OS.ARISTA_EOS, "show interfaces transceiver detail")
class ShowInterfacesTransceiverDetailParser(
    BaseParser[ShowInterfacesTransceiverDetailResult],
):
    """Parser for 'show interfaces transceiver detail' command on Arista EOS.

    Parses per-lane transceiver diagnostics including temperature, voltage,
    bias current, TX/RX optical power, and their alarm/warning thresholds.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Detects the measurement label line that identifies each section.
    # Examples: "           Temperature   Threshold   ..."
    #           "           Voltage       Threshold   ..."
    #           "           Tx Power      Threshold   ..."
    _SECTION_PATTERN = re.compile(
        r"^\s+(?P<section>Temperature|Voltage|Current|Tx Power|Rx Power)\s+",
    )

    # Data row: port, value, high_alarm, high_warn, low_alarm, low_warn
    # Optional alarm/warning indicators (++, +, -, --) may follow values.
    _DATA_PATTERN = re.compile(
        r"^(?P<port>(?:Et|Ma)\S+)\s+"
        r"(?P<value>-?[\d.]+)\s*(?:[+\-]{0,2})\s+"
        r"(?P<high_alarm>-?[\d.]+)\s+"
        r"(?P<high_warn>-?[\d.]+)\s+"
        r"(?P<low_alarm>-?[\d.]+)\s+"
        r"(?P<low_warn>-?[\d.]+)",
    )

    # Separator line of dashes
    _SEPARATOR_PATTERN = re.compile(r"^-{3,}")

    @classmethod
    def _parse_data_row(
        cls,
        line: str,
        section_value_key: str,
        section_threshold_key: str,
        interfaces: dict[str, dict[str, object]],
    ) -> None:
        """Parse a single data row and merge into the interfaces dict."""
        match = cls._DATA_PATTERN.match(line)
        if not match:
            return

        port = canonical_interface_name(match.group("port"), os=OS.ARISTA_EOS)

        if port not in interfaces:
            interfaces[port] = {}

        entry = interfaces[port]
        entry[section_value_key] = float(match.group("value"))
        entry[section_threshold_key] = ThresholdInfo(
            high_alarm=float(match.group("high_alarm")),
            high_warning=float(match.group("high_warn")),
            low_alarm=float(match.group("low_alarm")),
            low_warning=float(match.group("low_warn")),
        )

    @classmethod
    def parse(cls, output: str) -> ShowInterfacesTransceiverDetailResult:
        """Parse 'show interfaces transceiver detail' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed transceiver detail data keyed by interface name.

        Raises:
            ValueError: If no transceiver data found in output.
        """
        interfaces: dict[str, dict[str, object]] = {}
        current_section: tuple[str, str] | None = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Detect section header
            section_match = cls._SECTION_PATTERN.match(line)
            if section_match:
                section_name = section_match.group("section")
                current_section = _SECTION_MAP.get(section_name)
                continue

            # Skip separator and header lines
            if cls._SEPARATOR_PATTERN.match(stripped) or stripped.startswith("Port"):
                continue

            # Parse data rows when inside a section
            if current_section:
                cls._parse_data_row(
                    stripped,
                    current_section[0],
                    current_section[1],
                    interfaces,
                )

        if not interfaces:
            msg = "No transceiver data found in output"
            raise ValueError(msg)

        return ShowInterfacesTransceiverDetailResult(
            interfaces={k: cast(TransceiverEntry, v) for k, v in interfaces.items()},
        )
