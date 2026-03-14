"""Parser for 'show interface transceiver details' command on NX-OS."""

import re
from dataclasses import dataclass, field
from typing import NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.utils import canonical_interface_name


class DiagnosticReading(TypedDict):
    """Schema for a single diagnostic measurement with thresholds."""

    current: float
    alarm_high: NotRequired[float]
    alarm_low: NotRequired[float]
    warning_high: NotRequired[float]
    warning_low: NotRequired[float]


class TransceiverDetailEntry(TypedDict):
    """Schema for a single interface transceiver detail entry."""

    type: str
    name: str
    part_number: str
    revision: str
    serial_number: str
    nominal_bitrate_mbps: NotRequired[int]
    link_lengths: NotRequired[dict[str, str]]
    cisco_id: NotRequired[str]
    cisco_extended_id: NotRequired[str]
    cisco_part_number: NotRequired[str]
    cisco_product_id: NotRequired[str]
    cisco_version_id: NotRequired[str]
    calibration: NotRequired[str]
    temperature: NotRequired[DiagnosticReading]
    voltage: NotRequired[DiagnosticReading]
    current: NotRequired[DiagnosticReading]
    tx_power: NotRequired[DiagnosticReading]
    rx_power: NotRequired[DiagnosticReading]
    transmit_fault_count: NotRequired[int]


class ShowInterfaceTransceiverDetailsResult(TypedDict):
    """Schema for 'show interface transceiver details' parsed output."""

    interfaces: dict[str, TransceiverDetailEntry]


# Pattern to match interface header lines like "Ethernet1/1" or "Eth1/17"
_INTERFACE_PATTERN = re.compile(
    r"^(?P<intf>(?:Eth(?:ernet)?|mgmt)\S+)\s*$",
    re.IGNORECASE,
)

# Pattern matching "transceiver is present" or "sfp is present"
_PRESENCE_PATTERN = re.compile(
    r"^\s*(?:transceiver|sfp)\s+is\s+(?P<status>present|not\s+present)",
    re.IGNORECASE,
)

# Key-value patterns for transceiver identification fields
_KV_PATTERN = re.compile(r"^\s*(?P<key>[a-z][a-z _]+[a-z])\s+is\s+(?P<value>.+)$")

# Diagnostic table row: field, current, alarm_high, alarm_low, warn_high, warn_low
# Example: Temperature   34.41 C    90.00 C    -45.00 C    85.00 C    -40.00 C
_DIAG_ROW_PATTERN = re.compile(
    r"^\s*(?P<field>Temperature|Voltage|Current|Tx Power|Rx Power)\s+"
    r"(?P<current>-?[\d.]+)\s+\S+\s+"
    r"(?P<alarm_high>-?[\d.]+)\s+\S+\s+"
    r"(?P<alarm_low>-?[\d.]+)\s+\S+\s+"
    r"(?P<warn_high>-?[\d.]+)\s+\S+\s+"
    r"(?P<warn_low>-?[\d.]+)\s+\S+",
)

# Transmit Fault Count = 0
_TX_FAULT_PATTERN = re.compile(
    r"^\s*Transmit Fault Count\s*=\s*(?P<count>\d+)",
)

# Calibration header: "SFP Detail Diagnostics Information (internal calibration)"
_CALIBRATION_PATTERN = re.compile(
    r"Detail Diagnostics Information\s+\((?P<cal>[^)]+)\)",
)

# Maps raw key strings to TransceiverDetailEntry field names
_IDENTIFICATION_KEY_MAP: dict[str, str] = {
    "type": "type",
    "name": "name",
    "part number": "part_number",
    "revision": "revision",
    "serial number": "serial_number",
    "nominal bitrate": "nominal_bitrate_mbps",
    "cisco id": "cisco_id",
    "cisco extended id number": "cisco_extended_id",
    "cisco part number": "cisco_part_number",
    "cisco product id": "cisco_product_id",
    "cisco version id": "cisco_version_id",
}

# Maps diagnostic field labels to entry keys
_DIAG_FIELD_MAP: dict[str, str] = {
    "Temperature": "temperature",
    "Voltage": "voltage",
    "Current": "current",
    "Tx Power": "tx_power",
    "Rx Power": "rx_power",
}

# Pattern for link length lines:
# "Link length supported for 9/125um fiber is 40 km"
# "Link length supported for 50/125um OM3 fiber is 100 m(s)"
_LINK_LENGTH_PATTERN = re.compile(
    r"^\s*Link length supported for\s+(?P<fiber>.+?)\s+is\s+(?P<distance>.+)$",
)

# Pattern to extract numeric bitrate value:
# "10300 MBits/sec" or "1300 MBit/sec"
_BITRATE_VALUE_PATTERN = re.compile(r"^(\d+)")


def _parse_bitrate(raw: str) -> int | None:
    """Extract integer bitrate in Mbps from a raw string.

    Args:
        raw: Value like "10300 MBits/sec".

    Returns:
        Integer bitrate or None if unparseable.
    """
    match = _BITRATE_VALUE_PATTERN.match(raw.strip())
    if match:
        return int(match.group(1))
    return None


def _build_diagnostic_reading(
    match: re.Match[str],
) -> DiagnosticReading:
    """Build a DiagnosticReading from a regex match.

    Args:
        match: Match with groups: current, alarm_high, alarm_low,
               warn_high, warn_low.

    Returns:
        Populated DiagnosticReading dict.
    """
    return DiagnosticReading(
        current=float(match.group("current")),
        alarm_high=float(match.group("alarm_high")),
        alarm_low=float(match.group("alarm_low")),
        warning_high=float(match.group("warn_high")),
        warning_low=float(match.group("warn_low")),
    )


@dataclass
class _ParseState:
    """Mutable state for the transceiver detail parser."""

    interfaces: dict[str, TransceiverDetailEntry] = field(
        default_factory=dict,
    )
    current_intf: str | None = None
    current_entry: TransceiverDetailEntry | None = None

    def save_current(self) -> None:
        """Save the current entry into interfaces if valid."""
        if self.current_intf and self.current_entry:
            self.interfaces[self.current_intf] = self.current_entry

    def start_interface(self, name: str) -> None:
        """Begin tracking a new interface, saving any previous entry."""
        self.save_current()
        self.current_intf = name
        self.current_entry = None

    def clear_interface(self) -> None:
        """Clear the current interface without saving (not present)."""
        self.current_intf = None
        self.current_entry = None


def _handle_interface_header(
    stripped: str,
    state: _ParseState,
) -> bool:
    """Check for and handle an interface header line.

    Returns True if the line was consumed.
    """
    intf_match = _INTERFACE_PATTERN.match(stripped)
    if not intf_match:
        return False
    name = canonical_interface_name(
        intf_match.group("intf"),
        os=OS.CISCO_NXOS,
    )
    state.start_interface(name)
    return True


def _handle_presence(stripped: str, state: _ParseState) -> bool:
    """Check for and handle a transceiver presence line.

    Returns True if the line was consumed.
    """
    presence_match = _PRESENCE_PATTERN.match(stripped)
    if not presence_match:
        return False
    if "not" in presence_match.group("status").lower():
        state.clear_interface()
    return True


def _handle_diagnostics(
    stripped: str,
    entry: TransceiverDetailEntry,
) -> bool:
    """Handle calibration header, diagnostic rows, and fault count.

    Returns True if the line was consumed.
    """
    cal_match = _CALIBRATION_PATTERN.search(stripped)
    if cal_match:
        entry["calibration"] = cal_match.group("cal")
        return True

    diag_match = _DIAG_ROW_PATTERN.match(stripped)
    if diag_match:
        entry_key = _DIAG_FIELD_MAP.get(diag_match.group("field"))
        if entry_key:
            reading = _build_diagnostic_reading(diag_match)
            entry[entry_key] = reading  # type: ignore[literal-required]
        return True

    tx_fault_match = _TX_FAULT_PATTERN.match(stripped)
    if tx_fault_match:
        entry["transmit_fault_count"] = int(tx_fault_match.group("count"))
        return True

    return False


def _handle_link_length(
    stripped: str,
    entry: TransceiverDetailEntry,
) -> bool:
    """Handle link length lines.

    Returns True if the line was consumed.
    """
    link_match = _LINK_LENGTH_PATTERN.match(stripped)
    if not link_match:
        return False
    if "link_lengths" not in entry:
        entry["link_lengths"] = {}
    entry["link_lengths"][link_match.group("fiber").strip()] = link_match.group(
        "distance"
    ).strip()
    return True


def _handle_identification(
    stripped: str,
    state: _ParseState,
) -> bool:
    """Handle key-value identification fields.

    Returns True if the line was consumed.
    """
    kv_match = _KV_PATTERN.match(stripped)
    if not kv_match:
        return False
    raw_key = kv_match.group("key").strip().lower()
    raw_value = kv_match.group("value").strip()
    mapped_key = _IDENTIFICATION_KEY_MAP.get(raw_key)
    if not mapped_key:
        return False

    # "type" initialises the entry
    if mapped_key == "type" and state.current_entry is None:
        state.current_entry = TransceiverDetailEntry(
            type=raw_value,
            name="",
            part_number="",
            revision="",
            serial_number="",
        )
        return True

    if state.current_entry is None:
        return True

    if mapped_key == "nominal_bitrate_mbps":
        bitrate = _parse_bitrate(raw_value)
        if bitrate is not None:
            state.current_entry["nominal_bitrate_mbps"] = bitrate
    else:
        state.current_entry[mapped_key] = raw_value  # type: ignore[literal-required]
    return True


def _process_line(stripped: str, state: _ParseState) -> None:
    """Process a single stripped line, updating parser state."""
    if _handle_interface_header(stripped, state):
        return
    if _handle_presence(stripped, state):
        return
    if not state.current_intf:
        return
    if state.current_entry is not None:
        if _handle_diagnostics(stripped, state.current_entry):
            return
        if _handle_link_length(stripped, state.current_entry):
            return
    _handle_identification(stripped, state)


@register(OS.CISCO_NXOS, "show interface transceiver details")
class ShowInterfaceTransceiverDetailsParser(
    BaseParser[ShowInterfaceTransceiverDetailsResult],
):
    """Parser for 'show interface transceiver details' on NX-OS.

    Parses per-interface transceiver identification and DOM diagnostic
    data including temperature, voltage, current, Tx power, and Rx power
    with alarm and warning thresholds.
    """

    @classmethod
    def parse(cls, output: str) -> ShowInterfaceTransceiverDetailsResult:
        """Parse 'show interface transceiver details' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed transceiver detail data keyed by canonical interface name.

        Raises:
            ValueError: If no transceiver detail entries found.
        """
        state = _ParseState()

        for line in output.splitlines():
            _process_line(line.strip(), state)

        state.save_current()

        if not state.interfaces:
            msg = "No transceiver detail entries found in output"
            raise ValueError(msg)

        return ShowInterfaceTransceiverDetailsResult(
            interfaces=state.interfaces,
        )
