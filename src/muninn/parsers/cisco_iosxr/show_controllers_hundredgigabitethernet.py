"""Parser for 'show controllers HundredGigabitEthernet' on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class LaneDomInfo(TypedDict):
    """Per-lane Digital Optical Monitoring readings."""

    tx_power_dbm: float
    tx_power_mw: float
    rx_power_dbm: float
    rx_power_mw: float
    laser_bias_ma: float


class OpticsInfo(TypedDict, total=False):
    """Optics transceiver identification."""

    vendor: str
    part_number: str
    serial_number: str
    wavelength_nm: int


class AlarmThreshold(TypedDict, total=False):
    """High/low alarm and warning thresholds for a single DOM metric."""

    alarm_high: float
    warning_high: float
    warning_low: float
    alarm_low: float


class AlarmThresholds(TypedDict, total=False):
    """Vendor alarm thresholds for DOM-monitored metrics."""

    transceiver_temp_c: AlarmThreshold
    transceiver_voltage_v: AlarmThreshold
    laser_bias_ma: AlarmThreshold
    transmit_power_mw: AlarmThreshold
    transmit_power_dbm: AlarmThreshold
    receive_power_mw: AlarmThreshold
    receive_power_dbm: AlarmThreshold


class DomInfo(TypedDict, total=False):
    """Digital Optical Monitoring summary readings."""

    transceiver_temp_c: float
    transceiver_voltage_v: float
    lanes: dict[str, LaneDomInfo]
    alarm_thresholds: AlarmThresholds
    alarms: list[str]


class FecStatistics(TypedDict, total=False):
    """Forward Error Correction counters."""

    corrected_codeword_count: int
    uncorrected_codeword_count: int


class MacAddressInfo(TypedDict, total=False):
    """MAC address information."""

    operational_address: str
    burnt_in_address: str


class OperationalValues(TypedDict, total=False):
    """Operational interface parameters."""

    speed: str
    duplex: str
    flowcontrol: str
    loopback: str
    mtu: int
    mru: int
    forward_error_correction: str


class InterfaceControllerResult(TypedDict):
    """Schema for a single HundredGigE interface controller output."""

    admin_state: str
    oper_state: str
    led_state: NotRequired[str]
    media_type: NotRequired[str]
    optics: NotRequired[OpticsInfo]
    dom: NotRequired[DomInfo]
    fec_statistics: NotRequired[FecStatistics]
    mac_address: NotRequired[MacAddressInfo]
    autonegotiation: NotRequired[bool]
    operational_values: NotRequired[OperationalValues]


ShowControllersHundredGigabitEthernetResult = dict[str, InterfaceControllerResult]


_THRESHOLD_LABEL_TO_KEY: dict[str, str] = {
    "Transceiver Temp (C)": "transceiver_temp_c",
    "Transceiver Voltage (V)": "transceiver_voltage_v",
    "Laser Bias (mA)": "laser_bias_ma",
    "Transmit Power (mW)": "transmit_power_mw",
    "Transmit Power (dBm)": "transmit_power_dbm",
    "Receive Power (mW)": "receive_power_mw",
    "Receive Power (dBm)": "receive_power_dbm",
}

_THRESHOLD_COLUMN_KEYS: tuple[str, ...] = (
    "alarm_high",
    "warning_high",
    "warning_low",
    "alarm_low",
)

_PLACEHOLDER_TOKENS: frozenset[str] = frozenset({"n/a", "N/A", "NA", "-inf", "+inf"})


@register(
    OS.CISCO_IOSXR,
    r"show controllers (?P<interface>\S+)",
)
class ShowControllersHundredGigabitEthernetParser(
    BaseParser[ShowControllersHundredGigabitEthernetResult],
):
    """Parser for 'show controllers HundredGigabitEthernet' on Cisco IOS-XR.

    Parses per-interface controller details including state, optics,
    DOM readings, MAC addresses, and operational values.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _INTF_HEADER = re.compile(r"^Operational data for interface (?P<name>\S+):")

    _ADMIN_STATE = re.compile(r"^\s+Administrative state:\s+(?P<val>.+)$")
    _OPER_STATE = re.compile(r"^\s+Operational state:\s+(?P<val>.+)$")
    _LED_STATE = re.compile(r"^\s+LED state:\s+(?P<val>.+)$")

    _MEDIA_TYPE = re.compile(r"^\s+Media type:\s+(?P<val>.+)$")
    _VENDOR = re.compile(r"^\s+Vendor:\s+(?P<val>.+?)\s*$")
    _PART_NUMBER = re.compile(r"^\s+Part number:\s+(?P<val>\S+)")
    _SERIAL_NUMBER = re.compile(r"^\s+Serial number:\s+(?P<val>\S+)")
    _WAVELENGTH = re.compile(r"^\s+Wavelength:\s+(?P<val>\d+)\s+nm")

    _TRANSCEIVER_TEMP = re.compile(r"^\s+Transceiver Temp:\s+(?P<val>[\d.+-]+)\s+C")
    _TRANSCEIVER_VOLTAGE = re.compile(
        r"^\s+Transceiver Voltage:\s+(?P<val>[\d.+-]+)\s+V"
    )

    # Per-lane DOM reading.  Columns: lane, wavelength (nm or n/a),
    # tx dBm, tx mW, rx dBm, rx mW, laser bias mA.
    _LANE_DATA = re.compile(
        r"^\s+(?P<lane>\d+)\s+\S+\s+"
        r"(?P<tx_dbm>[\d.+-]+)\s+(?P<tx_mw>[\d.+-]+)\s+"
        r"(?P<rx_dbm>[\d.+-]+)\s+(?P<rx_mw>[\d.+-]+)\s+"
        r"(?P<bias>[\d.+-]+)"
    )

    _THRESHOLD_ROW = re.compile(
        r"^\s+(?P<label>[A-Za-z][A-Za-z ]+\([A-Za-z]+\)):\s+(?P<rest>.+?)\s*$"
    )

    _FEC_CORRECTED = re.compile(r"^\s+Corrected Codeword Count:\s+(?P<val>\d+)")
    _FEC_UNCORRECTED = re.compile(r"^\s+Uncorrected Codeword Count:\s+(?P<val>\d+)")

    _OPER_MAC = re.compile(r"^\s+Operational address:\s+(?P<val>\S+)")
    _BURNT_MAC = re.compile(r"^\s+Burnt-in address:\s+(?P<val>\S+)")

    _AUTONEG = re.compile(r"^Autonegotiation\s+(?P<val>\S+)")

    _SPEED = re.compile(r"^\s+Speed:\s+(?P<val>\S+)")
    _DUPLEX = re.compile(r"^\s+Duplex:\s+(?P<val>.+?)\s*$")
    _FLOWCONTROL = re.compile(r"^\s+Flowcontrol:\s+(?P<val>.+?)\s*$")
    _LOOPBACK = re.compile(r"^\s+Loopback:\s+(?P<val>.+?)\s*$")
    _MTU = re.compile(r"^\s+MTU:\s+(?P<val>\d+)")
    _MRU = re.compile(r"^\s+MRU:\s+(?P<val>\d+)")
    _FEC_MODE = re.compile(r"^\s+Forward error correction:\s+(?P<val>.+?)\s*$")

    @classmethod
    def _parse_optics(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract optics vendor/part/serial/wavelength from lines."""
        optics: dict[str, object] = {}
        for i in range(start, min(start + 10, len(lines))):
            line = lines[i]
            if m := cls._VENDOR.match(line):
                optics["vendor"] = m.group("val")
            elif m := cls._PART_NUMBER.match(line):
                optics["part_number"] = m.group("val")
            elif m := cls._SERIAL_NUMBER.match(line):
                optics["serial_number"] = m.group("val")
            elif m := cls._WAVELENGTH.match(line):
                optics["wavelength_nm"] = int(m.group("val"))
            elif line.strip().startswith("Digital Optical"):
                break
        if optics:
            result["optics"] = optics

    @classmethod
    def _parse_threshold_row(
        cls,
        line: str,
    ) -> tuple[str, AlarmThreshold] | None:
        """Parse a single alarm-threshold row.

        Returns ``(field_key, threshold_dict)`` when the row matches a known
        metric label and at least one column has a real value; otherwise None.
        """
        m = cls._THRESHOLD_ROW.match(line)
        if m is None:
            return None
        label = m.group("label").strip()
        key = _THRESHOLD_LABEL_TO_KEY.get(label)
        if key is None:
            return None
        cols = m.group("rest").split()
        threshold: dict[str, float] = {}
        for col_key, raw in zip(_THRESHOLD_COLUMN_KEYS, cols, strict=False):
            if raw in _PLACEHOLDER_TOKENS:
                continue
            try:
                threshold[col_key] = float(raw)
            except ValueError:
                continue
        if not threshold:
            return None
        return key, cast(AlarmThreshold, threshold)

    @classmethod
    def _record_threshold_row(
        cls,
        line: str,
        thresholds: dict[str, AlarmThreshold],
    ) -> bool:
        """Try to parse a threshold row; record it and return True on match."""
        parsed = cls._parse_threshold_row(line)
        if parsed is None:
            return False
        field, threshold = parsed
        thresholds[field] = threshold
        return True

    @classmethod
    def _parse_dom_alarms(
        cls,
        lines: list[str],
        start: int,
    ) -> list[str]:
        """Parse the 'DOM alarms:' block into a list of active alarm names."""
        alarms: list[str] = []
        for i in range(start, len(lines)):
            line = lines[i]
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Alarm") or stripped.startswith("Thresholds"):
                break
            if stripped == "No alarms":
                return []
            alarms.append(stripped)
        return alarms

    @classmethod
    def _parse_dom_lane(
        cls,
        line: str,
        lanes: dict[str, LaneDomInfo],
    ) -> bool:
        """Try to parse a per-lane DOM line; return True on a match."""
        m = cls._LANE_DATA.match(line)
        if m is None:
            return False
        lane_key = m.group("lane")
        lanes[lane_key] = LaneDomInfo(
            tx_power_dbm=float(m.group("tx_dbm")),
            tx_power_mw=float(m.group("tx_mw")),
            rx_power_dbm=float(m.group("rx_dbm")),
            rx_power_mw=float(m.group("rx_mw")),
            laser_bias_ma=float(m.group("bias")),
        )
        return True

    @classmethod
    def _parse_dom_scalars(cls, line: str, dom: DomInfo) -> bool:
        """Parse DOM temperature/voltage scalars; return True on a match."""
        if m := cls._TRANSCEIVER_TEMP.match(line):
            dom["transceiver_temp_c"] = float(m.group("val"))
            return True
        if m := cls._TRANSCEIVER_VOLTAGE.match(line):
            dom["transceiver_voltage_v"] = float(m.group("val"))
            return True
        return False

    @classmethod
    def _parse_dom(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract DOM temperature, voltage, lanes, alarms, and thresholds."""
        dom: DomInfo = {}
        lanes: dict[str, LaneDomInfo] = {}
        thresholds: dict[str, AlarmThreshold] = {}

        for i in range(start, len(lines)):
            line = lines[i]
            stripped = line.strip()
            if stripped.startswith("Statistics"):
                break
            if cls._parse_dom_scalars(line, dom):
                continue
            if cls._parse_dom_lane(line, lanes):
                continue
            if cls._record_threshold_row(line, thresholds):
                continue
            if stripped.startswith("DOM alarms"):
                dom["alarms"] = cls._parse_dom_alarms(lines, i + 1)

        if lanes:
            dom["lanes"] = lanes
        if thresholds:
            dom["alarm_thresholds"] = cast(AlarmThresholds, thresholds)
        if dom:
            result["dom"] = dom

    @classmethod
    def _parse_fec_stats(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract FEC corrected/uncorrected codeword counts."""
        fec: dict[str, int] = {}
        for i in range(start, min(start + 5, len(lines))):
            line = lines[i]
            if m := cls._FEC_CORRECTED.match(line):
                fec["corrected_codeword_count"] = int(m.group("val"))
            elif m := cls._FEC_UNCORRECTED.match(line):
                fec["uncorrected_codeword_count"] = int(m.group("val"))
        if fec:
            result["fec_statistics"] = fec

    @classmethod
    def _parse_mac_info(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract operational and burnt-in MAC addresses."""
        mac: dict[str, str] = {}
        for i in range(start, min(start + 5, len(lines))):
            line = lines[i]
            if m := cls._OPER_MAC.match(line):
                mac["operational_address"] = m.group("val")
            elif m := cls._BURNT_MAC.match(line):
                mac["burnt_in_address"] = m.group("val")
        if mac:
            result["mac_address"] = mac

    @classmethod
    def _parse_oper_values(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract operational parameters (speed, duplex, MTU, etc.)."""
        ov: dict[str, object] = {}
        for i in range(start, min(start + 15, len(lines))):
            line = lines[i]
            if m := cls._SPEED.match(line):
                ov["speed"] = m.group("val")
            elif m := cls._DUPLEX.match(line):
                ov["duplex"] = m.group("val")
            elif m := cls._FLOWCONTROL.match(line):
                ov["flowcontrol"] = m.group("val")
            elif m := cls._LOOPBACK.match(line):
                ov["loopback"] = m.group("val")
            elif m := cls._MTU.match(line):
                ov["mtu"] = int(m.group("val"))
            elif m := cls._MRU.match(line):
                ov["mru"] = int(m.group("val"))
            elif m := cls._FEC_MODE.match(line):
                ov["forward_error_correction"] = m.group("val")
        if ov:
            result["operational_values"] = ov

    @classmethod
    def _parse_state_fields(
        cls,
        line: str,
        result: dict[str, object],
    ) -> bool:
        """Parse state and media type fields from a single line."""
        if m := cls._ADMIN_STATE.match(line):
            result["admin_state"] = m.group("val").strip()
            return True
        if m := cls._OPER_STATE.match(line):
            result["oper_state"] = m.group("val").strip()
            return True
        if m := cls._LED_STATE.match(line):
            result["led_state"] = m.group("val").strip()
            return True
        if m := cls._MEDIA_TYPE.match(line):
            result["media_type"] = m.group("val").strip()
            return True
        if m := cls._AUTONEG.match(line):
            result["autonegotiation"] = m.group("val").lower() != "disabled."
            return True
        return False

    @classmethod
    def _dispatch_section(
        cls,
        line: str,
        lines: list[str],
        i: int,
        result: dict[str, object],
    ) -> None:
        """Dispatch section headers to sub-parsers."""
        stripped = line.strip()
        if stripped == "Optics:":
            cls._parse_optics(lines, i + 1, result)
        elif stripped.startswith("Digital Optical Monitoring"):
            cls._parse_dom(lines, i + 1, result)
        elif stripped == "FEC:":
            cls._parse_fec_stats(lines, i + 1, result)
        elif stripped == "MAC address information:":
            cls._parse_mac_info(lines, i + 1, result)
        elif stripped == "Operational values:":
            cls._parse_oper_values(lines, i + 1, result)

    @classmethod
    def _parse_interface_block(
        cls,
        lines: list[str],
    ) -> InterfaceControllerResult:
        """Parse a single interface block into structured data."""
        result: dict[str, object] = {}

        for i, line in enumerate(lines):
            if not cls._parse_state_fields(line, result):
                cls._dispatch_section(line, lines, i, result)

        return cast(InterfaceControllerResult, result)

    @classmethod
    def parse(
        cls,
        output: str,
    ) -> ShowControllersHundredGigabitEthernetResult:
        """Parse 'show controllers HundredGigabitEthernet' output.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict keyed by interface name with controller details.

        Raises:
            ValueError: If no interface blocks are found.
        """
        result: ShowControllersHundredGigabitEthernetResult = {}
        lines = output.splitlines()

        block_starts: list[tuple[str, int]] = []
        for i, line in enumerate(lines):
            if m := cls._INTF_HEADER.match(line):
                block_starts.append((m.group("name"), i))

        if not block_starts:
            msg = "No interface blocks found in output"
            raise ValueError(msg)

        for idx, (raw_name, start) in enumerate(block_starts):
            if idx + 1 < len(block_starts):
                end = block_starts[idx + 1][1]
            else:
                end = len(lines)
            block_lines = lines[start:end]
            intf_name = canonical_interface_name(raw_name)
            result[intf_name] = cls._parse_interface_block(block_lines)

        return result
