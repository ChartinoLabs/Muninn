"""Parser for 'show controllers HundredGigabitEthernet' on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LaneDomInfo(TypedDict):
    """Per-lane Digital Optical Monitoring readings."""

    tx_power_dbm: float
    tx_power_mw: float
    rx_power_dbm: float
    rx_power_mw: float
    laser_bias_ma: float


class OpticsInfo(TypedDict):
    """Optics transceiver identification."""

    vendor: str
    part_number: str
    serial_number: str
    wavelength_nm: int


class DomInfo(TypedDict):
    """Digital Optical Monitoring summary readings."""

    transceiver_temp_c: float
    transceiver_voltage_v: float
    lanes: dict[str, LaneDomInfo]


class FecStatistics(TypedDict):
    """Forward Error Correction counters."""

    corrected_codeword_count: int
    uncorrected_codeword_count: int


class MacAddressInfo(TypedDict):
    """MAC address information."""

    operational_address: str
    burnt_in_address: str


class OperationalValues(TypedDict):
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
    led_state: str
    media_type: str
    optics: NotRequired[OpticsInfo]
    dom: NotRequired[DomInfo]
    fec_statistics: NotRequired[FecStatistics]
    mac_address: NotRequired[MacAddressInfo]
    autonegotiation: bool
    operational_values: NotRequired[OperationalValues]


ShowControllersHundredGigabitEthernetResult = dict[str, InterfaceControllerResult]


@register(OS.CISCO_IOSXR, "show controllers HundredGigabitEthernet")
class ShowControllersHundredGigabitEthernetParser(
    BaseParser[ShowControllersHundredGigabitEthernetResult],
):
    """Parser for 'show controllers HundredGigabitEthernet' on Cisco IOS-XR.

    Parses per-interface controller details including state, optics,
    DOM readings, MAC addresses, and operational values.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    # Interface header
    _INTF_HEADER = re.compile(r"^Operational data for interface (?P<name>\S+):")

    # State section
    _ADMIN_STATE = re.compile(r"^\s+Administrative state:\s+(?P<val>.+)$")
    _OPER_STATE = re.compile(r"^\s+Operational state:\s+(?P<val>.+)$")
    _LED_STATE = re.compile(r"^\s+LED state:\s+(?P<val>.+)$")

    # Phy section
    _MEDIA_TYPE = re.compile(r"^\s+Media type:\s+(?P<val>.+)$")
    _VENDOR = re.compile(r"^\s+Vendor:\s+(?P<val>.+?)\s*$")
    _PART_NUMBER = re.compile(r"^\s+Part number:\s+(?P<val>\S+)")
    _SERIAL_NUMBER = re.compile(r"^\s+Serial number:\s+(?P<val>\S+)")
    _WAVELENGTH = re.compile(r"^\s+Wavelength:\s+(?P<val>\d+)\s+nm")

    # DOM readings
    _TRANSCEIVER_TEMP = re.compile(r"^\s+Transceiver Temp:\s+(?P<val>[\d.+-]+)\s+C")
    _TRANSCEIVER_VOLTAGE = re.compile(
        r"^\s+Transceiver Voltage:\s+(?P<val>[\d.+-]+)\s+V"
    )

    # Per-lane DOM data line:
    # "        00     n/a     0.1   1.0205     -1.8   0.6627     5.450"
    _LANE_DATA = re.compile(
        r"^\s+(?P<lane>\d+)\s+\S+\s+"
        r"(?P<tx_dbm>[\d.+-]+)\s+(?P<tx_mw>[\d.+-]+)\s+"
        r"(?P<rx_dbm>[\d.+-]+)\s+(?P<rx_mw>[\d.+-]+)\s+"
        r"(?P<bias>[\d.+-]+)"
    )

    # FEC statistics
    _FEC_CORRECTED = re.compile(r"^\s+Corrected Codeword Count:\s+(?P<val>\d+)")
    _FEC_UNCORRECTED = re.compile(r"^\s+Uncorrected Codeword Count:\s+(?P<val>\d+)")

    # MAC address
    _OPER_MAC = re.compile(r"^\s+Operational address:\s+(?P<val>\S+)")
    _BURNT_MAC = re.compile(r"^\s+Burnt-in address:\s+(?P<val>\S+)")

    # Autonegotiation
    _AUTONEG = re.compile(r"^Autonegotiation\s+(?P<val>\S+)")

    # Operational values
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
    def _parse_dom(
        cls,
        lines: list[str],
        start: int,
        result: dict[str, object],
    ) -> None:
        """Extract DOM temperature, voltage, and per-lane readings."""
        dom: dict[str, object] = {}
        lanes: dict[str, LaneDomInfo] = {}
        lane_index = 0

        for i in range(start, len(lines)):
            line = lines[i]
            if m := cls._TRANSCEIVER_TEMP.match(line):
                dom["transceiver_temp_c"] = float(m.group("val"))
            elif m := cls._TRANSCEIVER_VOLTAGE.match(line):
                dom["transceiver_voltage_v"] = float(m.group("val"))
            elif m := cls._LANE_DATA.match(line):
                lane_key = str(lane_index)
                lanes[lane_key] = LaneDomInfo(
                    tx_power_dbm=float(m.group("tx_dbm")),
                    tx_power_mw=float(m.group("tx_mw")),
                    rx_power_dbm=float(m.group("rx_dbm")),
                    rx_power_mw=float(m.group("rx_mw")),
                    laser_bias_ma=float(m.group("bias")),
                )
                lane_index += 1
            elif line.strip().startswith("DOM alarms"):
                break
            elif line.strip().startswith("Statistics"):
                break

        if lanes:
            dom["lanes"] = lanes
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

        # Split into per-interface blocks
        block_starts: list[tuple[str, int]] = []
        for i, line in enumerate(lines):
            if m := cls._INTF_HEADER.match(line):
                block_starts.append((m.group("name"), i))

        if not block_starts:
            msg = "No interface blocks found in output"
            raise ValueError(msg)

        for idx, (intf_name, start) in enumerate(block_starts):
            if idx + 1 < len(block_starts):
                end = block_starts[idx + 1][1]
            else:
                end = len(lines)
            block_lines = lines[start:end]
            result[intf_name] = cls._parse_interface_block(block_lines)

        return result
