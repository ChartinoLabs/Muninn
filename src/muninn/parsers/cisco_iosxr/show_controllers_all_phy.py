"""Parser for 'show controllers all phy' command on Cisco IOS-XR."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class LaneDiagnostics(TypedDict):
    """Schema for per-lane diagnostic measurements."""

    bias_ma: NotRequired[float]
    tx_power_mw: NotRequired[float]
    tx_power_dbm: NotRequired[float]
    rx_power_mw: NotRequired[float]
    rx_power_dbm: NotRequired[float]


class ModuleDiagnostics(TypedDict):
    """Schema for module-level diagnostic measurements."""

    temperature_c: NotRequired[float]
    voltage_v: NotRequired[float]


class ControllerPhyEntry(TypedDict):
    """Schema for a single interface's PHY/EEPROM data."""

    xcvr_type: NotRequired[str]
    connector_type: NotRequired[str]
    ethernet_compliance: NotRequired[str]
    encoding: NotRequired[str]
    nominal_bitrate_mbps: NotRequired[int]
    length_smf_km: NotRequired[int]
    length_om3_m: NotRequired[int]
    length_om2_m: NotRequired[int]
    length_om1_m: NotRequired[int]
    length_copper_m: NotRequired[int]
    vendor_name: NotRequired[str]
    vendor_oui: NotRequired[str]
    vendor_part_number: NotRequired[str]
    vendor_revision: NotRequired[str]
    vendor_serial_number: NotRequired[str]
    wavelength_nm: NotRequired[float]
    wavelength_tolerance_nm: NotRequired[float]
    date_code: NotRequired[str]
    clei_code: NotRequired[str]
    cisco_part_number: NotRequired[str]
    cisco_part_version: NotRequired[str]
    product_id: NotRequired[str]
    module_diagnostics: NotRequired[ModuleDiagnostics]
    lanes: NotRequired[dict[str, LaneDiagnostics]]


ShowControllersAllPhyResult = dict[str, ControllerPhyEntry]


@register(OS.CISCO_IOSXR, "show controllers all phy")
class ShowControllersAllPhyParser(BaseParser[ShowControllersAllPhyResult]):
    """Parser for 'show controllers all phy' on Cisco IOS-XR.

    Extracts transceiver EEPROM data and optical diagnostics per interface.
    Hex dump sections (MSA Data) are skipped.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _INTERFACE_HEADER = re.compile(r"^PHY data for interface:\s+(?P<interface>\S+)")

    _XCVR_TYPE = re.compile(r"^\s+Xcvr Type:\s+(?P<value>.+?)\s*$")
    _CONNECTOR = re.compile(r"^\s+Connector Type:\s+(?P<value>.+?)\s*$")
    _ETH_COMPLIANCE = re.compile(
        r"^\s+Ethernet Compliance Codes:\s+(?P<value>.+?),?\s*$"
    )
    _ENCODING = re.compile(r"^\s+Encoding:\s+(?P<value>.+?),?\s*$")
    _NOMINAL_BR = re.compile(r"^\s+BR, nominal:\s+(?P<value>\d+)\s+Mbps")
    _LENGTH = re.compile(
        r"^\s+Length SMF:\s+(?P<smf>\d+)KM,\s+"
        r"OM3:\s+(?P<om3>\d+)M,\s+"
        r"OM2:\s+(?P<om2>\d+)M,\s+"
        r"OM1:\s+(?P<om1>\d+)M,\s+"
        r"Copper:\s+(?P<copper>\d+)M"
    )
    _VENDOR_NAME = re.compile(r"^\s+Vendor Name:\s+(?P<value>.+?)\s*$")
    _VENDOR_OUI = re.compile(r"^\s+Vendor OUI:\s+(?P<value>\S+)")
    _VENDOR_PN = re.compile(
        r"^\s+Vendor Part Number:\s+(?P<pn>.+?)\s+"
        r"\(rev\.:\s+(?P<rev>\S+)\)"
    )
    _VENDOR_PN_NO_REV = re.compile(r"^\s+Vendor Part Number:\s+(?P<pn>.+?)\s*$")
    _WAVELENGTH = re.compile(r"^\s+Wavelength:\s+(?P<value>[\d.]+)\s+nm")
    _WAVELENGTH_TOL = re.compile(r"^\s+Wavelength Tolerance:\s+(?P<value>[\d.]+)\s+nm")
    _VENDOR_SN = re.compile(r"^\s+Vendor Serial Number:\s+(?P<value>.+?)\s*$")
    _DATE_CODE = re.compile(r"^\s+Date Code \(yy/mm/dd\):\s+(?P<value>\S+)")
    _CLEI = re.compile(r"^\s+CLEI Code:\s+(?P<value>\S+)")
    _CISCO_PN = re.compile(
        r"^\s+Part Number:\s+(?P<pn>\S+)\s+"
        r"\(ver\.:\s+(?P<ver>.+?)\s*\)"
    )
    _PRODUCT_ID = re.compile(r"^\s+Product Id:\s+(?P<value>\S+)")

    _MODULE_TEMP = re.compile(r"^\s+Temperature:\s+(?P<value>[+-]?[\d.]+)\s+C\s*$")
    _MODULE_VOLTAGE = re.compile(r"^\s+Voltage:\s+(?P<value>[\d.]+)\s+Volt\s*$")

    _LANE_DATA = re.compile(
        r"^\s+(?P<lane>\d+)\s+"
        r"(?P<temp>\S+)\s+"
        r"(?P<bias>[\d.]+)\s+mAmps\s+"
        r"(?P<tx_mw>[\d.]+)\s+mW\s+"
        r"\((?P<tx_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<rx_mw>[\d.]+)\s+mW\s+"
        r"\((?P<rx_dbm>[+-]?[\d.]+)\s+dBm\)"
    )

    # Lines to skip: hex dumps, thresholds headers, alarm/warning rows, etc.
    _HEX_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+:")
    _MSA_HEADER = re.compile(r"^MSA Data\s")

    @classmethod
    def _parse_transceiver_basics(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse transceiver type, connector, encoding, and length fields."""
        if match := cls._XCVR_TYPE.match(line):
            entry["xcvr_type"] = match.group("value").strip()
            return True
        if match := cls._CONNECTOR.match(line):
            entry["connector_type"] = match.group("value").strip()
            return True
        if match := cls._ETH_COMPLIANCE.match(line):
            entry["ethernet_compliance"] = match.group("value").strip()
            return True
        if match := cls._ENCODING.match(line):
            entry["encoding"] = match.group("value").strip()
            return True
        if match := cls._NOMINAL_BR.match(line):
            entry["nominal_bitrate_mbps"] = int(match.group("value"))
            return True
        if match := cls._LENGTH.match(line):
            entry["length_smf_km"] = int(match.group("smf"))
            entry["length_om3_m"] = int(match.group("om3"))
            entry["length_om2_m"] = int(match.group("om2"))
            entry["length_om1_m"] = int(match.group("om1"))
            entry["length_copper_m"] = int(match.group("copper"))
            return True
        return False

    @classmethod
    def _parse_vendor_info(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse vendor name, OUI, part number, serial, wavelength, and date."""
        if match := cls._VENDOR_NAME.match(line):
            entry["vendor_name"] = match.group("value").strip()
            return True
        if match := cls._VENDOR_OUI.match(line):
            entry["vendor_oui"] = match.group("value").strip()
            return True
        if match := cls._VENDOR_PN.match(line):
            entry["vendor_part_number"] = match.group("pn").strip()
            entry["vendor_revision"] = match.group("rev").strip()
            return True
        if match := cls._VENDOR_PN_NO_REV.match(line):
            entry["vendor_part_number"] = match.group("pn").strip()
            return True
        if match := cls._WAVELENGTH_TOL.match(line):
            entry["wavelength_tolerance_nm"] = float(match.group("value"))
            return True
        if match := cls._WAVELENGTH.match(line):
            entry["wavelength_nm"] = float(match.group("value"))
            return True
        if match := cls._VENDOR_SN.match(line):
            entry["vendor_serial_number"] = match.group("value").strip()
            return True
        if match := cls._DATE_CODE.match(line):
            entry["date_code"] = match.group("value").strip()
            return True
        return False

    @classmethod
    def _parse_cisco_fields(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse Cisco-specific CLEI, part number, and product ID fields."""
        if match := cls._CLEI.match(line):
            entry["clei_code"] = match.group("value").strip()
            return True
        if match := cls._CISCO_PN.match(line):
            entry["cisco_part_number"] = match.group("pn").strip()
            entry["cisco_part_version"] = match.group("ver").strip()
            return True
        if match := cls._PRODUCT_ID.match(line):
            entry["product_id"] = match.group("value").strip()
            return True
        return False

    @classmethod
    def _parse_eeprom_fields(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse EEPROM key-value fields from a single line."""
        return (
            cls._parse_transceiver_basics(line, entry)
            or cls._parse_vendor_info(line, entry)
            or cls._parse_cisco_fields(line, entry)
        )

    @classmethod
    def _parse_diagnostics(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse module-level and lane-level diagnostic lines."""
        if match := cls._MODULE_TEMP.match(line):
            diag = entry.setdefault("module_diagnostics", {})
            diag["temperature_c"] = float(match.group("value"))
            return True
        if match := cls._MODULE_VOLTAGE.match(line):
            diag = entry.setdefault("module_diagnostics", {})
            diag["voltage_v"] = float(match.group("value"))
            return True
        if match := cls._LANE_DATA.match(line):
            lanes = entry.setdefault("lanes", {})
            lane_id = match.group("lane")
            lane_entry: LaneDiagnostics = {
                "bias_ma": float(match.group("bias")),
                "tx_power_mw": float(match.group("tx_mw")),
                "tx_power_dbm": float(match.group("tx_dbm")),
                "rx_power_mw": float(match.group("rx_mw")),
                "rx_power_dbm": float(match.group("rx_dbm")),
            }
            lanes[lane_id] = lane_entry
            return True
        return False

    @classmethod
    def parse(cls, output: str) -> ShowControllersAllPhyResult:
        """Parse 'show controllers all phy' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Dict keyed by interface name with transceiver/PHY details.

        Raises:
            ValueError: If no interface data is found in the output.
        """
        result: ShowControllersAllPhyResult = {}
        current_entry: dict[str, object] | None = None

        for line in output.splitlines():
            # Skip hex dump and MSA header lines
            if cls._HEX_LINE.match(line) or cls._MSA_HEADER.match(line):
                continue

            if match := cls._INTERFACE_HEADER.match(line):
                current_entry = {}
                result[match.group("interface")] = current_entry  # type: ignore[assignment]
                continue

            if current_entry is None:
                continue

            cls._parse_eeprom_fields(line, current_entry)
            cls._parse_diagnostics(line, current_entry)

        if not result:
            msg = "No interface PHY data found in output"
            raise ValueError(msg)

        return result
