"""Parser for 'show controllers all phy' command on Cisco IOS-XR."""

import re
from typing import ClassVar, TypedDict, cast

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag
from muninn.utils import canonical_interface_name


class ThresholdSet(TypedDict):
    """Schema for alarm/warning threshold bounds for a single metric."""

    alarm_high: NotRequired[float]
    warning_high: NotRequired[float]
    warning_low: NotRequired[float]
    alarm_low: NotRequired[float]


class ModuleThresholds(TypedDict):
    """Schema for module-level alarm/warning thresholds."""

    temperature_c: NotRequired[ThresholdSet]
    voltage_v: NotRequired[ThresholdSet]


class LaneThresholds(TypedDict):
    """Schema for per-lane alarm/warning thresholds."""

    bias_ma: NotRequired[ThresholdSet]
    tx_power_mw: NotRequired[ThresholdSet]
    tx_power_dbm: NotRequired[ThresholdSet]
    rx_power_mw: NotRequired[ThresholdSet]
    rx_power_dbm: NotRequired[ThresholdSet]


class LaneDiagnostics(TypedDict):
    """Schema for per-lane diagnostic measurements."""

    temperature_c: NotRequired[float]
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
    power_class: NotRequired[str]
    connector_type: NotRequired[str]
    ethernet_compliance: NotRequired[str]
    encoding: NotRequired[str]
    nominal_bitrate_mbps: NotRequired[int]
    length_smf_km: NotRequired[int]
    length_om3_m: NotRequired[int]
    length_om2_m: NotRequired[int]
    length_om1_m: NotRequired[int]
    length_copper_m: NotRequired[int]
    device_tech: NotRequired[str]
    vendor_name: NotRequired[str]
    vendor_oui: NotRequired[str]
    vendor_part_number: NotRequired[str]
    vendor_revision: NotRequired[str]
    vendor_serial_number: NotRequired[str]
    wavelength_nm: NotRequired[float]
    wavelength_tolerance_nm: NotRequired[float]
    date_code: NotRequired[str]
    diagnostic_monitoring_type: NotRequired[str]
    options: NotRequired[list[str]]
    clei_code: NotRequired[str]
    cisco_part_number: NotRequired[str]
    cisco_part_version: NotRequired[str]
    product_id: NotRequired[str]
    module_diagnostics: NotRequired[ModuleDiagnostics]
    module_thresholds: NotRequired[ModuleThresholds]
    lanes: NotRequired[dict[str, LaneDiagnostics]]
    lane_thresholds: NotRequired[LaneThresholds]


class ShowControllersAllPhyResult(TypedDict):
    """Schema for 'show controllers all phy' parsed output.

    Dict-of-dicts keyed by canonical interface name.
    """

    interfaces: dict[str, ControllerPhyEntry]


_LANE_TEMP_SKIP = frozenset({"N/A", "n/a", "--"})


def _strip_trailing_comma(value: str) -> str:
    """Return value with a single trailing comma removed."""
    return value[:-1].rstrip() if value.endswith(",") else value


@register(OS.CISCO_IOSXR, "show controllers all phy")
class ShowControllersAllPhyParser(BaseParser[ShowControllersAllPhyResult]):
    """Parser for 'show controllers all phy' on Cisco IOS-XR.

    Extracts transceiver EEPROM data, alarm/warning thresholds, and
    optical diagnostics per interface. Hex dump sections are skipped.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INTERFACES})

    _INTERFACE_HEADER = re.compile(r"^PHY data for interface:\s+(?P<interface>\S+)")

    _XCVR_TYPE = re.compile(r"^\s+Xcvr Type:\s+(?P<value>.+?)\s*$")
    _EXT_TYPE = re.compile(r"^\s+Ext Type:\s+(?P<value>[^,]+?)\s*,")
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
    _DEVICE_TECH = re.compile(r"^\s+Device Tech:\s+(?P<value>.+?)\s*$")
    _VENDOR_NAME = re.compile(r"^\s+Vendor Name:\s+(?P<value>.+?)\s*$")
    _VENDOR_OUI = re.compile(r"^\s+Vendor OUI:\s+(?P<value>\S+)")
    _VENDOR_PN = re.compile(
        r"^\s+Vendor Part Number:\s+(?P<pn>.+?)"
        r"(?:\s+\(rev\.:\s+(?P<rev>\S+)\))?\s*$"
    )
    _WAVELENGTH = re.compile(r"^\s+Wavelength:\s+(?P<value>[\d.]+)\s+nm")
    _WAVELENGTH_TOL = re.compile(r"^\s+Wavelength Tolerance:\s+(?P<value>[\d.]+)\s+nm")
    _VENDOR_SN = re.compile(r"^\s+Vendor Serial Number:\s+(?P<value>.+?)\s*$")
    _DATE_CODE = re.compile(r"^\s+Date Code \(yy/mm/dd\):\s+(?P<value>\S+)")
    _DIAG_MON_TYPE = re.compile(r"^\s+Diagnostic Monitoring Type:\s+(?P<value>.+?)\s*$")
    _OPTIONS = re.compile(r"^\s+Options:\s+(?P<value>.+?)\s*$")
    _CLEI = re.compile(r"^\s+CLEI Code:\s+(?P<value>\S+)")
    _CISCO_PN = re.compile(
        r"^\s+Part Number:\s+(?P<pn>\S+)\s+\(ver\.:\s+(?P<ver>.+?)\s*\)"
    )
    _PRODUCT_ID = re.compile(r"^\s+Product Id:\s+(?P<value>\S+)")

    _MODULE_TEMP = re.compile(r"^\s+Temperature:\s+(?P<value>[+-]?[\d.]+)\s+C\s*$")
    _MODULE_VOLTAGE = re.compile(r"^\s+Voltage:\s+(?P<value>[\d.]+)\s+Volt\s*$")

    _MODULE_TEMP_THRESHOLDS = re.compile(
        r"^\s+Temperature:\s+"
        r"(?P<alarm_high>[+-]?[\d.]+)\s+C\s+"
        r"(?P<warning_high>[+-]?[\d.]+)\s+C\s+"
        r"(?P<warning_low>[+-]?[\d.]+)\s+C\s+"
        r"(?P<alarm_low>[+-]?[\d.]+)\s+C\s*$"
    )
    _MODULE_VOLT_THRESHOLDS = re.compile(
        r"^\s+Voltage:\s+"
        r"(?P<alarm_high>[\d.]+)\s+Volt\s+"
        r"(?P<warning_high>[\d.]+)\s+Volt\s+"
        r"(?P<warning_low>[\d.]+)\s+Volt\s+"
        r"(?P<alarm_low>[\d.]+)\s+Volt\s*$"
    )
    _LANE_BIAS_THRESHOLDS = re.compile(
        r"^\s+Bias:\s+"
        r"(?P<alarm_high>[\d.]+)\s+mAmps\s+"
        r"(?P<warning_high>[\d.]+)\s+mAmps\s+"
        r"(?P<warning_low>[\d.]+)\s+mAmps\s+"
        r"(?P<alarm_low>[\d.]+)\s+mAmps\s*$"
    )
    _LANE_TX_PWR_THRESHOLDS = re.compile(
        r"^\s+Transmit Power:\s+"
        r"(?P<ah_mw>[\d.]+)\s+mW\s+\((?P<ah_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<wh_mw>[\d.]+)\s+mW\s+\((?P<wh_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<wl_mw>[\d.]+)\s+mW\s+\((?P<wl_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<al_mw>[\d.]+)\s+mW\s+\((?P<al_dbm>[+-]?[\d.]+)\s+dBm\)"
    )
    _LANE_RX_PWR_THRESHOLDS = re.compile(
        r"^\s+Receive Power:\s+"
        r"(?P<ah_mw>[\d.]+)\s+mW\s+\((?P<ah_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<wh_mw>[\d.]+)\s+mW\s+\((?P<wh_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<wl_mw>[\d.]+)\s+mW\s+\((?P<wl_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<al_mw>[\d.]+)\s+mW\s+\((?P<al_dbm>[+-]?[\d.]+)\s+dBm\)"
    )

    _LANE_DATA = re.compile(
        r"^\s+(?P<lane>\d+)\s+"
        r"(?P<temp>\S+)\s+"
        r"(?P<bias>[\d.]+)\s+mAmps\s+"
        r"(?P<tx_mw>[\d.]+)\s+mW\s+"
        r"\((?P<tx_dbm>[+-]?[\d.]+)\s+dBm\)\s+"
        r"(?P<rx_mw>[\d.]+)\s+mW\s+"
        r"\((?P<rx_dbm>[+-]?[\d.]+)\s+dBm\)"
    )

    _HEX_LINE = re.compile(r"^\s*0x[0-9a-fA-F]+:")
    _MSA_HEADER = re.compile(r"^MSA Data\s")

    @classmethod
    def _parse_transceiver_basics(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse transceiver type, connector, encoding, and length fields."""
        if match := cls._XCVR_TYPE.match(line):
            entry["xcvr_type"] = match.group("value").strip()
            return True
        if match := cls._EXT_TYPE.match(line):
            entry["power_class"] = match.group("value").strip()
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
        if match := cls._DEVICE_TECH.match(line):
            entry["device_tech"] = _strip_trailing_comma(match.group("value").strip())
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
            if rev := match.group("rev"):
                entry["vendor_revision"] = rev.strip()
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
    def _parse_module_metadata(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse module-level descriptive fields (DDM type, options)."""
        if match := cls._DIAG_MON_TYPE.match(line):
            entry["diagnostic_monitoring_type"] = _strip_trailing_comma(
                match.group("value").strip()
            )
            return True
        if match := cls._OPTIONS.match(line):
            raw = _strip_trailing_comma(match.group("value").strip())
            entry["options"] = [item.strip() for item in raw.split(",") if item.strip()]
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
            or cls._parse_module_metadata(line, entry)
            or cls._parse_cisco_fields(line, entry)
        )

    @staticmethod
    def _threshold_set(match: re.Match[str]) -> ThresholdSet:
        """Build a ThresholdSet from a 4-value threshold regex match."""
        return {
            "alarm_high": float(match.group("alarm_high")),
            "warning_high": float(match.group("warning_high")),
            "warning_low": float(match.group("warning_low")),
            "alarm_low": float(match.group("alarm_low")),
        }

    @staticmethod
    def _threshold_pair(match: re.Match[str]) -> tuple[ThresholdSet, ThresholdSet]:
        """Build mW and dBm ThresholdSets from a paired-value match."""
        mw: ThresholdSet = {
            "alarm_high": float(match.group("ah_mw")),
            "warning_high": float(match.group("wh_mw")),
            "warning_low": float(match.group("wl_mw")),
            "alarm_low": float(match.group("al_mw")),
        }
        dbm: ThresholdSet = {
            "alarm_high": float(match.group("ah_dbm")),
            "warning_high": float(match.group("wh_dbm")),
            "warning_low": float(match.group("wl_dbm")),
            "alarm_low": float(match.group("al_dbm")),
        }
        return mw, dbm

    @classmethod
    def _parse_module_thresholds(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse module-level alarm/warning threshold rows."""
        if match := cls._MODULE_TEMP_THRESHOLDS.match(line):
            mt = cast(ModuleThresholds, entry.setdefault("module_thresholds", {}))
            mt["temperature_c"] = cls._threshold_set(match)
            return True
        if match := cls._MODULE_VOLT_THRESHOLDS.match(line):
            mt = cast(ModuleThresholds, entry.setdefault("module_thresholds", {}))
            mt["voltage_v"] = cls._threshold_set(match)
            return True
        return False

    @classmethod
    def _parse_lane_thresholds(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse per-lane alarm/warning threshold rows."""
        if match := cls._LANE_BIAS_THRESHOLDS.match(line):
            lt = cast(LaneThresholds, entry.setdefault("lane_thresholds", {}))
            lt["bias_ma"] = cls._threshold_set(match)
            return True
        if match := cls._LANE_TX_PWR_THRESHOLDS.match(line):
            lt = cast(LaneThresholds, entry.setdefault("lane_thresholds", {}))
            mw, dbm = cls._threshold_pair(match)
            lt["tx_power_mw"] = mw
            lt["tx_power_dbm"] = dbm
            return True
        if match := cls._LANE_RX_PWR_THRESHOLDS.match(line):
            lt = cast(LaneThresholds, entry.setdefault("lane_thresholds", {}))
            mw, dbm = cls._threshold_pair(match)
            lt["rx_power_mw"] = mw
            lt["rx_power_dbm"] = dbm
            return True
        return False

    @classmethod
    def _parse_module_diagnostics(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse single-value module temperature/voltage readings."""
        if match := cls._MODULE_TEMP.match(line):
            diag = cast(ModuleDiagnostics, entry.setdefault("module_diagnostics", {}))
            diag["temperature_c"] = float(match.group("value"))
            return True
        if match := cls._MODULE_VOLTAGE.match(line):
            diag = cast(ModuleDiagnostics, entry.setdefault("module_diagnostics", {}))
            diag["voltage_v"] = float(match.group("value"))
            return True
        return False

    @classmethod
    def _parse_lane_data(cls, line: str, entry: dict[str, object]) -> bool:
        """Parse per-lane bias / Tx / Rx data rows."""
        match = cls._LANE_DATA.match(line)
        if not match:
            return False
        lanes = cast(dict[str, LaneDiagnostics], entry.setdefault("lanes", {}))
        lane_entry: LaneDiagnostics = {
            "bias_ma": float(match.group("bias")),
            "tx_power_mw": float(match.group("tx_mw")),
            "tx_power_dbm": float(match.group("tx_dbm")),
            "rx_power_mw": float(match.group("rx_mw")),
            "rx_power_dbm": float(match.group("rx_dbm")),
        }
        temp_raw = match.group("temp")
        if temp_raw not in _LANE_TEMP_SKIP:
            try:
                lane_entry["temperature_c"] = float(temp_raw)
            except ValueError:
                pass
        lanes[match.group("lane")] = lane_entry
        return True

    @classmethod
    def _parse_diagnostics(cls, line: str, entry: dict[str, object]) -> bool:
        """Dispatch to module-level and lane-level diagnostic parsers."""
        return (
            cls._parse_module_thresholds(line, entry)
            or cls._parse_lane_thresholds(line, entry)
            or cls._parse_module_diagnostics(line, entry)
            or cls._parse_lane_data(line, entry)
        )

    @classmethod
    def parse(cls, output: str) -> ShowControllersAllPhyResult:
        """Parse 'show controllers all phy' output.

        Args:
            output: Raw CLI output from the command.

        Returns:
            Parsed PHY/transceiver data keyed by canonical interface name.

        Raises:
            ValueError: If no interface data is found in the output.
        """
        interfaces: dict[str, ControllerPhyEntry] = {}
        current_entry: dict[str, object] | None = None

        for line in output.splitlines():
            if cls._HEX_LINE.match(line) or cls._MSA_HEADER.match(line):
                continue

            if match := cls._INTERFACE_HEADER.match(line):
                current_entry = {}
                interface_name = canonical_interface_name(
                    match.group("interface"), os=OS.CISCO_IOSXR
                )
                interfaces[interface_name] = cast(ControllerPhyEntry, current_entry)
                continue

            if current_entry is None:
                continue

            cls._parse_eeprom_fields(line, current_entry)
            cls._parse_diagnostics(line, current_entry)

        if not interfaces:
            msg = "No interface PHY data found in output"
            raise ValueError(msg)

        return ShowControllersAllPhyResult(interfaces=interfaces)
