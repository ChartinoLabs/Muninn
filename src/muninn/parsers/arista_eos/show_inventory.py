"""Parser for 'show inventory' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict

from typing_extensions import NotRequired

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.patterns import SEPARATOR_DASH_SPACE_RE
from muninn.registry import register
from muninn.tags import ParserTag


class SystemInfo(TypedDict):
    """Schema for the system information block."""

    description: str
    hardware_version: str
    serial_number: str
    manufacturing_date: NotRequired[str]


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    model: str
    serial_number: NotRequired[str]


class FanModuleEntry(TypedDict):
    """Schema for a single fan module entry."""

    num_fans: int
    model: str
    serial_number: NotRequired[str]


class PortSummaryEntry(TypedDict):
    """Schema for a port type summary entry."""

    count: int


class TransceiverEntry(TypedDict):
    """Schema for a single transceiver entry."""

    manufacturer: str
    model: str
    serial_number: NotRequired[str]
    revision: NotRequired[str]


class InventoryTotals(TypedDict):
    """Schema for chassis-wide slot/port totals reported in section headers.

    These reflect the total slot capacity declared by the device (e.g.
    ``System has 52 transceiver slots``) and may exceed the number of
    populated entries when slots are empty.
    """

    power_supply_slots: NotRequired[int]
    fan_modules: NotRequired[int]
    ports: NotRequired[int]
    transceiver_slots: NotRequired[int]


class ShowInventoryResult(TypedDict):
    """Schema for 'show inventory' parsed output on Arista EOS."""

    system: SystemInfo
    totals: InventoryTotals
    power_supplies: dict[str, PowerSupplyEntry]
    fan_modules: dict[str, FanModuleEntry]
    ports: dict[str, PortSummaryEntry]
    transceivers: dict[str, TransceiverEntry]


# Sentinel values that should be treated as absent.
_NA_SENTINELS = frozenset({"N/A", "n/a", "NA"})

# Transceiver right-split constants: split the rest of the line from the right
# to separate model, serial, and rev (all single-word) from multi-word manufacturer.
_TRANSCEIVER_RIGHT_SPLIT_FIELDS = 3  # max splits from right (model, serial, rev)
_TRANSCEIVER_MIN_PARTS = 3  # manufacturer + model + serial (minimum)
_TRANSCEIVER_PARTS_WITH_REV = 4  # manufacturer + model + serial + rev


def _clean_optional(value: str) -> str | None:
    """Return None if the value is a placeholder sentinel, else stripped string."""
    stripped = value.strip()
    if not stripped or stripped in _NA_SENTINELS:
        return None
    return stripped


@register(OS.ARISTA_EOS, "show inventory")
class ShowInventoryParser(BaseParser[ShowInventoryResult]):
    """Parser for 'show inventory' command on Arista EOS.

    Parses system information, power supplies, fan modules, port summary,
    and transceiver inventory from the show inventory output.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.INVENTORY})

    # Section headers
    _SYSTEM_INFO_HEADER = re.compile(r"^System information$")
    _POWER_SUPPLY_HEADER = re.compile(
        r"^System has (?P<count>\d+) power supply slots?$"
    )
    _FAN_MODULE_HEADER = re.compile(r"^System has (?P<count>\d+) fan modules?$")
    _PORT_HEADER = re.compile(r"^System has (?P<count>\d+) ports?$")
    _TRANSCEIVER_HEADER = re.compile(r"^System has (?P<count>\d+) transceiver slots?$")

    # System information block: description line then hw_version serial mfg_date
    _SYSTEM_HW_LINE = re.compile(
        r"^\s*(?P<hw_version>\S+)"
        r"\s+(?P<serial>\S+)"
        r"(?:\s+(?P<mfg_date>\S+))?\s*$"
    )

    # Power supply table row
    _PSU_ROW = re.compile(
        r"^\s*(?P<slot>\d+)"
        r"\s+(?P<model>\S+)"
        r"\s+(?P<serial>\S+)\s*$"
    )

    # Fan module table row
    _FAN_ROW = re.compile(
        r"^\s*(?P<module>\d+)"
        r"\s+(?P<num_fans>\d+)"
        r"\s+(?P<model>\S+)"
        r"\s+(?P<serial>\S+)\s*$"
    )

    # Port summary table row
    _PORT_ROW = re.compile(
        r"^\s*(?P<type>[A-Za-z][\w -]*\S)"
        r"\s+(?P<count>\d+)\s*$"
    )

    # Transceiver table row: port number, then right-split rev, serial, model
    # from end since manufacturer can contain spaces.
    _TRANSCEIVER_ROW = re.compile(r"^\s*(?P<port>\d+)\s+(?P<rest>.+)$")

    # Separator line (dashes/whitespace) shared across all section tables.
    _SEPARATOR = SEPARATOR_DASH_SPACE_RE

    @classmethod
    def _parse_transceiver_row(cls, row: str) -> tuple[str, TransceiverEntry] | None:
        """Parse a single transceiver data row.

        Uses right-split to handle multi-word manufacturer names.
        Expected fields (right to left): Rev, Serial Number, Model, Manufacturer.
        """
        match = cls._TRANSCEIVER_ROW.match(row)
        if not match:
            return None

        port = match.group("port")
        rest = match.group("rest")

        # Split from the right: the last three single-word fields are
        # Rev (optional), Serial Number, and Model. Everything remaining
        # is the manufacturer name.
        parts = rest.rsplit(maxsplit=_TRANSCEIVER_RIGHT_SPLIT_FIELDS)

        if len(parts) < _TRANSCEIVER_MIN_PARTS:
            return None

        if len(parts) == _TRANSCEIVER_PARTS_WITH_REV:
            # manufacturer, model, serial, rev
            manufacturer, model, serial_raw, rev_raw = (
                parts[0],
                parts[1],
                parts[2],
                parts[3],
            )
        else:
            # manufacturer, model, serial (no rev)
            manufacturer, model, serial_raw = parts[0], parts[1], parts[2]
            rev_raw = None

        entry = TransceiverEntry(
            manufacturer=manufacturer,
            model=model,
        )
        serial = _clean_optional(serial_raw)
        if serial is not None:
            entry["serial_number"] = serial
        if rev_raw is not None:
            rev = _clean_optional(rev_raw)
            if rev is not None:
                entry["revision"] = rev

        return port, entry

    @classmethod
    def _collect_content_lines(
        cls, lines: list[str], start: int
    ) -> tuple[list[str], int]:
        """Collect non-empty content lines until the next section header.

        Returns content lines and the index of the next unconsumed line.
        """
        idx = start
        content: list[str] = []
        while idx < len(lines):
            stripped = lines[idx].strip()
            if cls._is_section_header(stripped):
                break
            if stripped:
                content.append(stripped)
            idx += 1
        return content, idx

    @classmethod
    def _parse_system_info(cls, lines: list[str], start: int) -> tuple[SystemInfo, int]:
        """Parse the System information block starting after the header.

        Returns the parsed SystemInfo and the index of the next unconsumed line.
        """
        content, idx = cls._collect_content_lines(lines, start)

        _min_system_info_lines = 2
        if len(content) < _min_system_info_lines:
            msg = "Could not parse system information block"
            raise ValueError(msg)

        description = content[0]
        match = cls._SYSTEM_HW_LINE.match(content[1])
        if not match:
            msg = "Could not parse system hardware line"
            raise ValueError(msg)

        result = SystemInfo(
            description=description,
            hardware_version=match.group("hw_version"),
            serial_number=match.group("serial"),
        )
        mfg_date = match.group("mfg_date")
        if mfg_date is not None:
            result["manufacturing_date"] = mfg_date

        return result, idx

    @classmethod
    def _is_section_header(cls, stripped: str) -> bool:
        """Check if a stripped line is a section header."""
        return bool(
            cls._SYSTEM_INFO_HEADER.match(stripped)
            or cls._POWER_SUPPLY_HEADER.match(stripped)
            or cls._FAN_MODULE_HEADER.match(stripped)
            or cls._PORT_HEADER.match(stripped)
            or cls._TRANSCEIVER_HEADER.match(stripped)
        )

    @classmethod
    def _parse_table_rows(cls, lines: list[str], start: int) -> tuple[list[str], int]:
        """Skip header/separator lines and collect data rows until next section.

        Returns a list of raw data lines and the next unconsumed line index.
        """
        idx = start
        data_lines: list[str] = []
        past_separator = False

        while idx < len(lines):
            line = lines[idx]
            stripped = line.strip()

            if cls._is_section_header(stripped):
                break

            if not stripped:
                idx += 1
                continue

            if cls._SEPARATOR.match(stripped):
                past_separator = True
                idx += 1
                continue

            if not past_separator:
                idx += 1
                continue

            data_lines.append(line)
            idx += 1

        return data_lines, idx

    @classmethod
    def _parse_power_supplies(
        cls, data_lines: list[str]
    ) -> dict[str, PowerSupplyEntry]:
        """Parse power supply table rows into a dict keyed by slot number."""
        result: dict[str, PowerSupplyEntry] = {}
        for row in data_lines:
            match = cls._PSU_ROW.match(row)
            if match:
                slot = match.group("slot")
                entry = PowerSupplyEntry(model=match.group("model"))
                serial = _clean_optional(match.group("serial"))
                if serial is not None:
                    entry["serial_number"] = serial
                result[slot] = entry
        return result

    @classmethod
    def _parse_fan_modules(cls, data_lines: list[str]) -> dict[str, FanModuleEntry]:
        """Parse fan module table rows into a dict keyed by module number."""
        result: dict[str, FanModuleEntry] = {}
        for row in data_lines:
            match = cls._FAN_ROW.match(row)
            if match:
                module = match.group("module")
                entry = FanModuleEntry(
                    num_fans=int(match.group("num_fans")),
                    model=match.group("model"),
                )
                serial = _clean_optional(match.group("serial"))
                if serial is not None:
                    entry["serial_number"] = serial
                result[module] = entry
        return result

    @classmethod
    def _parse_ports(cls, data_lines: list[str]) -> dict[str, PortSummaryEntry]:
        """Parse port summary table rows into a dict keyed by port type."""
        result: dict[str, PortSummaryEntry] = {}
        for row in data_lines:
            match = cls._PORT_ROW.match(row)
            if match:
                port_type = match.group("type").strip()
                result[port_type] = PortSummaryEntry(
                    count=int(match.group("count")),
                )
        return result

    @classmethod
    def _parse_transceivers(cls, data_lines: list[str]) -> dict[str, TransceiverEntry]:
        """Parse transceiver table rows into a dict keyed by port number."""
        result: dict[str, TransceiverEntry] = {}
        for row in data_lines:
            entry_result = cls._parse_transceiver_row(row)
            if entry_result is not None:
                port, entry = entry_result
                result[port] = entry
        return result

    @classmethod
    def parse(cls, output: str) -> ShowInventoryResult:
        """Parse 'show inventory' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed inventory information keyed by component name.

        Raises:
            ValueError: If the system information block cannot be parsed.
        """
        lines = output.splitlines()
        idx = 0

        system: SystemInfo | None = None
        totals: InventoryTotals = {}
        power_supplies: dict[str, PowerSupplyEntry] = {}
        fan_modules: dict[str, FanModuleEntry] = {}
        ports: dict[str, PortSummaryEntry] = {}
        transceivers: dict[str, TransceiverEntry] = {}

        while idx < len(lines):
            stripped = lines[idx].strip()

            if not stripped:
                idx += 1
                continue

            if cls._SYSTEM_INFO_HEADER.match(stripped):
                idx += 1
                system, idx = cls._parse_system_info(lines, idx)
            elif psu_match := cls._POWER_SUPPLY_HEADER.match(stripped):
                totals["power_supply_slots"] = int(psu_match.group("count"))
                idx += 1
                data_lines, idx = cls._parse_table_rows(lines, idx)
                power_supplies = cls._parse_power_supplies(data_lines)
            elif fan_match := cls._FAN_MODULE_HEADER.match(stripped):
                totals["fan_modules"] = int(fan_match.group("count"))
                idx += 1
                data_lines, idx = cls._parse_table_rows(lines, idx)
                fan_modules = cls._parse_fan_modules(data_lines)
            elif port_match := cls._PORT_HEADER.match(stripped):
                totals["ports"] = int(port_match.group("count"))
                idx += 1
                data_lines, idx = cls._parse_table_rows(lines, idx)
                ports = cls._parse_ports(data_lines)
            elif xcvr_match := cls._TRANSCEIVER_HEADER.match(stripped):
                totals["transceiver_slots"] = int(xcvr_match.group("count"))
                idx += 1
                data_lines, idx = cls._parse_table_rows(lines, idx)
                transceivers = cls._parse_transceivers(data_lines)
            else:
                idx += 1

        if system is None:
            msg = "No system information block found in output"
            raise ValueError(msg)

        return ShowInventoryResult(
            system=system,
            totals=totals,
            power_supplies=power_supplies,
            fan_modules=fan_modules,
            ports=ports,
            transceivers=transceivers,
        )
