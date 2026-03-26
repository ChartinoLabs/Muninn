"""Parser for 'show environment' command on NX-OS."""

import re
from typing import ClassVar, NotRequired, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class FanEntry(TypedDict):
    """Schema for a single fan entry."""

    status: str
    model: NotRequired[str]
    hw_version: NotRequired[str]
    direction: NotRequired[str]


class PowerSupplyEntry(TypedDict):
    """Schema for a single power supply entry."""

    status: str
    model: NotRequired[str]
    actual_output_watts: NotRequired[int]
    actual_input_watts: NotRequired[int]
    total_capacity_watts: NotRequired[int]


class ModuleEntry(TypedDict):
    """Schema for a single module power entry."""

    status: str
    model: NotRequired[str]
    actual_draw_watts: NotRequired[float]
    power_allocated_watts: NotRequired[float]


class PowerSummary(TypedDict):
    """Schema for power usage summary."""

    redundancy_mode_configured: str
    redundancy_mode_operational: str
    total_capacity_watts: NotRequired[float]
    total_grid_a_capacity_watts: NotRequired[float]
    total_grid_b_capacity_watts: NotRequired[float]
    total_power_all_inputs_watts: NotRequired[float]
    total_power_output_watts: NotRequired[float]
    total_power_input_watts: NotRequired[float]
    total_power_allocated_watts: NotRequired[float]
    total_power_available_watts: NotRequired[float]


class ClockEntry(TypedDict):
    """Schema for a single clock module entry."""

    status: str
    model: NotRequired[str]
    hw_version: NotRequired[str]


class TemperatureSensorEntry(TypedDict):
    """Schema for a single temperature sensor entry."""

    major_threshold_celsius: int
    minor_threshold_celsius: int
    current_temp_celsius: int
    status: str


class ShowEnvironmentResult(TypedDict):
    """Schema for 'show environment' parsed output."""

    fans: NotRequired[dict[str, FanEntry]]
    fan_zone_speed: NotRequired[str]
    fan_air_filter: NotRequired[str]
    power_supplies: NotRequired[dict[str, PowerSupplyEntry]]
    voltage: NotRequired[int]
    modules: NotRequired[dict[str, ModuleEntry]]
    power_summary: NotRequired[PowerSummary]
    clocks: NotRequired[dict[str, ClockEntry]]
    temperatures: NotRequired[dict[str, dict[str, TemperatureSensorEntry]]]


# Section header patterns
_SECTION_FAN = re.compile(r"^Fan:\s*$")
_SECTION_POWER_SUPPLY = re.compile(r"^Power Supply:\s*$")
_SECTION_POWER_USAGE = re.compile(r"^Power Usage Summary:\s*$")
_SECTION_CLOCK = re.compile(r"^Clock:\s*$")
_SECTION_TEMPERATURE = re.compile(r"^Temperature:\s*$")
_SECTION_MODULE = re.compile(r"^Module\s+Model\s+Draw\s+Allocated\s+Status")

# Data patterns
_FAN_WITH_DIR = re.compile(
    r"^(?P<name>\S+)\s+(?P<model>\S+)?\s+(?P<hw>\S+)\s+"
    r"(?P<direction>front-to-back|back-to-front)\s+(?P<status>\S+)\s*$"
)
_FAN_NO_DIR = re.compile(
    r"^(?P<name>\S+)\s+(?P<model>\S+)?\s+(?P<hw>\S+)\s+(?P<status>\S+)\s*$"
)
_FAN_ZONE_SPEED = re.compile(r"^Fan Zone Speed:\s*(?P<value>.+)$")
_FAN_AIR_FILTER = re.compile(r"^Fan Air Filter\s*:\s*(?P<value>\S+)")

_VOLTAGE = re.compile(r"^Voltage:\s*(?P<volts>\d+)\s*Volts", re.I)

_PS_WITH_INPUT = re.compile(
    r"^(?P<id>\d+)\s+(?P<model>\S+)\s+"
    r"(?P<output>\d+)\s*W\s+(?P<input>\d+)\s*W\s+(?P<capacity>\d+)\s*W\s+(?P<status>\S+)"
)
_PS_NO_INPUT = re.compile(
    r"^(?P<id>\d+)\s+(?P<model>\S+)\s+"
    r"(?P<output>\d+)\s*W\s+(?P<capacity>\d+)\s*W\s+(?P<status>\S+)"
)

_MODULE_ROW = re.compile(
    r"^(?P<id>\S+)\s+(?P<model>\S+)\s+"
    r"(?P<draw>[\d.]+|N/A)\s*W?\s+(?P<alloc>[\d.]+)\s*W\s+(?P<status>\S+(?:-\S+)?)"
)

_CLOCK_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<model>.+?)\s{2,}(?P<hw>\S+)\s+(?P<status>\S+.*)$"
)

_TEMP_ROW = re.compile(
    r"^(?P<module>\d+)\s+(?P<sensor>.+?)\s{2,}(?P<major>\d+)\s+(?P<minor>\d+)\s+"
    r"(?P<current>\d+)\s+(?P<status>\S+)"
)

_POWER_CONFIG_MODE = re.compile(
    r"Power Supply redundancy mode \(configured\)\s+(?P<value>.+)$"
)
_POWER_OPER_MODE = re.compile(
    r"Power Supply redundancy mode \(operational\)\s+(?P<value>.+)$"
)
_POWER_CAPACITY = re.compile(
    r"Total Power Capacity \(based on configured mode\)\s+(?P<value>[\d.]+)\s*W"
)
_POWER_GRID_A = re.compile(r"Total Grid-A .+?\s+(?P<value>[\d.]+)\s*W")
_POWER_GRID_B = re.compile(r"Total Grid-B .+?\s+(?P<value>[\d.]+)\s*W")
_POWER_ALL_INPUTS = re.compile(
    r"Total Power of all Inputs \(cumulative\)\s+(?P<value>[\d.]+)\s*W"
)
_POWER_OUTPUT = re.compile(
    r"Total Power Output \(actual draw\)\s+(?P<value>[\d.]+)\s*W"
)
_POWER_INPUT = re.compile(r"Total Power Input \(actual draw\)\s+(?P<value>[\d.]+)\s*W")
_POWER_ALLOCATED = re.compile(
    r"Total Power Allocated \(budget\)\s+(?P<value>[\d.]+|N/A)\s*W?"
)
_POWER_AVAILABLE = re.compile(
    r"Total Power Available for additional modules\s+(?P<value>[\d.]+|N/A)\s*W?"
)

_SEPARATOR = re.compile(r"^-{3,}")
_HEADER_LINE = re.compile(
    r"^\s*(?:Fan\s+Model|Power\s+Actual|Supply\s+Model|Module\s+Sensor|"
    r"Clock\s+Model|\(Watts|\(Celsius|-------)"
)


def _normalize(value: str | None) -> str | None:
    """Normalize a value, converting --, N/A, and empty to None."""
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("--", "------------", "N/A"):
        return None
    return value


def _build_fan_entry(match: re.Match[str], direction: str | None = None) -> FanEntry:
    """Build a FanEntry from a regex match."""
    entry: FanEntry = {"status": match.group("status")}
    model = _normalize(match.group("model"))
    if model:
        entry["model"] = model
    hw = _normalize(match.group("hw"))
    if hw:
        entry["hw_version"] = hw
    if direction:
        entry["direction"] = direction
    return entry


def _try_match_fan_metadata(line: str, result: dict) -> bool:
    """Try to match fan zone speed or air filter lines. Returns True if matched."""
    if match := _FAN_ZONE_SPEED.match(line):
        result["fan_zone_speed"] = match.group("value").strip()
        return True
    if match := _FAN_AIR_FILTER.match(line):
        result["fan_air_filter"] = match.group("value").strip()
        return True
    return False


def _try_match_fan_row(
    line: str, has_direction: bool, fans: dict[str, FanEntry]
) -> bool | None:
    """Try to match a fan data row.

    Returns True if directional, False if non-directional, None if no match.
    """
    if match := _FAN_WITH_DIR.match(line):
        fans[match.group("name")] = _build_fan_entry(match, match.group("direction"))
        return True
    if not has_direction and (match := _FAN_NO_DIR.match(line)):
        fans[match.group("name")] = _build_fan_entry(match)
        return False
    return None


def _parse_fan_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Fan section. Returns the new line index."""
    fans: dict[str, FanEntry] = {}
    has_direction = False

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
            idx += 1
            continue

        if _try_match_fan_metadata(line, result):
            idx += 1
            continue

        fan_match = _try_match_fan_row(line, has_direction, fans)
        if fan_match is not None:
            has_direction = has_direction or fan_match
            idx += 1
            continue

        break

    if fans:
        result["fans"] = fans
    return idx


def _build_ps_entry(match: re.Match[str], has_input: bool) -> PowerSupplyEntry:
    """Build a PowerSupplyEntry from a regex match."""
    entry: PowerSupplyEntry = {"status": match.group("status")}
    model = _normalize(match.group("model"))
    if model:
        entry["model"] = model
    entry["actual_output_watts"] = int(match.group("output"))
    if has_input:
        entry["actual_input_watts"] = int(match.group("input"))
    entry["total_capacity_watts"] = int(match.group("capacity"))
    return entry


def _try_match_ps_row(line: str, supplies: dict[str, PowerSupplyEntry]) -> bool:
    """Try to match a power supply data row. Returns True if matched."""
    if match := _PS_WITH_INPUT.match(line):
        supplies[match.group("id")] = _build_ps_entry(match, has_input=True)
        return True
    if match := _PS_NO_INPUT.match(line):
        supplies[match.group("id")] = _build_ps_entry(match, has_input=False)
        return True
    return False


def _parse_power_supply_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Power Supply section. Returns the new line index."""
    supplies: dict[str, PowerSupplyEntry] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
            idx += 1
            continue

        if match := _VOLTAGE.match(line):
            result["voltage"] = int(match.group("volts"))
            idx += 1
            continue

        if _try_match_ps_row(line, supplies):
            idx += 1
            continue

        break

    if supplies:
        result["power_supplies"] = supplies
    return idx


def _parse_module_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Module power section. Returns the new line index."""
    modules: dict[str, ModuleEntry] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
            idx += 1
            continue

        if line.startswith("N/A - "):
            idx += 1
            continue

        if match := _MODULE_ROW.match(line):
            mod_id = match.group("id")
            entry: ModuleEntry = {"status": match.group("status")}
            model = _normalize(match.group("model"))
            if model:
                entry["model"] = model
            draw_str = match.group("draw")
            if draw_str != "N/A":
                entry["actual_draw_watts"] = float(draw_str)
            entry["power_allocated_watts"] = float(match.group("alloc"))
            modules[mod_id] = entry
            idx += 1
            continue

        break

    if modules:
        result["modules"] = modules
    return idx


# Power summary patterns mapped to output keys.
# Patterns returning "str" use the value as-is; "float" converts numerically.
_POWER_SUMMARY_STR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_POWER_CONFIG_MODE, "redundancy_mode_configured"),
    (_POWER_OPER_MODE, "redundancy_mode_operational"),
]

_POWER_SUMMARY_FLOAT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_POWER_CAPACITY, "total_capacity_watts"),
    (_POWER_GRID_A, "total_grid_a_capacity_watts"),
    (_POWER_GRID_B, "total_grid_b_capacity_watts"),
    (_POWER_ALL_INPUTS, "total_power_all_inputs_watts"),
    (_POWER_OUTPUT, "total_power_output_watts"),
    (_POWER_INPUT, "total_power_input_watts"),
    (_POWER_ALLOCATED, "total_power_allocated_watts"),
    (_POWER_AVAILABLE, "total_power_available_watts"),
]


def _try_power_summary_line(line: str, summary: dict[str, object]) -> bool:
    """Attempt to match a power summary line. Returns True if matched."""
    for pattern, key in _POWER_SUMMARY_STR_PATTERNS:
        if match := pattern.match(line):
            summary[key] = match.group("value").strip()
            return True

    for pattern, key in _POWER_SUMMARY_FLOAT_PATTERNS:
        if match := pattern.match(line):
            val = match.group("value")
            if val != "N/A":
                summary[key] = float(val)
            return True

    return False


def _parse_power_usage_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Power Usage Summary section. Returns the new line index."""
    summary: dict[str, object] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line):
            idx += 1
            continue

        if _try_power_summary_line(line, summary):
            idx += 1
            continue

        break

    if summary:
        result["power_summary"] = summary
    return idx


def _parse_clock_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Clock section. Returns the new line index."""
    clocks: dict[str, ClockEntry] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
            idx += 1
            continue

        if match := _CLOCK_ROW.match(line):
            name = match.group("name")
            entry: ClockEntry = {"status": match.group("status").strip()}
            model = _normalize(match.group("model"))
            if model:
                entry["model"] = model
            hw = _normalize(match.group("hw"))
            if hw:
                entry["hw_version"] = hw
            clocks[name] = entry
            idx += 1
            continue

        break

    if clocks:
        result["clocks"] = clocks
    return idx


def _parse_temperature_section(lines: list[str], idx: int, result: dict) -> int:
    """Parse the Temperature section. Returns the new line index."""
    temps: dict[str, dict[str, TemperatureSensorEntry]] = {}

    while idx < len(lines):
        line = lines[idx].strip()

        if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
            idx += 1
            continue

        if match := _TEMP_ROW.match(line):
            module = match.group("module")
            sensor = match.group("sensor").strip()
            sensor_entry: TemperatureSensorEntry = {
                "major_threshold_celsius": int(match.group("major")),
                "minor_threshold_celsius": int(match.group("minor")),
                "current_temp_celsius": int(match.group("current")),
                "status": match.group("status"),
            }
            if module not in temps:
                temps[module] = {}
            temps[module][sensor] = sensor_entry
            idx += 1
            continue

        break

    if temps:
        result["temperatures"] = temps
    return idx


@register(OS.CISCO_NXOS, "show environment")
class ShowEnvironmentParser(BaseParser[ShowEnvironmentResult]):
    """Parser for 'show environment' command on NX-OS.

    Parses temperature sensors, fans, power supplies, modules,
    clocks, and power usage summary information.
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset(
        {
            ParserTag.ENVIRONMENT,
            ParserTag.SYSTEM,
        }
    )

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentResult:
        """Parse 'show environment' output on NX-OS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Parsed environment information.
        """
        result: dict[str, object] = {}
        lines = output.splitlines()
        idx = 0

        while idx < len(lines):
            line = lines[idx].strip()

            if _SECTION_FAN.match(line):
                idx = _parse_fan_section(lines, idx + 1, result)
            elif _SECTION_POWER_SUPPLY.match(line):
                idx = _parse_power_supply_section(lines, idx + 1, result)
            elif _SECTION_MODULE.match(line):
                idx = _parse_module_section(lines, idx + 1, result)
            elif _SECTION_POWER_USAGE.match(line):
                idx = _parse_power_usage_section(lines, idx + 1, result)
            elif _SECTION_CLOCK.match(line):
                idx = _parse_clock_section(lines, idx + 1, result)
            elif _SECTION_TEMPERATURE.match(line):
                idx = _parse_temperature_section(lines, idx + 1, result)
            else:
                idx += 1

        return cast(ShowEnvironmentResult, result)
