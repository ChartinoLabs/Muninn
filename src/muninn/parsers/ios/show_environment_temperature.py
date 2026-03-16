"""Parser for 'show environment temperature' command on IOS."""

import re
from typing import ClassVar, NotRequired, TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class TemperatureSensorEntry(TypedDict):
    """Schema for a single temperature sensor reading."""

    temperature_value: int
    temperature_state: str
    yellow_threshold: int
    red_threshold: int


class SwitchTemperatureEntry(TypedDict):
    """Schema for a single switch temperature entry."""

    system_temperature: str
    inlet: NotRequired[TemperatureSensorEntry]
    hotspot: NotRequired[TemperatureSensorEntry]


class ShowEnvironmentTemperatureResult(TypedDict):
    """Schema for 'show environment temperature' parsed output."""

    switches: dict[str, SwitchTemperatureEntry]


_SWITCH_HEADER = re.compile(
    r"^Switch\s+(?P<switch_id>\d+):\s+SYSTEM TEMPERATURE is\s+(?P<status>\S+)"
)
_SENSOR_VALUE = re.compile(
    r"^(?P<sensor>Inlet|Hotspot)\s+Temperature\s+Value:\s+(?P<value>\d+)"
)
_TEMP_STATE = re.compile(r"^Temperature\s+State:\s+(?P<state>\S+)")
_YELLOW_THRESHOLD = re.compile(r"^Yellow\s+Threshold\s*:\s+(?P<value>\d+)")
_RED_THRESHOLD = re.compile(r"^Red\s+Threshold\s*:\s+(?P<value>\d+)")


def _parse_sensor(lines: list[str], idx: int) -> tuple[TemperatureSensorEntry, int]:
    """Parse a sensor block (value, state, yellow threshold, red threshold).

    Args:
        lines: List of stripped lines from output.
        idx: Index of the sensor value line (already matched).

    Returns:
        Tuple of (sensor entry, next line index).

    Raises:
        ValueError: If expected follow-on lines are missing.
    """
    value_match = _SENSOR_VALUE.match(lines[idx])
    if not value_match:
        msg = f"Expected sensor value line at index {idx}"
        raise ValueError(msg)
    temp_value = int(value_match.group("value"))
    idx += 1

    state = _extract_field(_TEMP_STATE, lines, idx, "Temperature State")
    idx += 1

    yellow = int(_extract_field(_YELLOW_THRESHOLD, lines, idx, "Yellow Threshold"))
    idx += 1

    red = int(_extract_field(_RED_THRESHOLD, lines, idx, "Red Threshold"))
    idx += 1

    entry: TemperatureSensorEntry = {
        "temperature_value": temp_value,
        "temperature_state": state,
        "yellow_threshold": yellow,
        "red_threshold": red,
    }
    return entry, idx


def _extract_field(
    pattern: re.Pattern[str], lines: list[str], idx: int, field_name: str
) -> str:
    """Extract a single field value from the expected line position.

    Args:
        pattern: Compiled regex with a named group to extract.
        lines: List of stripped lines.
        idx: Current line index.
        field_name: Human-readable field name for error messages.

    Returns:
        The matched group value.

    Raises:
        ValueError: If the line doesn't match the expected pattern.
    """
    if idx >= len(lines):
        msg = f"Unexpected end of output while looking for {field_name}"
        raise ValueError(msg)
    match = pattern.match(lines[idx])
    if not match:
        msg = f"Expected {field_name} at line: {lines[idx]!r}"
        raise ValueError(msg)
    return match.group(1)


@register(OS.CISCO_IOS, "show environment temperature")
class ShowEnvironmentTemperatureParser(
    BaseParser[ShowEnvironmentTemperatureResult],
):
    """Parser for 'show environment temperature' command.

    Example output:
        Switch 1: SYSTEM TEMPERATURE is OK
        Inlet Temperature Value: 29 Degree Celsius
        Temperature State: GREEN
        Yellow Threshold : 46 Degree Celsius
        Red Threshold    : 56 Degree Celsius
    """

    tags: ClassVar[frozenset[str]] = frozenset({"environment", "system"})

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentTemperatureResult:
        """Parse 'show environment temperature' output.

        Args:
            output: Raw CLI output from 'show environment temperature' command.

        Returns:
            Parsed data keyed by switch number.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        raw_lines = output.splitlines()
        lines = [line.strip() for line in raw_lines]

        switches: dict[str, SwitchTemperatureEntry] = {}
        idx = 0

        while idx < len(lines):
            line = lines[idx]
            if not line:
                idx += 1
                continue

            header_match = _SWITCH_HEADER.match(line)
            if header_match:
                switch_id = header_match.group("switch_id")
                status = header_match.group("status")
                entry: SwitchTemperatureEntry = {"system_temperature": status}
                switches[switch_id] = entry
                idx += 1
                continue

            sensor_match = _SENSOR_VALUE.match(line)
            if sensor_match and switches:
                sensor_type = sensor_match.group("sensor").lower()
                current_switch = list(switches.values())[-1]
                sensor_entry, idx = _parse_sensor(lines, idx)
                current_switch[sensor_type] = sensor_entry  # type: ignore[literal-required]
                continue

            idx += 1

        if not switches:
            msg = "No switch temperature data found in output"
            raise ValueError(msg)

        return {"switches": switches}
