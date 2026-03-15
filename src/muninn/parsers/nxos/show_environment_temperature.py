"""Parser for 'show environment temperature' command on NX-OS."""

import re
from typing import TypedDict

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register


class TemperatureSensorEntry(TypedDict):
    """Schema for a single temperature sensor entry."""

    major_threshold_celsius: int
    minor_threshold_celsius: int
    current_temp_celsius: int
    status: str


class ShowEnvironmentTemperatureResult(TypedDict):
    """Schema for 'show environment temperature' parsed output."""

    temperatures: dict[str, dict[str, TemperatureSensorEntry]]


_SEPARATOR = re.compile(r"^-{3,}")
_HEADER_LINE = re.compile(r"^\s*(?:Module\s+Sensor|\(Celsius)")

_TEMP_ROW = re.compile(
    r"^(?P<module>\d+)\s+(?P<sensor>.+?)\s{2,}(?P<major>\d+)\s+(?P<minor>\d+)\s+"
    r"(?P<current>\d+)\s+(?P<status>\S+)"
)


@register(OS.CISCO_NXOS, "show environment temperature")
class ShowEnvironmentTemperatureParser(
    BaseParser[ShowEnvironmentTemperatureResult],
):
    """Parser for 'show environment temperature' command.

    Example output:
        Temperature
        ---------------------------------------------------------------
        Module  Sensor             MajorThresh   MinorThres   CurTemp     Status
                                    (Celsius)     (Celsius)   (Celsius)
        ---------------------------------------------------------------
        1       ASIC                101           95           52          ok
    """

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentTemperatureResult:
        """Parse 'show environment temperature' output.

        Args:
            output: Raw CLI output from 'show environment temperature' command.

        Returns:
            Parsed data.

        Raises:
            ValueError: If the output cannot be parsed.
        """
        temps: dict[str, dict[str, TemperatureSensorEntry]] = {}

        for line in output.splitlines():
            line = line.strip()

            if not line or _SEPARATOR.match(line) or _HEADER_LINE.match(line):
                continue

            if match := _TEMP_ROW.match(line):
                module = match.group("module")
                sensor = " ".join(match.group("sensor").split())
                sensor_entry: TemperatureSensorEntry = {
                    "major_threshold_celsius": int(match.group("major")),
                    "minor_threshold_celsius": int(match.group("minor")),
                    "current_temp_celsius": int(match.group("current")),
                    "status": match.group("status"),
                }
                if module not in temps:
                    temps[module] = {}
                temps[module][sensor] = sensor_entry

        if not temps:
            msg = "No temperature entries found in output"
            raise ValueError(msg)

        return {"temperatures": temps}
