"""Parser for 'show environment temperature' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TemperatureSensorEntry(TypedDict):
    """Schema for a single temperature sensor entry.

    `setpoint_nominal_celsius` is the integer target temperature configured
    for the sensor (printed in parentheses by EOS), while `setpoint_celsius`
    is the floating-point setpoint EOS actually applies after compensation.
    """

    description: str
    temperature_celsius: float
    setpoint_nominal_celsius: int
    setpoint_celsius: float
    alert_limit_celsius: float
    critical_limit_celsius: float


class ShowEnvironmentTemperatureResult(TypedDict):
    """Schema for 'show environment temperature' parsed output on Arista EOS.

    `sensors` is keyed by slot label, then by stringified sensor ID, e.g.
    ``sensors["Linecard 3"]["6"]``.
    """

    system_status: str
    sensors: dict[str, dict[str, TemperatureSensorEntry]]


@register(OS.ARISTA_EOS, "show environment temperature")
class ShowEnvironmentTemperatureParser(
    BaseParser[ShowEnvironmentTemperatureResult],
):
    """Parser for 'show environment temperature' command on Arista EOS."""

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    _SYSTEM_STATUS = re.compile(r"^System temperature status is:\s*(?P<status>.+)$")
    _SLOT_HEADER = re.compile(r"^(?P<slot>.+?):\s*$")
    _SENSOR_LINE = re.compile(
        r"^(?P<sensor_id>\d+)\s+"
        r"(?P<description>.+?)\s{2,}"
        r"(?P<temp>[\d.]+)\s+"
        r"\((?P<setpoint_nominal>\d+)\)\s+(?P<setpoint_actual>[\d.]+)\s+"
        r"(?P<alert>[\d.]+)\s+"
        r"(?P<critical>[\d.]+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> ShowEnvironmentTemperatureResult:
        """Parse 'show environment temperature' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            System temperature status and per-slot, per-sensor readings.

        Raises:
            ValueError: If no sensor data is found in the output.
        """
        sensors: dict[str, dict[str, TemperatureSensorEntry]] = {}
        system_status = ""
        current_slot = ""

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if status_match := cls._SYSTEM_STATUS.match(stripped):
                system_status = status_match.group("status").strip()
                continue

            slot_match = cls._SLOT_HEADER.match(stripped)
            if slot_match:
                current_slot = slot_match.group("slot")
                continue

            sensor_match = cls._SENSOR_LINE.match(stripped)
            if sensor_match and current_slot:
                sensor_id = sensor_match.group("sensor_id")
                slot_sensors = sensors.setdefault(current_slot, {})
                slot_sensors[sensor_id] = TemperatureSensorEntry(
                    description=sensor_match.group("description").strip(),
                    temperature_celsius=float(sensor_match.group("temp")),
                    setpoint_nominal_celsius=int(
                        sensor_match.group("setpoint_nominal")
                    ),
                    setpoint_celsius=float(sensor_match.group("setpoint_actual")),
                    alert_limit_celsius=float(sensor_match.group("alert")),
                    critical_limit_celsius=float(sensor_match.group("critical")),
                )

        if not sensors:
            msg = "No temperature sensor data found in output"
            raise ValueError(msg)

        return cast(
            ShowEnvironmentTemperatureResult,
            {"system_status": system_status, "sensors": sensors},
        )
