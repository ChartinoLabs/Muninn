"""Parser for 'show environment temperature' command on Arista EOS."""

import re
from typing import ClassVar, TypedDict, cast

from muninn.os import OS
from muninn.parser import BaseParser
from muninn.registry import register
from muninn.tags import ParserTag


class TemperatureSensorEntry(TypedDict):
    """Schema for a single temperature sensor entry."""

    slot: str
    sensor_id: int
    description: str
    temperature_celsius: float
    setpoint_celsius: float
    alert_limit_celsius: int
    critical_limit_celsius: int


@register(OS.ARISTA_EOS, "show environment temperature")
class ShowEnvironmentTemperatureParser(
    BaseParser[dict[str, TemperatureSensorEntry]],
):
    """Parser for 'show environment temperature' command on Arista EOS.

    Returns a dict-of-dicts keyed by a composite key of
    ``<slot>/<sensor_id>`` (e.g. ``Supervisor 1/1``).
    """

    tags: ClassVar[frozenset[ParserTag]] = frozenset({ParserTag.ENVIRONMENT})

    _SLOT_HEADER = re.compile(r"^(?P<slot>.+?):\s*$")
    _SENSOR_LINE = re.compile(
        r"^(?P<sensor_id>\d+)\s+"
        r"(?P<description>.+?)\s{2,}"
        r"(?P<temp>[\d.]+)\s+"
        r"\((?P<setpoint_nominal>\d+)\)\s+(?P<setpoint_actual>[\d.]+)\s+"
        r"(?P<alert>\d+)\s+"
        r"(?P<critical>\d+)\s*$"
    )

    @classmethod
    def parse(cls, output: str) -> dict[str, TemperatureSensorEntry]:
        """Parse 'show environment temperature' output on Arista EOS.

        Args:
            output: Raw CLI output from command.

        Returns:
            Dict of sensor entries keyed by ``<slot>/<sensor_id>``.

        Raises:
            ValueError: If no sensor data is found in the output.
        """
        result: dict[str, TemperatureSensorEntry] = {}
        current_slot = ""

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            slot_match = cls._SLOT_HEADER.match(stripped)
            if slot_match:
                current_slot = slot_match.group("slot")
                continue

            sensor_match = cls._SENSOR_LINE.match(stripped)
            if sensor_match:
                sensor_id = int(sensor_match.group("sensor_id"))
                key = f"{current_slot}/{sensor_id}"
                result[key] = cast(
                    TemperatureSensorEntry,
                    {
                        "slot": current_slot,
                        "sensor_id": sensor_id,
                        "description": sensor_match.group("description").strip(),
                        "temperature_celsius": float(sensor_match.group("temp")),
                        "setpoint_celsius": float(
                            sensor_match.group("setpoint_actual")
                        ),
                        "alert_limit_celsius": int(sensor_match.group("alert")),
                        "critical_limit_celsius": int(sensor_match.group("critical")),
                    },
                )

        if not result:
            msg = "No temperature sensor data found in output"
            raise ValueError(msg)

        return result
